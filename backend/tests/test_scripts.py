"""Command-line entry points: OpenAPI export, worker preflight and the Celery smoke task."""

import json
from pathlib import Path

import pytest

from app.scanners.profile import ProfileError, load_evidence_profile, load_profile
from app.workers.celery_app import ping
from scripts import check_worker, export_openapi

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "profiles/command-injection-v0.1/profile.json"
EVIDENCE_MANIFEST = "profiles/path-traversal-v0.2/profile.json"


def test_openapi_export_is_deterministic_json_with_every_route():
    first = export_openapi.export()
    assert first == export_openapi.export()
    assert first.endswith("\n")
    spec = json.loads(first)
    assert set(spec["paths"]) == {
        "/api/v1/health/live",
        "/api/v1/health/ready",
        "/api/v1/projects",
        "/api/v1/projects/{project_id}",
        "/api/v1/projects/{project_id}/scans",
        "/api/v1/scans/{scan_id}",
        "/api/v1/scans/{scan_id}/report",
        "/api/v1/scans/{scan_id}/report.sarif",
        "/api/v1/scans/{scan_id}/units",
        "/api/v1/scans/{scan_id}/units/{unit_id}",
    }
    assert "ErrorResponse" in spec["components"]["schemas"]


def test_openapi_export_writes_an_lf_utf8_file(tmp_path):
    target = tmp_path / "openapi.json"
    export_openapi.main([str(target)])
    content = target.read_bytes()
    assert b"\r\n" not in content
    assert content.decode("utf-8") == export_openapi.export()


def test_openapi_export_defaults_to_stdout(capsys):
    export_openapi.main([])
    assert capsys.readouterr().out == export_openapi.export()


def test_ping_task_runs_without_a_broker():
    assert ping.apply().get() == "pong"


def _fake_tool_version(calls):
    def fake(binary, expected, output, tool, steps, /, *, working_directory, invoke_fn):
        calls.append((binary, expected, tool))

    return fake


def test_check_worker_verifies_every_profile_and_scanner_versions():
    calls: list[tuple[str, str, str]] = []
    message = check_worker.check(
        ROOT, [MANIFEST, EVIDENCE_MANIFEST], tool_version_fn=_fake_tool_version(calls)
    )
    pins = check_worker.read_pins(ROOT / "tools/pins.env")
    assert calls == [
        ("semgrep", pins["SEMGREP_VERSION"], "semgrep"),
        ("codeql", pins["CODEQL_VERSION"], "codeql"),
    ]
    assert message.startswith("Worker ready: profiles command-injection-v0.1 sha256=")
    assert ", path-traversal-v0.2 sha256=" in message


def test_check_worker_checks_screening_tools_only_when_a_profile_uses_them():
    calls: list[tuple[str, str, str]] = []
    manifest = "profiles/command-injection-v0.2/profile.json"
    message = check_worker.check(ROOT, manifest, tool_version_fn=_fake_tool_version(calls))
    pins = check_worker.read_pins(ROOT / "tools/pins.env")
    assert [(tool, version) for _, version, tool in calls] == [
        ("semgrep", pins["SEMGREP_VERSION"]),
        ("codeql", pins["CODEQL_VERSION"]),
        ("bandit", pins["BANDIT_VERSION"]),
        ("eslint", pins["ESLINT_VERSION"]),
    ]
    assert message.endswith(f"bandit {pins['BANDIT_VERSION']}, eslint {pins['ESLINT_VERSION']}")
    profile = load_profile(ROOT, manifest)
    with pytest.raises(ProfileError, match="python profile bandit differs"):
        check_worker.check_pins(profile, {**pins, "BANDIT_VERSION": "0.0.0"})


@pytest.mark.parametrize(
    "profile",
    [lambda: load_profile(ROOT, MANIFEST), lambda: load_evidence_profile(ROOT, EVIDENCE_MANIFEST)],
    ids=["priority", "evidence"],
)
def test_check_worker_rejects_profile_that_differs_from_pins(profile):
    pins = check_worker.read_pins(ROOT / "tools/pins.env")
    with pytest.raises(ProfileError, match="differs from tools/pins.env"):
        check_worker.check_pins(profile(), {**pins, "CODEQL_PYTHON_QUERY_PACK": "0.0.0"})
