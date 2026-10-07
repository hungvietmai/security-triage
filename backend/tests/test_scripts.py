"""Command-line entry points: OpenAPI export, worker preflight and the Celery smoke task."""

import json
from pathlib import Path

import pytest

from app.scanners.profile import ProfileError, load_profile
from app.workers.celery_app import ping
from scripts import check_worker, export_openapi

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "profiles/command-injection-v0.1/profile.json"


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


def test_check_worker_verifies_profile_pins_and_scanner_versions():
    calls: list[tuple[str, str, str]] = []
    message = check_worker.check(ROOT, MANIFEST, tool_version_fn=_fake_tool_version(calls))
    pins = check_worker.read_pins(ROOT / "tools/pins.env")
    assert calls == [
        ("semgrep", pins["SEMGREP_VERSION"], "semgrep"),
        ("codeql", pins["CODEQL_VERSION"], "codeql"),
    ]
    assert message.startswith("Worker ready: profile command-injection-v0.1 sha256=")


def test_check_worker_rejects_profile_that_differs_from_pins():
    profile = load_profile(ROOT, MANIFEST)
    pins = check_worker.read_pins(ROOT / "tools/pins.env")
    with pytest.raises(ProfileError, match="differs from tools/pins.env"):
        check_worker.check_pins(profile, {**pins, "CODEQL_PYTHON_QUERY_PACK": "0.0.0"})
