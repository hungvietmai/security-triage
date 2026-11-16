"""Detection profiles: pinned queries of the standard CodeQL pack, detected and kept."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.scanners.profile import (
    CompositeProfile,
    DetectionProfile,
    ProfileError,
    load_any_profile,
    load_detection_profile,
    load_member_profile,
)
from app.workflows.scans.families import COMPOSITION_VERSION, members_of
from app.workflows.scans.task import SOFT_TIME_LIMIT, worst_case_seconds
from scripts import check_worker
from tests.scanners.test_profile import ROOT, _sha

SQL = "profiles/sql-injection-v0.1/profile.json"
V01 = "profiles/multi-cwe-v0.1/profile.json"
V02 = "profiles/multi-cwe-v0.2/profile.json"
V03 = "profiles/multi-cwe-v0.3/profile.json"
SQL2 = "profiles/sql-injection-v0.2/profile.json"
QUERY = "Security/CWE-089/SqlInjection.ql"


def _config(language: str = "python", **changes: Any) -> dict[str, Any]:
    return {
        "scanners": ["codeql"],
        "semgrep_version": "1.0.0",
        "codeql_version": "2.0.0",
        "jobs": 1,
        "timeout_seconds": 60,
        "semgrep_rules": [],
        "codeql_queries": [QUERY],
        "codeql_query_sha256": {QUERY: "a" * 64},
        "codeql_bundle": {f"{language}_query_pack": "1.0.0"},
        **changes,
    }


def _write(root: Path, *, config: dict[str, Any] | None = None, **changes: Any) -> str:
    """A synthetic detection profile under `root`; returns its manifest path."""
    (root / "python.json").write_text(json.dumps(config or _config()), encoding="utf-8")
    (root / "spec.md").write_bytes(b"# detect and keep\n")
    manifest: dict[str, Any] = {
        "kind": "detection",
        "profile_id": "detection-test",
        "languages": {"python": {"config": "python.json"}},
        "rules": {"python": {"py/example": ["CWE-89"]}},
        "priority": "U",
        "policy": {"id": "detect-and-keep", "version": "0.1", "source": "spec.md"},
        "specification": "spec.md",
        "files": {name: _sha((root / name).read_bytes()) for name in ("python.json", "spec.md")},
        **changes,
    }
    (root / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    return "profile.json"


def test_a_detection_profile_loads_its_pinned_rules_and_tier(tmp_path):
    profile = load_member_profile(tmp_path, _write(tmp_path))
    assert isinstance(profile, DetectionProfile)
    assert (profile.profile_id, profile.priority) == ("detection-test", "U")
    assert profile.rules == {"python": {"py/example": ["CWE-89"]}}
    assert (profile.policy_id, profile.policy_version) == ("detect-and-keep", "0.1")
    assert profile.policy_sha256 == profile.specification_sha256 == _sha(b"# detect and keep\n")
    assert profile.configs["python"]["codeql_queries"] == [QUERY]
    assert load_any_profile(tmp_path, "profile.json") == profile


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"kind": "safety-evidence"}, "Malformed scan profile"),
        ({"rules": {}}, "names no rules for python"),
        ({"rules": {"python": {}}}, "names no rules for python"),
        ({"rules": {"python": {"py/example": []}}}, "names no mapped CWE"),
        ({"rules": {"python": {"py/example": ["89"]}}}, "names no mapped CWE"),
        (
            {"rules": {"python": {"py/example": ["CWE-89"]}, "ruby": {"rb/x": ["CWE-89"]}}},
            "name different languages",
        ),
        ({"priority": "P9"}, "Unknown priority tier"),
        ({"policy": {"id": "x", "version": "1", "source": "missing.md"}}, "does not pin"),
    ],
)
def test_malformed_detection_manifests_are_refused(tmp_path, change, message):
    with pytest.raises(ProfileError, match=message):
        load_member_profile(tmp_path, _write(tmp_path, **change))


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (_config(scanners=["semgrep", "codeql"]), "runs CodeQL only"),
        (_config(semgrep_rules=[{"path": "rule.yaml"}]), "runs CodeQL only"),
        (_config(codeql_queries=[]), "queries and their hashes differ"),
        (_config(codeql_query_sha256={"Other.ql": "b" * 64}), "queries and their hashes differ"),
    ],
)
def test_a_detection_config_runs_pinned_codeql_queries_only(tmp_path, config, message):
    with pytest.raises(ProfileError, match=message):
        load_member_profile(tmp_path, _write(tmp_path, config=config))


def test_a_changed_config_no_longer_matches_its_pin(tmp_path):
    manifest = _write(tmp_path)
    (tmp_path / "python.json").write_text(json.dumps(_config(timeout_seconds=1)), encoding="utf-8")
    with pytest.raises(ProfileError, match="hash mismatch|does not match"):
        load_detection_profile(tmp_path, manifest)


def test_the_repository_sql_profile_pins_the_standard_queries_and_their_cwes():
    profile = load_member_profile(ROOT, SQL)
    assert isinstance(profile, DetectionProfile)
    assert (profile.profile_id, profile.priority) == ("sql-injection-v0.1", "U")
    assert profile.rules == {
        "python": {"py/sql-injection": ["CWE-89"]},
        # One rule mapped to several CWEs: the JavaScript query also reports NoSQL and LDAP.
        "javascript": {"js/sql-injection": ["CWE-89", "CWE-90", "CWE-943"]},
    }
    for language, pack in (("python", "1.8.11"), ("javascript", "2.4.6")):
        config = profile.configs[language]
        assert config["scanners"] == ["codeql"] and config["semgrep_rules"] == []
        assert config["codeql_queries"] == [QUERY]
        assert len(config["codeql_query_sha256"][QUERY]) == 64
        assert config["codeql_bundle"][f"{language}_query_pack"] == pack
    command = load_member_profile(ROOT, "profiles/command-injection-v0.3/profile.json")
    # The shared database is created by the command member, with the same CodeQL.
    for language in ("python", "javascript"):
        ours, theirs = profile.configs[language], command.configs[language]
        assert ours["codeql_version"] == theirs["codeql_version"]
        assert ours["codeql_bundle"] == theirs["codeql_bundle"]


def test_multi_cwe_v0_2_adds_the_sql_member_to_the_members_of_v0_1():
    old, new = load_any_profile(ROOT, V01), load_any_profile(ROOT, V02)
    assert isinstance(old, CompositeProfile) and isinstance(new, CompositeProfile)
    assert (new.profile_id, new.composition) == ("multi-cwe-v0.2", COMPOSITION_VERSION)
    assert [(m.family, m.profile.profile_id) for m in members_of(new)] == [
        ("command-injection", "command-injection-v0.3"),
        ("path-traversal", "path-traversal-v0.2"),
        ("sql-injection", "sql-injection-v0.1"),
    ]
    # The first two members are byte for byte the members of multi-cwe-v0.1.
    for ours, theirs in zip(new.members[:2], old.members, strict=True):
        assert ours[0] == theirs[0]
        assert ours[1].manifest_sha256 == theirs[1].manifest_sha256
    assert new.manifest_sha256 != old.manifest_sha256
    # Two more analysis passes fit the task's time budget.
    assert worst_case_seconds(new) == worst_case_seconds(old) + 2 * 600 < SOFT_TIME_LIMIT


def test_the_worker_check_accepts_the_three_family_profile():
    calls: list[str] = []

    def fake(binary, expected, output, tool, steps, /, *, working_directory, invoke_fn):
        calls.append(tool)

    message = check_worker.check(ROOT, [V01, V02], tool_version_fn=fake)
    assert "multi-cwe-v0.1" in message and "multi-cwe-v0.2" in message
    assert sorted(calls) == ["bandit", "codeql", "eslint", "semgrep"]


def _write_v2(root: Path, *, config_changes: dict[str, Any] | None = None, **changes: Any) -> str:
    """A synthetic schema-2 detection profile: Semgrep, Bandit and CodeQL."""
    (root / "rule.yaml").write_text("rules: [{id: sqli}]\n", encoding="utf-8")
    (root / "bandit.ini").write_text("[bandit]\n", encoding="utf-8")
    config = _config(
        scanners=["semgrep", "bandit", "codeql"],
        semgrep_rules=[
            {
                "path": "rule.yaml",
                "sha256": _sha((root / "rule.yaml").read_bytes()),
                "rule_id": "sqli",
                "canonical_rule_id": "python.example.sqli",
            }
        ],
        bandit={
            "version": "1.9.4",
            "config": {"path": "bandit.ini", "sha256": _sha((root / "bandit.ini").read_bytes())},
            "rules": ["B608"],
        },
    )
    config.update(config_changes or {})
    (root / "python.json").write_text(json.dumps(config), encoding="utf-8")
    (root / "spec.md").write_bytes(b"# detect and keep\n")
    manifest: dict[str, Any] = {
        "schema": 2,
        "kind": "detection",
        "profile_id": "detection-v2-test",
        "languages": {"python": {"config": "python.json"}},
        "rules": {
            "python": {
                "py/example": ["CWE-89"],
                "python.example.sqli": ["CWE-89"],
                "B608": ["CWE-89"],
            }
        },
        "units": "sql-call-site-v1",
        "priority": "U",
        "policy": {"id": "detect-and-keep", "version": "0.2", "source": "spec.md"},
        "specification": "spec.md",
        "files": {
            name: _sha((root / name).read_bytes())
            for name in ("python.json", "spec.md", "rule.yaml", "bandit.ini")
        },
        **changes,
    }
    (root / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    return "profile.json"


def test_a_schema_2_detection_profile_runs_pinned_semgrep_and_bandit_too(tmp_path):
    profile = load_member_profile(tmp_path, _write_v2(tmp_path))
    assert isinstance(profile, DetectionProfile)
    assert profile.unit_merge == "sql-call-site-v1"
    assert profile.configs["python"]["scanners"] == ["semgrep", "bandit", "codeql"]
    # A schema-1 profile keeps one unit per reported location.
    schema_1 = load_member_profile(ROOT, SQL)
    assert isinstance(schema_1, DetectionProfile) and schema_1.unit_merge is None


@pytest.mark.parametrize(
    ("config_changes", "changes", "message"),
    [
        ({}, {"units": "nearest-line"}, "Unknown way of merging"),
        ({}, {"schema": 3}, "Unknown detection profile schema"),
        ({"scanners": ["semgrep", "bandit"]}, {}, "runs CodeQL, optionally"),
        ({"scanners": ["eslint", "codeql"]}, {}, "runs CodeQL, optionally"),
        ({"scanners": ["codeql", "codeql"]}, {}, "lists a tool twice"),
        ({"scanners": ["bandit", "codeql"]}, {}, "both list Semgrep and pin its rules"),
        ({"scanners": ["semgrep", "codeql"]}, {}, "both list and configure bandit"),
        (
            {
                "semgrep_rules": [
                    {
                        "path": "rule.yaml",
                        "sha256": "0" * 64,
                        "rule_id": "sqli",
                        "canonical_rule_id": "x",
                    }
                ]
            },
            {},
            "pin rule.yaml differently",
        ),
        (
            {"semgrep_rules": [{"path": "rule.yaml", "sha256": None, "rule_id": "sqli"}]},
            {},
            "pin rule.yaml differently|names no canonical_rule_id",
        ),
        ({}, {"rules": {"python": {"py/example": ["CWE-89"]}}}, "No mapped CWE for rules"),
    ],
)
def test_malformed_schema_2_detection_profiles_are_refused(
    tmp_path, config_changes, changes, message
):
    manifest = _write_v2(tmp_path, config_changes=config_changes)
    if changes:
        data = json.loads((tmp_path / manifest).read_text(encoding="utf-8"))
        data.update(changes)
        (tmp_path / manifest).write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ProfileError, match=message):
        load_member_profile(tmp_path, manifest)


def test_the_repository_multi_tool_profile_and_its_composite():
    profile = load_member_profile(ROOT, SQL2)
    assert isinstance(profile, DetectionProfile) and profile.unit_merge == "sql-call-site-v1"
    v02, v03 = load_any_profile(ROOT, V02), load_any_profile(ROOT, V03)
    assert isinstance(v02, CompositeProfile) and isinstance(v03, CompositeProfile)
    assert [(m.family, m.profile.profile_id) for m in members_of(v03)] == [
        ("command-injection", "command-injection-v0.3"),
        ("path-traversal", "path-traversal-v0.2"),
        ("sql-injection", "sql-injection-v0.2"),
    ]
    # The first two members are byte for byte those of multi-cwe-v0.2; the CodeQL-only
    # member stays the profile of multi-cwe-v0.2.
    for ours, theirs in zip(v03.members[:2], v02.members[:2], strict=True):
        assert ours[1].manifest_sha256 == theirs[1].manifest_sha256
    assert v02.members[2][1].profile_id == "sql-injection-v0.1"
    # Three more passes (Semgrep and Bandit for Python, Semgrep for JS/TS) fit the budget.
    assert worst_case_seconds(v03) == worst_case_seconds(v02) + 3 * 600 < SOFT_TIME_LIMIT


def test_the_worker_check_accepts_the_multi_tool_profile():
    calls: list[str] = []

    def fake(binary, expected, output, tool, steps, /, *, working_directory, invoke_fn):
        calls.append(tool)

    message = check_worker.check(ROOT, [V03], tool_version_fn=fake)
    assert "multi-cwe-v0.3" in message
    assert sorted(calls) == ["bandit", "codeql", "eslint", "semgrep"]
