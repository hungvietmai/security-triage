"""The ssrf family (CWE-918) in a five-family scan (multi-cwe-v0.6), Python and JavaScript.

The sources are the synthetic Python of test_sql_multitool and the synthetic JavaScript of the
legacy golden tests. Every tool is scripted at its boundary: the command member's tools, the
CodeQL passes on each language's shared database (`analyze`) and the SQL member's own Semgrep and
Bandit passes (`member_pass`). Everything between the tools' output and the API is the real code:
classification by pass, the detection member's units, the composition, the worker, persistence,
the report and the SARIF export.

What must hold: the four families of a multi-cwe-v0.5 scan come out exactly as in a multi-cwe-v0.5
scan of the same input; no SSRF alert is lost, merged into another family's unit or filtered; a
broken SSRF pass in one language leaves every other family, and the other language's SSRF pass,
alone and keeps what it reported.
"""

import dataclasses
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.scanners.profile import CompositeProfile, DetectionProfile, load_member_profile
from app.workers.celery_app import celery_app
from app.workflows.scans import task as scan_task
from app.workflows.scans.detection import (
    DETECTION_UNIT_VERSION,
    KEPT_DECISION,
    NO_FILTER_CONDITION,
)
from app.workflows.scans.families import (
    FAMILIES,
    FAMILY_OF_PROFILE,
    NOT_RANKED,
    NOT_RANKED_DECISION,
    CompositeResult,
    members_of,
    scan_language_families,
)
from tests.workflows.scans.fakes import FakeStorage
from tests.workflows.scans.test_composite_scan import _detail, _never_invoked, _units
from tests.workflows.scans.test_composite_scan import _scan as _seed
from tests.workflows.scans.test_families import (
    COMMAND_ARGUMENTS,
    PATH_REGIONS,
    SNAPSHOT,
    SOURCE,
    STEP,
    _finding,
    _region,
    _workspace,
)
from tests.workflows.scans.test_legacy_golden import (
    JS_SOURCE,
    JS_TAINTED_ARGUMENT,
    _js_span,
    js_locator,
    js_pipeline,
)
from tests.workflows.scans.test_sql_family import _decided, standard_pack  # noqa: F401
from tests.workflows.scans.test_sql_linked_merge import LITERAL5
from tests.workflows.scans.test_sql_multitool import DB_SOURCE, LINE4, LINE7, MultiTools
from tests.workflows.scans.test_xss_family import OWN, XssTools, _js, _load

SSRF = "ssrf-v0.1"
PROFILE = "multi-cwe-v0.6"
BASELINE = "multi-cwe-v0.5"
SSRF_PASS = "codeql-ssrf"
SSRF_FAMILY = "ssrf"
PY_FILES = {"app.py": SOURCE, "db.py": DB_SOURCE}
JS_FILES = {"index.js": JS_SOURCE}
QUERIES = {
    "python": [
        "Security/CWE-918/FullServerSideRequestForgery.ql",
        "Security/CWE-918/PartialServerSideRequestForgery.ql",
    ],
    "javascript": ["Security/CWE-918/RequestForgery.ql"],
}
PACKS = {"python": "python-queries/1.8.11", "javascript": "javascript-queries/2.4.6"}
OLD = {
    "python": ["command-injection", "path-traversal", "sql-injection"],
    "javascript": ["command-injection", "sql-injection", "cross-site-scripting"],
}
# (rule, region). Python: one alert on exactly the command argument CodeQL's command query
# reports, one on a path alert's region, one at a place of its own. JavaScript: one on the
# command argument of the tainted call, one at a place of its own.
ALERTS: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "python": [
        ("py/full-ssrf", COMMAND_ARGUMENTS[0]),
        ("py/full-ssrf", PATH_REGIONS["a"]),
        ("py/partial-ssrf", _region(2, "request")),
    ],
    "javascript": [
        ("js/request-forgery", _js_span(JS_TAINTED_ARGUMENT)),
        ("js/request-forgery", OWN),
    ],
}
SSRF_CWES = ["cwe-918"]


@dataclasses.dataclass
class SsrfTools:
    """The scripted tools of both languages plus the SSRF pass on each shared database.

    A mode is "completed", "failed" (the analysis raised before writing SARIF),
    "failed-with-results" (it wrote its SARIF and then exited with an error) or "partial" (the
    SARIF says the run did not finish).
    """

    python_ssrf: str = "completed"
    javascript_ssrf: str = "completed"
    ssrf_rule: str = ""
    python: MultiTools = dataclasses.field(
        default_factory=lambda: MultiTools(bandit_regions=(LINE4, LITERAL5, LINE7))
    )
    javascript: XssTools = dataclasses.field(default_factory=XssTools)
    calls: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    def pipeline(self, **kwargs: Any) -> Any:
        if kwargs["language"] == "javascript":
            return js_pipeline(**kwargs)
        return self.python.pipeline(**kwargs)

    def member_pass(self, tool: str, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        tools = self.javascript if kwargs["config"]["language"] == "javascript" else self.python
        return tools.member_pass(tool, **kwargs)

    def analyze(self, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        pack = kwargs["query_pack"].as_posix()
        language = "javascript" if "javascript-queries" in pack else "python"
        name = kwargs["name"]
        self.calls.append((language, name))
        if name != SSRF_PASS:
            return (self.javascript if language == "javascript" else self.python).analyze(**kwargs)
        assert pack.endswith(f"qlpacks/codeql/{PACKS[language]}")
        assert list(kwargs["queries"]) == QUERIES[language]
        member = load_member_profile(get_settings().triage_root, f"profiles/{SSRF}/profile.json")
        assert kwargs["expected_query_sha256"] == member.configs[language]["codeql_query_sha256"]
        assert kwargs["jobs"] == 1 and kwargs["timeout_seconds"] == 600
        mode = self.python_ssrf if language == "python" else self.javascript_ssrf
        if mode == "failed":
            raise RuntimeError("Evidence queries produced no SARIF output")
        make = _js if language == "javascript" else _finding
        alerts = [
            make(f"{name}:0:{index}", name, self.ssrf_rule or rule, region, list(SSRF_CWES))
            for index, (rule, region) in enumerate(ALERTS[language])
        ]
        (kwargs["output"] / f"{name}.sarif").write_text('{"runs": []}\n', encoding="utf-8")
        status = {"failed-with-results": "failed", "partial": "partial"}.get(mode, "completed")
        record = {**STEP, "status": status, "seconds": 3.0, "raw_findings": len(alerts)}
        return record, alerts, status == "completed"


def _compose(
    tmp_path: Path, tools: SsrfTools, language: str, profile: str = PROFILE
) -> CompositeResult:
    files = JS_FILES if language == "javascript" else PY_FILES
    source, output = _workspace(tmp_path, language, files)
    return scan_language_families(
        language,
        members=members_of(_load(profile)),
        settings=get_settings(),
        source=source,
        files=sorted(files),
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=tools.pipeline,
        invoke_fn=js_locator(1) if language == "javascript" else _never_invoked,  # type: ignore[arg-type]
        analyze_fn=tools.analyze,
        pass_fn=tools.member_pass,
    )


def _family(result: CompositeResult, name: str) -> Any:
    return next(family for family in result.families if family.family == name)


def _scan(engine: Engine, tools: SsrfTools, profile: str = PROFILE) -> tuple[str, str]:
    """A scan of Python and JavaScript together, through the worker."""
    storage = FakeStorage()
    scan_id = _seed(engine, storage, {**PY_FILES, **JS_FILES}, profile)
    status = scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=tools.pipeline,
        # Only the JavaScript sink locator runs a process; Python's runs in process.
        invoke_fn=js_locator(1),  # type: ignore[arg-type]
        analyze_fn=tools.analyze,
        pass_fn=tools.member_pass,
    )
    return scan_id, status


def _in_units_once(result: CompositeResult) -> bool:
    in_units = Counter(
        raw_id
        for units in (
            *(family.units for family in result.families),
            *(part.units for part in result.held),
        )
        for unit in units
        for raw_id in unit["raw_finding_ids"]
    )
    return sorted(in_units) == sorted(f["raw_id"] for f in result.findings) and set(
        in_units.values()
    ) <= {1}


# --- Profiles ----------------------------------------------------------------------------------


def test_the_ssrf_member_pins_the_server_side_request_forgery_queries_of_both_packs():
    member = load_member_profile(get_settings().triage_root, f"profiles/{SSRF}/profile.json")
    assert isinstance(member, DetectionProfile) and member.unit_merge is None
    assert sorted(member.configs) == ["javascript", "python"]
    for language, config in member.configs.items():
        assert config["scanners"] == ["codeql"] and config["semgrep_rules"] == []
        assert config["codeql_queries"] == QUERIES[language]
        assert list(config["codeql_query_sha256"]) == QUERIES[language]
        assert (config["jobs"], config["timeout_seconds"]) == (1, 600)
    assert member.rules == {
        "python": {"py/full-ssrf": ["CWE-918"], "py/partial-ssrf": ["CWE-918"]},
        "javascript": {"js/request-forgery": ["CWE-918"]},
    }
    # The client-side query shares the CWE tag but checks requests the browser sends.
    assert "Security/CWE-918/ClientSideRequestForgery.ql" not in str(member.configs)
    assert (member.priority, member.policy_id) == ("U", "ssrf-detect-and-keep")
    assert FAMILY_OF_PROFILE[SSRF] == SSRF_FAMILY and FAMILIES[SSRF_FAMILY].cwe == "CWE-918"
    # The pass name is stored in tool_runs.tool, a column of 32 characters.
    assert len(SSRF_PASS) <= 32


def test_the_five_family_profile_adds_one_member_to_the_four_of_v0_5():
    new, old = _load(PROFILE), _load(BASELINE)
    assert isinstance(new, CompositeProfile)
    assert [family for family, _ in new.members] == [
        "command-injection",
        "path-traversal",
        "sql-injection",
        "cross-site-scripting",
        SSRF_FAMILY,
    ]
    # The first four members are the very manifests v0.5 pins.
    assert [(f, m.profile_id, m.manifest_sha256) for f, m in new.members[:4]] == [
        (f, m.profile_id, m.manifest_sha256) for f, m in old.members
    ]


def test_the_time_limits_cover_the_five_family_profile_within_the_broker_timeout():
    new, old = _load(PROFILE), _load(BASELINE)
    # Two more passes of 600 s: one per language.
    assert scan_task.worst_case_seconds(new) == scan_task.worst_case_seconds(old) + 2 * 600
    assert scan_task.worst_case_seconds(new) < scan_task.SOFT_TIME_LIMIT < scan_task.TIME_LIMIT
    visibility = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert scan_task.TIME_LIMIT < visibility


# --- One run of the composition per language ---------------------------------------------------


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_the_other_four_families_are_those_of_multi_cwe_v0_5(tmp_path, language):
    tools = SsrfTools()
    new = _compose(tmp_path / "new", tools, language)
    old = _compose(tmp_path / "old", SsrfTools(), language, profile=BASELINE)
    assert [f.family for f in new.families] == [*OLD[language], SSRF_FAMILY]
    assert [f.family for f in old.families] == OLD[language]
    for name in OLD[language]:
        ours, theirs = _family(new, name), _family(old, name)
        assert (ours.status, ours.units, ours.assessments, ours.raw_finding_ids) == (
            theirs.status,
            theirs.units,
            theirs.assessments,
            theirs.raw_finding_ids,
        )
    assert new.status == old.status == "completed"
    assert new.steps[SSRF_PASS]["serves"] == [SSRF_FAMILY]
    assert new.steps[SSRF_PASS]["kind"] == "detection"
    # The SSRF queries run once, in a pass of their own after every other member's.
    assert [name for _, name in tools.calls][-1] == SSRF_PASS
    assert [name for _, name in tools.calls].count(SSRF_PASS) == 1


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_every_ssrf_alert_is_kept_in_its_own_family_and_nothing_is_filtered(tmp_path, language):
    result = _compose(tmp_path, SsrfTools(), language)
    ssrf = _family(result, SSRF_FAMILY)
    assert ssrf.status == "completed" and ssrf.result is not None
    assert ssrf.result.unit_version == DETECTION_UNIT_VERSION
    routed = [r for r in result.classification if r["analysis_family"] == SSRF_FAMILY]
    count = len(ALERTS[language])
    assert sorted(r["raw_id"] for r in routed) == [f"{SSRF_PASS}:0:{i}" for i in range(count)]
    assert {r["tool_pass"] for r in routed} == {SSRF_PASS}
    assert {tuple(r["mapped_cwes"]) for r in routed} == {("CWE-918",)}
    assert {tuple(r["reported_cwes"]) for r in routed} == {tuple(SSRF_CWES)}
    assert len(ssrf.units) == count
    assert {
        (
            a["priority"],
            a["decision_id"],
            a["disposition"],
            tuple(a["adjudication"]["kept_because"]),
        )
        for a in ssrf.assessments
    } == {("U", KEPT_DECISION, "review", (NO_FILTER_CONDITION,))}
    assert _in_units_once(result)


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_ssrf_alerts_at_another_familys_place_stay_separate_units(tmp_path, language):
    result = _compose(tmp_path, SsrfTools(), language)

    def places(family: str) -> set[tuple[Any, ...]]:
        return {
            (u["path"], tuple(sorted(u["reported_region"].items())))
            for u in _family(result, family).units
            if u["reported_region"]
        }

    ssrf_raw = {r for u in _family(result, SSRF_FAMILY).units for r in u["raw_finding_ids"]}
    ssrf_ids = {u["unit_id"] for u in _family(result, SSRF_FAMILY).units}
    for other in OLD[language]:
        other_units = _family(result, other).units
        assert not ssrf_raw & {r for u in other_units for r in u["raw_finding_ids"]}
        assert not ssrf_ids & {u["unit_id"] for u in other_units}
    # The alert on the command argument is a unit of the SSRF family of its own.
    path = "index.js" if language == "javascript" else "app.py"
    shared = (path, tuple(sorted(ALERTS[language][0][1].items())))
    assert shared in places(SSRF_FAMILY)


@pytest.mark.parametrize("language", ["python", "javascript"])
@pytest.mark.parametrize(
    ("mode", "status", "units", "held", "decision", "kept"),
    [
        ("failed", "failed", 0, 0, None, None),
        ("failed-with-results", "failed", 0, None, NOT_RANKED_DECISION, [NOT_RANKED]),
        ("partial", "partial", None, 0, KEPT_DECISION, ["run_incomplete", NO_FILTER_CONDITION]),
    ],
)
def test_a_broken_ssrf_pass_keeps_its_alerts_and_leaves_the_other_families_alone(
    tmp_path, language, mode, status, units, held, decision, kept
):
    count = len(ALERTS[language])
    units = count if units is None else units
    held = count if held is None else held
    result = _compose(tmp_path / "broken", SsrfTools(**{f"{language}_ssrf": mode}), language)
    clean = _compose(tmp_path / "clean", SsrfTools(), language)
    for name in OLD[language]:
        ours, theirs = _family(result, name), _family(clean, name)
        assert (ours.status, ours.units, ours.assessments) == (
            theirs.status,
            theirs.units,
            theirs.assessments,
        )
    ssrf = _family(result, SSRF_FAMILY)
    assert (ssrf.status, len(ssrf.units)) == (status, units)
    assert result.status == "partial"
    assert result.steps[SSRF_PASS]["status"] == ("partial" if mode == "partial" else "failed")
    held_units = [unit for part in result.held for unit in part.units]
    assert len(held_units) == held
    assessments = [a for part in result.held for a in part.assessments] + list(ssrf.assessments)
    if decision is not None:
        assert {a["decision_id"] for a in assessments} == {decision}
        assert {tuple(a["adjudication"]["kept_because"]) for a in assessments} == {tuple(kept)}
        assert {(a["priority"], a["disposition"]) for a in assessments} == {("U", "review")}
    # Whatever happened, every finding of the run is in exactly one unit.
    assert _in_units_once(result)


def test_an_ssrf_alert_of_a_rule_the_profile_does_not_pin_is_held_unranked(tmp_path):
    result = _compose(tmp_path, SsrfTools(ssrf_rule="js/client-side-request-forgery"), "javascript")
    ssrf = _family(result, SSRF_FAMILY)
    assert (ssrf.status, ssrf.units) == ("failed", [])
    (part,) = result.held
    assert part.family == SSRF_FAMILY and len(part.units) == len(ALERTS["javascript"])
    assert _family(result, "cross-site-scripting").status == "completed"


# --- Through the worker, the database, the API and the exports --------------------------------


def test_the_api_accepts_the_five_family_profile(client, monkeypatch):
    project_id = client.post("/api/v1/projects", json={"name": "Five"}).json()["id"]
    monkeypatch.setattr("app.workflows.scans.router.run_scan.delay", lambda scan_id: None)
    response = client.post(
        f"/api/v1/projects/{project_id}/scans",
        json={
            "source": {"kind": "npm", "package": "curling", "version": "0.2.0"},
            "profile": PROFILE,
        },
    )
    assert response.status_code == 202, response.text
    assert client.get(f"/api/v1/scans/{response.json()['scan_id']}").json()["profile"] == PROFILE


def _ssrf_results(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        r
        for run in sarif["runs"]
        for r in run["results"]
        if r["properties"]["securityTriage"]["analysisFamily"] == SSRF_FAMILY
    ]


def test_a_five_family_scan_is_stored_and_exported_with_every_ssrf_alert(client, engine):
    scan_id, status = _scan(engine, SsrfTools())
    baseline, _ = _scan(engine, SsrfTools(), profile=BASELINE)
    assert status == "completed"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    families = {f["family"]: f for f in scan["families"]}
    assert list(families) == [
        "command-injection",
        "path-traversal",
        "sql-injection",
        "cross-site-scripting",
        SSRF_FAMILY,
    ]
    ssrf = families[SSRF_FAMILY]
    total = len(ALERTS["python"]) + len(ALERTS["javascript"])
    assert (ssrf["cwe"], ssrf["profile_id"]) == ("CWE-918", SSRF)
    assert (ssrf["units"], ssrf["review"], ssrf["filtered"], ssrf["held"]) == (total, total, 0, 0)
    assert sorted((r["language"], r["status"], r["raw_findings"]) for r in ssrf["runs"]) == [
        ("javascript", "completed", len(ALERTS["javascript"])),
        ("python", "completed", len(ALERTS["python"])),
    ]
    tool_runs = {(run["language"], run["tool"]): run["status"] for run in scan["tool_runs"]}
    assert tool_runs[("python", SSRF_PASS)] == tool_runs[("javascript", SSRF_PASS)] == "completed"
    # The other families read exactly as in a multi-cwe-v0.5 scan of the same input.
    for family in OLD["python"] + ["cross-site-scripting"]:
        assert sorted(map(_decided, _units(client, scan_id, family=family))) == sorted(
            map(_decided, _units(client, baseline, family=family))
        )
    units = _units(client, scan_id, family=SSRF_FAMILY)
    assert len(units) == total
    assert {
        (u["priority"], u["disposition"], u["decision_id"], u["evidence_state"]) for u in units
    } == {("U", "review", KEPT_DECISION, "insufficient")}
    findings = [f for u in units for f in _detail(client, scan_id, u)["findings"]]
    assert {(f["tool_pass"], tuple(f["cwe_ids"])) for f in findings} == {
        (SSRF_PASS, tuple(SSRF_CWES))
    }
    assert sorted(f["rule_id"] for f in findings) == sorted(
        rule for alerts in ALERTS.values() for rule, _ in alerts
    )

    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["raw_alerts"][SSRF_PASS] == total
    family = next(f for f in report["families"] if f["family"] == SSRF_FAMILY)
    assert (family["raw_alerts"], family["units"], family["main_list"], family["filtered"]) == (
        total,
        total,
        total,
        0,
    )
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    exported = _ssrf_results(sarif)
    assert sorted(
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["locations"][0]["physicalLocation"]["region"]["startColumn"],
        )
        for r in exported
    ) == sorted(
        (
            rule,
            "index.js" if language == "javascript" else "app.py",
            r["startLine"],
            r["startColumn"],
        )
        for language, alerts in ALERTS.items()
        for rule, r in alerts
    )
    for result in exported:
        triage = result["properties"]["securityTriage"]
        assert (triage["analysisFamily"], triage["cwe"]) == (SSRF_FAMILY, "CWE-918")
        assert (triage["reportedCwes"], triage["mappedCwes"]) == (SSRF_CWES, ["CWE-918"])
        assert (triage["disposition"], triage["filterRule"], triage["ranked"]) == (
            "review",
            None,
            True,
        )
        assert "suppressions" not in result
    assert sum(len(run["results"]) for run in sarif["runs"]) == report["stages"]["raw_alerts"]


def test_a_failed_ssrf_pass_in_one_language_keeps_the_other_languages_alerts(client, engine):
    # Python's SSRF pass wrote its SARIF and then failed; JavaScript's completed.
    scan_id, status = _scan(engine, SsrfTools(python_ssrf="failed-with-results"))
    clean, _ = _scan(engine, SsrfTools())
    assert status == "partial"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "partial" and SSRF_FAMILY in scan["error_message"]
    tool_runs = {(run["language"], run["tool"]): run["status"] for run in scan["tool_runs"]}
    assert (tool_runs[("python", SSRF_PASS)], tool_runs[("javascript", SSRF_PASS)]) == (
        "failed",
        "completed",
    )
    ssrf = next(f for f in scan["families"] if f["family"] == SSRF_FAMILY)
    assert sorted((r["language"], r["status"]) for r in ssrf["runs"]) == [
        ("javascript", "completed"),
        ("python", "failed"),
    ]
    total = len(ALERTS["python"]) + len(ALERTS["javascript"])
    held = len(ALERTS["python"])
    assert (ssrf["units"], ssrf["review"], ssrf["filtered"], ssrf["held"]) == (
        total,
        total,
        0,
        held,
    )
    units = _units(client, scan_id, family=SSRF_FAMILY)
    assert Counter(
        (u["path"].endswith(".js"), u["decision_id"], u["evidence_state"]) for u in units
    ) == {
        (False, NOT_RANKED_DECISION, "unavailable"): held,
        (True, KEPT_DECISION, "insufficient"): len(ALERTS["javascript"]),
    }
    assert {(u["priority"], u["disposition"]) for u in units} == {("U", "review")}
    for family in OLD["python"] + ["cross-site-scripting"]:
        assert sorted(map(_decided, _units(client, scan_id, family=family))) == sorted(
            map(_decided, _units(client, clean, family=family))
        )
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    exported = _ssrf_results(sarif)
    assert len(exported) == total and not [r for r in exported if "suppressions" in r]
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert sum(len(run["results"]) for run in sarif["runs"]) == report["stages"]["raw_alerts"]
