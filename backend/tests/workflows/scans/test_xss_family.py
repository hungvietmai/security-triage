"""The cross-site-scripting family (CWE-79) in a four-family scan (multi-cwe-v0.5).

The source is the synthetic JavaScript of the legacy golden tests and every tool is scripted at
its boundary: the command member's tools (`js_pipeline`, `js_locator`), CodeQL passes on the
shared database (`analyze`) and the SQL member's own Semgrep pass (`member_pass`). Everything
between the tools' output and the API is the real code: classification by pass, the detection
member's units, the composition, the worker, persistence, the report and the SARIF export.

What must hold: the command and SQL families of a multi-cwe-v0.5 scan are exactly those of a
multi-cwe-v0.4 scan of the same input; no XSS alert is lost, merged into another family's unit or
filtered; a broken XSS pass leaves the other families alone and keeps what it reported.
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
from app.scanners.profile import (
    CompositeProfile,
    DetectionProfile,
    load_any_profile,
    load_member_profile,
)
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
from tests.workflows.scans.test_composite_scan import _detail, _units
from tests.workflows.scans.test_composite_scan import _scan as _seed
from tests.workflows.scans.test_families import STEP, _finding, _workspace
from tests.workflows.scans.test_legacy_golden import (
    JS_SOURCE,
    JS_TAINTED_ARGUMENT,
    _js_span,
    js_locator,
    js_pipeline,
)
from tests.workflows.scans.test_sql_family import _decided, standard_pack  # noqa: F401

XSS = "cross-site-scripting-v0.1"
PROFILE = "multi-cwe-v0.5"
BASELINE = "multi-cwe-v0.4"
XSS_PASS = "codeql-cross-site-scripting"
SQL_PASS = "codeql-sql-injection"
XSS_FAMILY = "cross-site-scripting"
FILES = {"index.js": JS_SOURCE}
QUERIES = [
    "Security/CWE-079/ExceptionXss.ql",
    "Security/CWE-079/ReflectedXss.ql",
    "Security/CWE-079/StoredXss.ql",
    "Security/CWE-079/UnsafeHtmlConstruction.ql",
    "Security/CWE-079/UnsafeJQueryPlugin.ql",
    "Security/CWE-079/Xss.ql",
    "Security/CWE-079/XssThroughDom.ql",
]
OWN = _js_span("name) {")
SQL_REGION = _js_span("'ls -l'")
# (rule, region): two rules at one place, one alert on the command argument CodeQL's command
# query reports, one on the region of the SQL alert.
XSS_ALERTS = [
    ("js/reflected-xss", OWN),
    ("js/xss-through-dom", OWN),
    ("js/xss", _js_span(JS_TAINTED_ARGUMENT)),
    ("js/stored-xss", SQL_REGION),
]
XSS_CWES = ["cwe-079", "cwe-116"]


def _load(profile_id: str) -> CompositeProfile:
    settings = get_settings()
    profile = load_any_profile(settings.triage_root, settings.scan_profiles[profile_id])
    assert isinstance(profile, CompositeProfile)
    return profile


def _js(raw_id: str, name: str, rule: str, region: dict[str, Any], cwes: list[str]) -> Any:
    finding = _finding(raw_id, name, rule, region, cwes)
    finding["reported_path"] = "index.js"
    return finding


@dataclasses.dataclass
class XssTools:
    """The CodeQL passes of the SQL and XSS members and the SQL member's Semgrep pass."""

    # "failed": the analysis raised before writing SARIF; "failed-with-results": it wrote its
    # SARIF and then exited with an error; "partial": the SARIF says the run did not finish.
    xss_pass: str = "completed"
    xss_rule: str = ""
    calls: list[str] = dataclasses.field(default_factory=list)

    def analyze(self, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        name = kwargs["name"]
        self.calls.append(name)
        assert kwargs["query_pack"].as_posix().endswith("qlpacks/codeql/javascript-queries/2.4.6")
        output: Path = kwargs["output"]
        if name == SQL_PASS:
            alerts = [_js(f"{name}:0:0", name, "js/sql-injection", SQL_REGION, ["cwe-089"])]
            (output / f"{name}.sarif").write_text('{"runs": []}\n', encoding="utf-8")
            return {**STEP, "raw_findings": 1}, alerts, True
        assert name == XSS_PASS
        assert list(kwargs["queries"]) == QUERIES
        member = load_member_profile(get_settings().triage_root, f"profiles/{XSS}/profile.json")
        assert (
            kwargs["expected_query_sha256"] == member.configs["javascript"]["codeql_query_sha256"]
        )
        assert kwargs["jobs"] == 1 and kwargs["timeout_seconds"] == 600
        if self.xss_pass == "failed":
            raise RuntimeError("Evidence queries produced no SARIF output")
        alerts = [
            _js(f"{name}:0:{index}", name, self.xss_rule or rule, region, list(XSS_CWES))
            for index, (rule, region) in enumerate(XSS_ALERTS)
        ]
        (output / f"{name}.sarif").write_text('{"runs": []}\n', encoding="utf-8")
        status = {"failed-with-results": "failed", "partial": "partial"}.get(
            self.xss_pass, "completed"
        )
        record = {**STEP, "status": status, "seconds": 4.0, "raw_findings": len(alerts)}
        return record, alerts, status == "completed"

    def member_pass(self, tool: str, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        # The SQL member's JavaScript Semgrep pass reports nothing on this source.
        assert (tool, kwargs["name"]) == ("semgrep", "semgrep-sql-injection")
        (kwargs["output"] / f"{kwargs['name']}.sarif").write_text(
            '{"runs": []}\n', encoding="utf-8"
        )
        return {**STEP, "raw_findings": 0}, [], True


def _compose(tmp_path: Path, tools: XssTools, profile: str = PROFILE) -> CompositeResult:
    source, output = _workspace(tmp_path, "js", FILES)
    return scan_language_families(
        "javascript",
        members=members_of(_load(profile)),
        settings=get_settings(),
        source=source,
        files=sorted(FILES),
        output=output,
        snapshot_sha256="a" * 64,
        run_pipeline_fn=js_pipeline,
        invoke_fn=js_locator(1),  # type: ignore[arg-type]
        analyze_fn=tools.analyze,
        pass_fn=tools.member_pass,
    )


def _family(result: CompositeResult, name: str) -> Any:
    return next(family for family in result.families if family.family == name)


def _scan(engine: Engine, tools: XssTools, profile: str = PROFILE) -> tuple[str, str]:
    storage = FakeStorage()
    scan_id = _seed(engine, storage, FILES, profile)
    status = scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=js_pipeline,
        invoke_fn=js_locator(1),  # type: ignore[arg-type]
        analyze_fn=tools.analyze,
        pass_fn=tools.member_pass,
    )
    return scan_id, status


# --- Profiles ----------------------------------------------------------------------------------


def test_the_xss_member_pins_the_seven_cwe_079_queries_of_the_standard_pack():
    member = load_member_profile(get_settings().triage_root, f"profiles/{XSS}/profile.json")
    assert isinstance(member, DetectionProfile) and member.unit_merge is None
    # JavaScript/TypeScript only: the Python run of a four-family scan has three families.
    assert list(member.configs) == ["javascript"]
    config = member.configs["javascript"]
    assert config["scanners"] == ["codeql"] and config["semgrep_rules"] == []
    assert config["codeql_queries"] == QUERIES
    assert all(query.startswith("Security/CWE-079/") for query in config["codeql_query_sha256"])
    assert member.rules["javascript"] == {
        rule: ["CWE-79", "CWE-116"]
        for rule in (
            "js/xss-through-exception",
            "js/reflected-xss",
            "js/stored-xss",
            "js/html-constructed-from-input",
            "js/unsafe-jquery-plugin",
            "js/xss",
            "js/xss-through-dom",
        )
    }
    assert (member.priority, member.policy_id) == ("U", "cross-site-scripting-detect-and-keep")
    assert FAMILY_OF_PROFILE[XSS] == XSS_FAMILY and FAMILIES[XSS_FAMILY].cwe == "CWE-79"


def test_the_four_family_profile_adds_one_member_to_the_three_of_v0_4():
    new, old = _load(PROFILE), _load(BASELINE)
    assert [family for family, _ in new.members] == [
        "command-injection",
        "path-traversal",
        "sql-injection",
        XSS_FAMILY,
    ]
    # The first three members are the very manifests v0.4 pins.
    assert [(f, m.profile_id, m.manifest_sha256) for f, m in new.members[:3]] == [
        (f, m.profile_id, m.manifest_sha256) for f, m in old.members
    ]
    assert [member.family for member in members_of(new)][-1] == XSS_FAMILY


# --- One JavaScript run of the composition -----------------------------------------------------


def test_the_command_and_sql_families_are_those_of_multi_cwe_v0_4(tmp_path):
    tools = XssTools()
    new = _compose(tmp_path / "new", tools)
    old = _compose(tmp_path / "old", XssTools(), profile=BASELINE)
    # The path member has no JavaScript configuration; the XSS member has.
    assert [f.family for f in new.families] == ["command-injection", "sql-injection", XSS_FAMILY]
    assert [f.family for f in old.families] == ["command-injection", "sql-injection"]
    for name in ("command-injection", "sql-injection"):
        ours, theirs = _family(new, name), _family(old, name)
        assert (ours.status, ours.units, ours.assessments, ours.raw_finding_ids) == (
            theirs.status,
            theirs.units,
            theirs.assessments,
            theirs.raw_finding_ids,
        )
    assert new.status == old.status == "completed"
    assert new.steps[XSS_PASS]["serves"] == [XSS_FAMILY]
    assert new.steps[XSS_PASS]["kind"] == "detection"
    # Each member's queries run once, in a pass of its own on the database the command
    # member created; the XSS pass comes after the SQL pass.
    assert tools.calls == [SQL_PASS, XSS_PASS]


def test_every_xss_alert_is_kept_in_its_own_family_and_nothing_is_filtered(tmp_path):
    result = _compose(tmp_path, XssTools())
    xss = _family(result, XSS_FAMILY)
    assert xss.status == "completed" and xss.result is not None
    assert xss.result.unit_version == DETECTION_UNIT_VERSION
    routed = [r for r in result.classification if r["analysis_family"] == XSS_FAMILY]
    assert sorted(r["raw_id"] for r in routed) == [f"{XSS_PASS}:0:{i}" for i in range(4)]
    assert {r["tool_pass"] for r in routed} == {XSS_PASS}
    assert {tuple(r["mapped_cwes"]) for r in routed} == {("CWE-79", "CWE-116")}
    assert {tuple(r["reported_cwes"]) for r in routed} == {tuple(XSS_CWES)}
    # Two rules at one place share a unit; each keeps its own rule in the evidence.
    assert len(xss.units) == 3
    shared = next(u for u in xss.units if len(u["raw_finding_ids"]) == 2)
    assessment = next(a for a in xss.assessments if a["unit_id"] == shared["unit_id"])
    assert sorted(e["rule_id"] for e in assessment["finding_evidence"]) == [
        "js/reflected-xss",
        "js/xss-through-dom",
    ]
    assert {
        (
            a["priority"],
            a["decision_id"],
            a["disposition"],
            tuple(a["adjudication"]["kept_because"]),
        )
        for a in xss.assessments
    } == {("U", KEPT_DECISION, "review", (NO_FILTER_CONDITION,))}


def test_xss_alerts_at_another_familys_place_stay_separate_units(tmp_path):
    result = _compose(tmp_path, XssTools())

    def places(family: str) -> set[tuple[Any, ...]]:
        return {
            (u["path"], tuple(sorted((u["sink_span"] or u["reported_region"]).items())))
            for u in _family(result, family).units
        }

    def ids(family: str) -> set[str]:
        return {u["unit_id"] for u in _family(result, family).units}

    xss_raw = {r for u in _family(result, XSS_FAMILY).units for r in u["raw_finding_ids"]}
    for other in ("command-injection", "sql-injection"):
        other_raw = {r for u in _family(result, other).units for r in u["raw_finding_ids"]}
        assert not xss_raw & other_raw
        assert not ids(XSS_FAMILY) & ids(other)
    # The XSS alert on the SQL alert's region is a unit of each family, never one shared unit.
    sql_region = ("index.js", tuple(sorted(SQL_REGION.items())))
    assert sql_region in places(XSS_FAMILY) and sql_region in places("sql-injection")


@pytest.mark.parametrize(
    ("mode", "status", "units", "held", "decision", "kept"),
    [
        ("failed", "failed", 0, 0, None, None),
        ("failed-with-results", "failed", 0, 3, NOT_RANKED_DECISION, [NOT_RANKED]),
        ("partial", "partial", 3, 0, KEPT_DECISION, ["run_incomplete", NO_FILTER_CONDITION]),
    ],
)
def test_a_broken_xss_pass_keeps_its_alerts_and_leaves_the_other_families_alone(
    tmp_path, mode, status, units, held, decision, kept
):
    result = _compose(tmp_path / "broken", XssTools(xss_pass=mode))
    clean = _compose(tmp_path / "clean", XssTools())
    for name in ("command-injection", "sql-injection"):
        ours, theirs = _family(result, name), _family(clean, name)
        assert (ours.status, ours.units, ours.assessments) == (
            theirs.status,
            theirs.units,
            theirs.assessments,
        )
    xss = _family(result, XSS_FAMILY)
    assert (xss.status, len(xss.units)) == (status, units)
    assert result.status == "partial"
    assert result.steps[XSS_PASS]["status"] == ("partial" if mode == "partial" else "failed")
    held_units = [unit for part in result.held for unit in part.units]
    assert len(held_units) == held
    assessments = [a for part in result.held for a in part.assessments] + list(xss.assessments)
    if decision is not None:
        assert {a["decision_id"] for a in assessments} == {decision}
        assert {tuple(a["adjudication"]["kept_because"]) for a in assessments} == {tuple(kept)}
        assert {(a["priority"], a["disposition"]) for a in assessments} == {("U", "review")}
    # Whatever happened, every finding of the run is in exactly one unit.
    in_units = Counter(
        raw_id
        for units_ in (
            *(family.units for family in result.families),
            *(part.units for part in result.held),
        )
        for unit in units_
        for raw_id in unit["raw_finding_ids"]
    )
    assert sorted(in_units) == sorted(f["raw_id"] for f in result.findings)
    assert set(in_units.values()) == {1}


def test_an_xss_alert_of_a_rule_the_profile_does_not_pin_is_held_unranked(tmp_path):
    result = _compose(tmp_path, XssTools(xss_rule="js/code-injection"))
    xss = _family(result, XSS_FAMILY)
    assert (xss.status, xss.units) == ("failed", [])
    (part,) = result.held
    assert part.family == XSS_FAMILY and len(part.units) == 3
    assert _family(result, "command-injection").status == "completed"


# --- Through the worker, the database, the API and the exports --------------------------------


def test_the_api_accepts_the_four_family_profile(client, monkeypatch):
    project_id = client.post("/api/v1/projects", json={"name": "Four"}).json()["id"]
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


def test_a_four_family_scan_is_stored_and_exported_with_every_xss_alert(client, engine):
    scan_id, status = _scan(engine, XssTools())
    baseline, _ = _scan(engine, XssTools(), profile=BASELINE)
    assert status == "completed"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    families = {f["family"]: f for f in scan["families"]}
    assert list(families) == ["command-injection", "sql-injection", XSS_FAMILY]
    xss = families[XSS_FAMILY]
    assert (xss["cwe"], xss["profile_id"]) == ("CWE-79", XSS)
    assert (xss["units"], xss["review"], xss["filtered"], xss["held"]) == (3, 3, 0, 0)
    assert [(r["language"], r["status"], r["raw_findings"]) for r in xss["runs"]] == [
        ("javascript", "completed", 4)
    ]
    tool_runs = {(run["language"], run["tool"]): run["status"] for run in scan["tool_runs"]}
    assert tool_runs[("javascript", XSS_PASS)] == "completed"
    # The other families read exactly as in a multi-cwe-v0.4 scan of the same input.
    for family in ("command-injection", "sql-injection"):
        assert sorted(map(_decided, _units(client, scan_id, family=family))) == sorted(
            map(_decided, _units(client, baseline, family=family))
        )
    units = _units(client, scan_id, family=XSS_FAMILY)
    assert {
        (u["priority"], u["disposition"], u["decision_id"], u["evidence_state"]) for u in units
    } == {("U", "review", KEPT_DECISION, "insufficient")}
    shared = next(u for u in units if len(_detail(client, scan_id, u)["findings"]) == 2)
    detail = _detail(client, scan_id, shared)
    assert sorted((f["rule_id"], f["tool_pass"]) for f in detail["findings"]) == [
        ("js/reflected-xss", XSS_PASS),
        ("js/xss-through-dom", XSS_PASS),
    ]
    assert {tuple(f["cwe_ids"]) for f in detail["findings"]} == {tuple(XSS_CWES)}

    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["raw_alerts"][XSS_PASS] == 4
    family = next(f for f in report["families"] if f["family"] == XSS_FAMILY)
    assert (family["raw_alerts"], family["units"], family["main_list"], family["filtered"]) == (
        4,
        3,
        3,
        0,
    )
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    runs = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    exported = runs[XSS_PASS]["results"]
    assert sorted(
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["locations"][0]["physicalLocation"]["region"]["startColumn"],
        )
        for r in exported
    ) == sorted(
        (rule, "index.js", region["startLine"], region["startColumn"])
        for rule, region in XSS_ALERTS
    )
    for result in exported:
        triage = result["properties"]["securityTriage"]
        assert (triage["analysisFamily"], triage["cwe"]) == (XSS_FAMILY, "CWE-79")
        assert (triage["reportedCwes"], triage["mappedCwes"]) == (XSS_CWES, ["CWE-79", "CWE-116"])
        assert (triage["disposition"], triage["filterRule"], triage["ranked"]) == (
            "review",
            None,
            True,
        )
        assert "suppressions" not in result
    assert sum(len(run["results"]) for run in sarif["runs"]) == report["stages"]["raw_alerts"]


def test_a_failed_xss_pass_is_stored_as_a_partial_scan_with_the_other_families(client, engine):
    scan_id, status = _scan(engine, XssTools(xss_pass="failed-with-results"))
    clean, _ = _scan(engine, XssTools())
    assert status == "partial"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "partial" and XSS_FAMILY in scan["error_message"]
    tool_runs = {run["tool"]: run["status"] for run in scan["tool_runs"]}
    assert tool_runs[XSS_PASS] == "failed"
    xss = next(f for f in scan["families"] if f["family"] == XSS_FAMILY)
    assert xss["runs"][0]["status"] == "failed"
    assert (xss["units"], xss["review"], xss["filtered"], xss["held"]) == (3, 3, 0, 3)
    units = _units(client, scan_id, family=XSS_FAMILY)
    assert {(u["priority"], u["disposition"], u["decision_id"]) for u in units} == {
        ("U", "review", NOT_RANKED_DECISION)
    }
    assert {u["evidence_state"] for u in units} == {"unavailable"}
    for family in ("command-injection", "sql-injection"):
        assert sorted(map(_decided, _units(client, scan_id, family=family))) == sorted(
            map(_decided, _units(client, clean, family=family))
        )
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    xss_results = [
        r
        for run in sarif["runs"]
        for r in run["results"]
        if r["properties"]["securityTriage"]["analysisFamily"] == XSS_FAMILY
    ]
    assert len(xss_results) == 4 and not [r for r in xss_results if "suppressions" in r]
