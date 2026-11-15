"""The sql-injection family (CWE-89): detected by CodeQL and kept, in a three-family scan.

The source is the synthetic test data of test_families and the scanners are scripted. What is
tested is real: the detection member's units, routing by tool pass, the composition, the
worker, persistence, the API, the before/after report and the SARIF export.

Two things must hold. The command and path families of a `multi-cwe-v0.2` scan are exactly
those of a `multi-cwe-v0.1` scan of the same input. And no SQL alert is ever lost, merged
into another family's unit, or filtered.
"""

import dataclasses
import json
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment
from app.scanners.profile import DetectionProfile, load_member_profile
from app.workflows.scans import families, service
from app.workflows.scans import task as scan_task
from app.workflows.scans.detection import (
    DETECTION_UNIT_VERSION,
    KEPT_DECISION,
    NO_FILTER_CONDITION,
    keep_detected,
    scan_language_detection,
)
from app.workflows.scans.families import (
    COMPOSITION_VERSION,
    NOT_RANKED,
    NOT_RANKED_DECISION,
    CompositeResult,
    compose,
    scan_language_families,
)
from tests.workflows.scans.fakes import FakeStorage
from tests.workflows.scans.test_composite_scan import _composite as _scan_v01
from tests.workflows.scans.test_composite_scan import _detail, _never_invoked, _scan, _units
from tests.workflows.scans.test_families import (
    COMMAND,
    COMMAND_ARGUMENTS,
    PATH,
    PATH_REGIONS,
    SNAPSHOT,
    SOURCE,
    STEP,
    Tools,
    _finding,
    _profile,
    _region,
    _workspace,
)
from tests.workflows.scans.test_families import _composite as _two_families
from tests.workflows.scans.test_legacy_golden import JS_SOURCE, js_locator, js_pipeline

SQL = "sql-injection-v0.1"
PROFILE = "multi-cwe-v0.2"
SQL_PASS = "codeql-sql-injection"
PATH_PASS = "codeql-path-traversal"
THREE = ["command-injection", "path-traversal", "sql-injection"]
# SQL alerts: one at a place of its own, one on exactly a command argument's region, one on
# exactly a path alert's region, and one inside the command call of line 6.
SQL_REGIONS: dict[str, dict[str, Any]] = {
    "own": _region(1, "os"),
    "same-as-command": COMMAND_ARGUMENTS[0],
    "same-as-path": PATH_REGIONS["a"],
    "nested": _region(6, "'cat '"),
}


def _sql_profile() -> Any:
    """The detection member; it is no scan profile of its own, so it is loaded by its path."""
    settings = get_settings()
    return load_member_profile(settings.triage_root, f"profiles/{SQL}/profile.json")


@dataclasses.dataclass
class SqlTools(Tools):
    """The scripted scanners of test_families plus the SQL pass on the shared database."""

    sql_pass: str = "completed"
    # "failed" with results: the analysis wrote its SARIF and then exited with an error.
    sql_results_when_failed: bool = False
    sql_rule: str = "py/sql-injection"
    sql_cwes: tuple[str, ...] = ("cwe-089",)

    def _sql_alerts(self, name: str) -> list[Any]:
        return [
            _finding(f"{name}:0:{index}", name, self.sql_rule, region, list(self.sql_cwes))
            for index, region in enumerate(SQL_REGIONS.values())
        ]

    def analyze(self, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        if kwargs["name"] != SQL_PASS:
            return super().analyze(**kwargs)
        # The standard pack of the pinned bundle, on the database the command member created.
        assert kwargs["query_pack"].as_posix().endswith("qlpacks/codeql/python-queries/1.8.11")
        assert list(kwargs["queries"]) == ["Security/CWE-089/SqlInjection.ql"]
        assert (
            kwargs["expected_query_sha256"]
            == _sql_profile().configs["python"]["codeql_query_sha256"]
        )
        if self.database != "completed":
            raise RuntimeError("No CodeQL database to run evidence queries on")
        if self.sql_pass == "failed" and not self.sql_results_when_failed:
            raise RuntimeError("Evidence queries produced no SARIF output")
        alerts = self._sql_alerts(kwargs["name"])
        (kwargs["output"] / f"{kwargs['name']}.sarif").write_text(
            '{"runs": []}\n', encoding="utf-8"
        )
        record = {**STEP, "status": self.sql_pass, "seconds": 3.5, "raw_findings": len(alerts)}
        return record, alerts, self.sql_pass == "completed"


@pytest.fixture(autouse=True)
def standard_pack(monkeypatch, tmp_path):
    """A stand-in for the installed standard query pack: only its manifest is read here."""
    home = tmp_path / "codeql-home"
    for language, version in (("python", "1.8.11"), ("javascript", "2.4.6")):
        pack = home / f"qlpacks/codeql/{language}-queries/{version}"
        pack.mkdir(parents=True)
        (pack / "qlpack.yml").write_text(f"name: codeql/{language}-queries\n", encoding="utf-8")
    monkeypatch.setenv("CODEQL_HOME", str(home))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _three(tmp_path: Path, tools: Tools, **options: Any) -> CompositeResult:
    source, output = _workspace(tmp_path, "three", {"app.py": SOURCE})
    return scan_language_families(
        "python",
        members=compose([_profile(COMMAND), _profile(PATH), _sql_profile()]),
        settings=get_settings(),
        source=source,
        files=["app.py"],
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
        **options,
    )


def _family(result: CompositeResult, name: str) -> Any:
    return next(family for family in result.families if family.family == name)


def _scan_v02(engine: Engine, tools: Tools) -> tuple[str, str, FakeStorage]:
    storage = FakeStorage()
    scan_id = _scan(engine, storage, {"app.py": SOURCE}, PROFILE)
    status = scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
    )
    return scan_id, status, storage


def _decided(unit: dict[str, Any]) -> tuple[Any, ...]:
    """What a reviewer sees of a unit, without the row IDs of one test database."""
    return (
        unit["unit_key"],
        unit["analysis_family"],
        unit["path"],
        unit["start_line"],
        unit["sink_kind"],
        unit["priority"],
        unit["decision_id"],
        unit["disposition"],
        unit["filter_rule"],
        unit["reason"],
        unit["candidate_key"],
        tuple(unit["tools"]),
        tuple(unit["kept_because"]),
        unit["evidence_state"],
    )


# --- The detection member on its own ---------------------------------------------------------


def test_every_reported_location_is_one_kept_unit_at_the_profiles_tier():
    alerts = [
        _finding("codeql:0:0", "codeql", "py/sql-injection", SQL_REGIONS["own"], ["cwe-089"]),
        _finding("codeql:0:1", "codeql", "py/sql-injection", SQL_REGIONS["own"], ["cwe-089"]),
        _finding("codeql:0:2", "codeql", "py/sql-injection", SQL_REGIONS["nested"], ["cwe-089"]),
    ]
    units, assessments = keep_detected(
        alerts,
        snapshot_sha256=SNAPSHOT,
        family="sql-injection",
        rules={"py/sql-injection": ["CWE-89"]},
        priority="U",
        complete=True,
        provenance={"policy_id": "p", "policy_version": "0.1"},
    )
    # Two alerts at one location are one unit; nothing is merged across locations.
    assert [unit["raw_finding_ids"] for unit in units] == [
        ["codeql:0:0", "codeql:0:1"],
        ["codeql:0:2"],
    ]
    for unit, assessment in zip(units, assessments, strict=True):
        assert assessment["unit_id"] == unit["unit_id"]
        assert (assessment["priority"], assessment["decision_id"]) == ("U", KEPT_DECISION)
        assert assessment["disposition"] == "review"
        adjudication = assessment["adjudication"]
        assert (adjudication["status"], adjudication["rule"], adjudication["rules"]) == (
            "kept",
            None,
            [],
        )
        assert adjudication["kept_because"] == [NO_FILTER_CONDITION]
        assert adjudication["evidence"] == []
    evidence = assessments[0]["finding_evidence"][0]
    assert (evidence["rule_id"], evidence["mapped_cwes"], evidence["reported_cwes"]) == (
        "py/sql-injection",
        ["CWE-89"],
        ["cwe-089"],
    )


def test_the_family_is_part_of_a_units_identity():
    alert = [_finding("codeql:0:0", "codeql", "r", SQL_REGIONS["own"], [])]
    common: dict[str, Any] = {
        "snapshot_sha256": SNAPSHOT,
        "rules": {"r": ["CWE-89"]},
        "priority": "U",
        "complete": True,
        "provenance": {},
    }
    (one,), _ = keep_detected(alert, family="sql-injection", **common)
    (other,), _ = keep_detected(alert, family="another-family", **common)
    assert one["unit_id"] != other["unit_id"]


def test_an_incomplete_run_keeps_its_alerts_and_says_so():
    alert = [_finding("codeql:0:0", "codeql", "r", SQL_REGIONS["own"], [])]
    _, (assessment,) = keep_detected(
        alert,
        snapshot_sha256=SNAPSHOT,
        family="sql-injection",
        rules={"r": ["CWE-89"]},
        priority="U",
        complete=False,
        provenance={},
    )
    assert assessment["disposition"] == "review"
    assert assessment["adjudication"]["kept_because"] == ["run_incomplete", NO_FILTER_CONDITION]
    assert "chưa hoàn tất" in assessment["reason"]
    state = service.evidence_state("review", KEPT_DECISION, assessment["adjudication"])
    assert state == "unavailable"


def test_an_alert_of_a_rule_the_profile_does_not_pin_is_refused():
    alert = [_finding("codeql:0:0", "codeql", "py/other", SQL_REGIONS["own"], [])]
    with pytest.raises(ValueError, match="Unexpected rule in a detection scan: 'py/other'"):
        keep_detected(
            alert,
            snapshot_sha256=SNAPSHOT,
            family="sql-injection",
            rules={"py/sql-injection": ["CWE-89"]},
            priority="U",
            complete=True,
            provenance={},
        )


def test_the_detection_member_alone_runs_its_pinned_queries_of_the_standard_pack(tmp_path):
    profile = _sql_profile()
    assert isinstance(profile, DetectionProfile)
    seen: dict[str, Any] = {}

    def pipeline(**kwargs: Any) -> Any:
        from app.scanners.pipeline import PipelineResult

        seen.update(kwargs)
        return PipelineResult(
            status="completed",
            steps={"codeql-create": dict(STEP), "codeql": dict(STEP)},  # type: ignore[dict-item]
            findings=SqlTools()._sql_alerts("codeql"),
            codeql_query_files=kwargs["codeql_query_sha256"],
            codeql_pack_manifest=None,
        )

    source, output = _workspace(tmp_path, "alone", {"app.py": SOURCE})
    result = scan_language_detection(
        "python",
        profile=profile,
        family="sql-injection",
        settings=get_settings(),
        source=source,
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=pipeline,
        invoke_fn=_never_invoked,
    )
    assert seen["scanners"] == ["codeql"] and seen["semgrep_rules"] == []
    assert seen["codeql_queries"] == ["Security/CWE-089/SqlInjection.ql"]
    assert seen["python_query_pack"].as_posix().endswith("qlpacks/codeql/python-queries/1.8.11")
    assert seen["javascript_query_pack"] is None
    assert (result.unit_version, len(result.units)) == (DETECTION_UNIT_VERSION, 4)
    assert {a["disposition"] for a in result.assessments} == {"review"}
    run = json.loads((output / "run.json").read_text(encoding="utf-8"))
    assert (run["profile_id"], run["raw_findings"], run["unit_count"]) == (SQL, 4, 4)
    assert run["codeql_query_files"] == profile.configs["python"]["codeql_query_sha256"]


# --- Three families in one composition --------------------------------------------------------


def test_the_command_and_path_families_are_those_of_the_two_family_scan(tmp_path):
    tools = SqlTools()
    three = _three(tmp_path, tools)
    two = _two_families(tmp_path, tools)
    assert [family.family for family in three.families] == THREE
    for name in ("command-injection", "path-traversal"):
        ours, theirs = _family(three, name), _family(two, name)
        assert (ours.status, ours.error) == (theirs.status, theirs.error)
        assert (ours.units, ours.assessments) == (theirs.units, theirs.assessments)
        assert ours.raw_finding_ids == theirs.raw_finding_ids
    assert three.status == two.status == "completed"
    # The same findings and records for the two families, in the same order; SQL comes after.
    assert three.findings[: len(two.findings)] == two.findings
    assert three.classification[: len(two.classification)] == two.classification


def test_every_sql_alert_is_kept_in_its_own_family_and_nothing_is_filtered(tmp_path):
    result = _three(tmp_path, SqlTools())
    sql = _family(result, "sql-injection")
    assert (sql.status, sql.error, sql.profile_id) == ("completed", None, SQL)
    assert sql.raw_finding_ids == [f"{SQL_PASS}:0:{index}" for index in range(4)]
    assert len(sql.units) == 4
    assert {a["disposition"] for a in sql.assessments} == {"review"}
    assert {a["priority"] for a in sql.assessments} == {"U"}
    assert result.conservation["families"]["sql-injection"] == {
        "routed": 4,
        "in_units": 4,
        "not_ranked": 0,
        "units": 4,
        "held_units": 0,
    }
    assert result.conservation["raw_findings"] == len(result.findings) == 17
    assert result.held == []
    # Routed by the pass that produced them; the mapped CWE comes from the pinned manifest.
    records = [r for r in result.classification if r["analysis_family"] == "sql-injection"]
    assert {(r["tool"], r["tool_pass"], r["family_basis"]) for r in records} == {
        ("codeql", SQL_PASS, "pass_provenance")
    }
    assert {tuple(r["mapped_cwes"]) for r in records} == {("CWE-89",)}
    assert {tuple(r["reported_cwes"]) for r in records} == {("cwe-089",)}
    assert {r["mapped_cwes_basis"] for r in records} == {f"pinned_rule_id:{SQL}"}
    step = result.steps[SQL_PASS]
    assert (step["kind"], step["serves"], step["seconds"]) == ("detection", ["sql-injection"], 3.5)
    assert result.steps[PATH_PASS]["kind"] == "detection+evidence"
    assert result.steps["codeql-create"]["serves"] == THREE


def test_sql_alerts_at_another_familys_place_stay_separate_units(tmp_path):
    result = _three(tmp_path, SqlTools())
    owner = {
        raw_id: family.family
        for family in result.families
        for unit in family.units
        for raw_id in unit["raw_finding_ids"]
    }
    # Every finding sits in exactly one unit, and that unit belongs to the finding's family.
    assert len(owner) == len(result.findings)
    routed = {r["raw_id"]: r["analysis_family"] for r in result.classification}
    assert owner == routed
    unit_ids = [unit["unit_id"] for family in result.families for unit in family.units]
    assert len(set(unit_ids)) == len(unit_ids)
    # The SQL alert on exactly the command argument's region did not join the command unit,
    # and the one on exactly a path alert's region did not join the path unit.
    command_unit = next(
        unit
        for unit in _family(result, "command-injection").units
        if unit["sink_span"] and unit["sink_span"]["startLine"] == 3
    )
    assert all(not raw_id.startswith(SQL_PASS) for raw_id in command_unit["raw_finding_ids"])
    path_unit = next(
        unit
        for unit in _family(result, "path-traversal").units
        if unit["sink_span"] == PATH_REGIONS["a"]
    )
    assert all(raw_id.startswith(PATH_PASS) for raw_id in path_unit["raw_finding_ids"])
    sql_spans = [unit["sink_span"] for unit in _family(result, "sql-injection").units]
    assert PATH_REGIONS["a"] in sql_spans and COMMAND_ARGUMENTS[0] in sql_spans


def test_evidence_of_the_other_families_never_touches_sql_alerts(tmp_path):
    # Both other families filter here; the SQL family is the same as when neither does.
    refuting = _three(tmp_path / "a", SqlTools(command_refuted=True, path_hidden=()))
    plain = _three(tmp_path / "b", SqlTools(path_hidden=("a", "b", "nested", "same")))
    ours, theirs = _family(refuting, "sql-injection"), _family(plain, "sql-injection")
    assert (ours.units, ours.assessments) == (theirs.units, theirs.assessments)
    assert {a["disposition"] for a in ours.assessments} == {"review"}


@pytest.mark.parametrize(
    ("tools", "status", "units", "held", "error"),
    [
        # Partial: the member keeps what was reported and marks the run incomplete.
        (SqlTools(sql_pass="partial"), "partial", 4, 0, None),
        # Failed without results: nothing to keep.
        (SqlTools(sql_pass="failed"), "failed", 0, 0, None),
        # Failed after writing results: the composition holds them for review.
        (SqlTools(sql_pass="failed", sql_results_when_failed=True), "failed", 0, 4, None),
        # A rule the member does not pin: it ranks nothing; the alerts are held.
        (SqlTools(sql_rule="py/nosql-injection"), "failed", 0, 4, "Unexpected rule"),
    ],
)
def test_a_sql_pass_that_fails_keeps_its_alerts_and_leaves_the_other_families_alone(
    tmp_path, tools, status, units, held, error
):
    result = _three(tmp_path / "broken", tools)
    clean = _three(tmp_path / "clean", SqlTools())
    for name in ("command-injection", "path-traversal"):
        ours, theirs = _family(result, name), _family(clean, name)
        assert (ours.status, ours.units, ours.assessments) == (
            theirs.status,
            theirs.units,
            theirs.assessments,
        )
    sql = _family(result, "sql-injection")
    assert (sql.status, len(sql.units)) == (status, units)
    assert (sql.error is None) == (error is None)
    if error:
        assert error in str(sql.error)
    assert result.status == "partial"
    held_units = [unit for part in result.held for unit in part.units]
    assert len(held_units) == held
    for part in result.held:
        assert part.family == "sql-injection"
        assert {a["decision_id"] for a in part.assessments} == {NOT_RANKED_DECISION}
        assert {(a["priority"], a["disposition"]) for a in part.assessments} == {("U", "review")}
    # Whatever happened, every finding of the scan is in exactly one unit.
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
    assert set(in_units.values()) <= {1}
    if tools.sql_pass == "partial":
        assert {tuple(a["adjudication"]["kept_because"]) for a in sql.assessments} == {
            ("run_incomplete", NO_FILTER_CONDITION)
        }


def test_a_failed_database_fails_the_sql_family_without_alerts(tmp_path):
    result = _three(tmp_path, SqlTools(database="failed"))
    sql = _family(result, "sql-injection")
    assert (sql.status, sql.units, sql.raw_finding_ids) == ("failed", [], [])
    assert result.steps[SQL_PASS]["status"] == "failed"
    assert "No CodeQL database" in result.steps[SQL_PASS]["error"]


def test_javascript_alerts_keep_every_mapped_cwe_of_their_rule(tmp_path):
    def analyze(**kwargs: Any) -> tuple[Any, list[Any], bool]:
        assert kwargs["name"] == SQL_PASS
        assert kwargs["query_pack"].as_posix().endswith("qlpacks/codeql/javascript-queries/2.4.6")
        region = {"startLine": 2, "startColumn": 1, "endLine": 2, "endColumn": 5}
        alert = _finding(
            f"{SQL_PASS}:0:0",
            SQL_PASS,
            "js/sql-injection",
            region,
            ["cwe-089", "cwe-090", "cwe-943"],
        )
        alert["reported_path"] = "index.js"
        return {**STEP, "raw_findings": 1}, [alert], True

    source, output = _workspace(tmp_path, "js", {"index.js": JS_SOURCE})
    result = scan_language_families(
        "javascript",
        members=compose([_profile(COMMAND), _profile(PATH), _sql_profile()]),
        settings=get_settings(),
        source=source,
        files=["index.js"],
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=js_pipeline,
        invoke_fn=js_locator(1),  # type: ignore[arg-type]
        analyze_fn=analyze,
    )
    # The path member has no JavaScript configuration; the SQL member has.
    assert [family.family for family in result.families] == ["command-injection", "sql-injection"]
    (record,) = [r for r in result.classification if r["analysis_family"] == "sql-injection"]
    assert record["mapped_cwes"] == ["CWE-89", "CWE-90", "CWE-943"]
    assert record["reported_cwes"] == ["cwe-089", "cwe-090", "cwe-943"]
    (unit,) = _family(result, "sql-injection").units
    assert unit["path"] == "index.js"
    # The command family still filters its constant command, exactly as without the SQL member.
    command = _family(result, "command-injection")
    assert [a["disposition"] for a in command.assessments].count("filtered") == 1


# --- Through the worker, the database, the API and the exports --------------------------------


def test_the_api_accepts_the_three_family_profile(client, monkeypatch):
    project_id = client.post("/api/v1/projects", json={"name": "Three"}).json()["id"]
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


def test_a_three_family_scan_stores_the_sql_family_with_its_provenance(engine):
    scan_id, status, storage = _scan_v02(engine, SqlTools())
    assert status == "completed"
    settings = get_settings()
    sql = _sql_profile()
    with Session(engine) as session:
        scan = session.get_one(Scan, uuid.UUID(scan_id))
        assert (scan.reconciler_version, scan.policy_version) == (
            COMPOSITION_VERSION,
            COMPOSITION_VERSION,
        )
        assert [m["profile_id"] for m in scan.config["composition"]["members"]] == [
            COMMAND,
            PATH,
            SQL,
        ]
        assert scan.config["composition"]["members"][2]["profile_sha256"] == sql.manifest_sha256
        runs = {run.tool: run for run in session.scalars(select(ToolRun))}
        assert (runs[SQL_PASS].status, runs[SQL_PASS].tool_version) == ("completed", "2.27.1")
        assert str(runs[SQL_PASS].result_key).endswith(f"python/{SQL_PASS}.sarif")
        units = session.scalars(
            select(LocationUnit).where(LocationUnit.analysis_family == "sql-injection")
        ).all()
        assert len(units) == 4
        assert {unit.reconciler_version for unit in units} == {DETECTION_UNIT_VERSION}
        assessments = session.scalars(
            select(UnitAssessment).where(UnitAssessment.unit_id.in_([unit.id for unit in units]))
        ).all()
        assert {(a.policy_id, a.policy_version, a.policy_sha256) for a in assessments} == {
            ("sql-injection-detect-and-keep", "0.1", sql.policy_sha256)
        }
        record = json.loads(
            storage.objects[(settings.s3_bucket, scan.artifacts["python/run.json"]["key"])]
        )
        assert (
            record["members"][2]["codeql_query_files"]
            == sql.configs["python"]["codeql_query_sha256"]
        )


def test_the_other_two_families_read_exactly_as_in_a_two_family_scan(client, engine):
    tools = SqlTools(command_refuted=True)
    new, _, _ = _scan_v02(engine, tools)
    old, _, _ = _scan_v01(engine, tools)
    for family in ("command-injection", "path-traversal"):
        ours = sorted(map(_decided, _units(client, new, family=family)))
        theirs = sorted(map(_decided, _units(client, old, family=family)))
        assert ours == theirs and ours
    new_report = client.get(f"/api/v1/scans/{new}/report").json()
    old_report = client.get(f"/api/v1/scans/{old}/report").json()
    assert new_report["families"][:2] == old_report["families"]
    assert new_report["filtered_by_rule"] == old_report["filtered_by_rule"]
    assert new_report["stages"]["filtered"] == old_report["stages"]["filtered"]


def test_sql_units_are_all_in_the_review_list_with_their_labels(client, engine):
    scan_id, _, _ = _scan_v02(engine, SqlTools())
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert [family["family"] for family in scan["families"]] == THREE
    sql = scan["families"][2]
    assert (sql["cwe"], sql["label"], sql["profile_id"]) == ("CWE-89", "SQL injection", SQL)
    assert (sql["units"], sql["review"], sql["filtered"], sql["held"]) == (4, 4, 0, 0)
    assert sql["runs"] == [
        {
            "language": "python",
            "status": "completed",
            "error": None,
            "raw_findings": 4,
            "evidence_steps": {},
        }
    ]
    units = _units(client, scan_id, family="sql-injection")
    assert len(units) == 4 == len(_units(client, scan_id, family="sql-injection", tool="codeql"))
    assert _units(client, scan_id, family="sql-injection", disposition="filtered") == []
    for unit in units:
        assert (unit["analysis_family"], unit["cwe"]) == ("sql-injection", "CWE-89")
        assert (unit["priority"], unit["decision_id"]) == ("U", KEPT_DECISION)
        assert (unit["disposition"], unit["filter_rule"]) == ("review", None)
        assert (unit["evidence_state"], unit["kept_because"]) == (
            "insufficient",
            [NO_FILTER_CONDITION],
        )
        detail = _detail(client, scan_id, unit)
        (finding,) = detail["findings"]
        assert (finding["tool"], finding["tool_pass"]) == ("codeql", SQL_PASS)
        assert (finding["rule_id"], finding["cwe_ids"], finding["mapped_cwes"]) == (
            "py/sql-injection",
            ["cwe-089"],
            ["CWE-89"],
        )
        assert (finding["analysis_family"], finding["family_basis"]) == (
            "sql-injection",
            "pass_provenance",
        )
        assert finding["start_line"] == unit["start_line"]


def test_the_report_and_sarif_keep_every_sql_alert_unsuppressed(client, engine):
    scan_id, _, _ = _scan_v02(engine, SqlTools())
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert report["raw_alerts"][SQL_PASS] == 4
    command, path, sql = report["families"]
    assert (sql["family"], sql["raw_alerts"], sql["detection_alerts"], sql["evidence_results"]) == (
        "sql-injection",
        4,
        4,
        0,
    )
    assert (sql["units"], sql["candidates"], sql["main_list"], sql["filtered"]) == (4, 4, 4, 0)
    assert sql["filtered_by_rule"] == {} and sql["evidence_states"] == {"insufficient": 4}
    assert sql["main_list_by_priority"]["U"] == 4
    for key in ("raw_alerts", "detection_alerts", "units", "candidates", "main_list", "filtered"):
        assert command[key] + path[key] + sql[key] == report["stages"][key]
    assert report["stages"]["unranked_alerts"] == 0

    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    runs = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    assert len(runs[SQL_PASS]["results"]) == 4
    assert runs[SQL_PASS]["tool"]["driver"]["version"] == "2.27.1"
    for result in runs[SQL_PASS]["results"]:
        triage = result["properties"]["securityTriage"]
        assert result["ruleId"] == "py/sql-injection"
        assert (triage["analysisFamily"], triage["cwe"]) == ("sql-injection", "CWE-89")
        assert (triage["reportedCwes"], triage["mappedCwes"]) == (["cwe-089"], ["CWE-89"])
        assert (triage["disposition"], triage["filterRule"]) == ("review", None)
        assert (triage["ranked"], triage["resultRole"]) == (True, "detection")
        assert triage["evidenceState"] == "insufficient"
        assert "suppressions" not in result
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    regions = sorted(
        (
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            result["locations"][0]["physicalLocation"]["region"]["startColumn"],
        )
        for result in runs[SQL_PASS]["results"]
    )
    assert regions == sorted(
        (region["startLine"], region["startColumn"]) for region in SQL_REGIONS.values()
    )
    exported = sum(len(run["results"]) for run in sarif["runs"])
    assert exported == report["stages"]["raw_alerts"] == 17


@pytest.mark.parametrize(
    ("tools", "family_status", "decision", "kept"),
    [
        (
            SqlTools(sql_pass="partial"),
            "partial",
            KEPT_DECISION,
            ["run_incomplete", NO_FILTER_CONDITION],
        ),
        (
            SqlTools(sql_pass="failed", sql_results_when_failed=True),
            "failed",
            NOT_RANKED_DECISION,
            [NOT_RANKED],
        ),
        (SqlTools(sql_rule="py/nosql-injection"), "failed", NOT_RANKED_DECISION, [NOT_RANKED]),
    ],
)
def test_a_broken_sql_pass_is_stored_with_its_state_and_its_alerts(
    client, engine, tools, family_status, decision, kept
):
    scan_id, status, _ = _scan_v02(engine, tools)
    clean, _, _ = _scan_v02(engine, SqlTools())
    assert status == "partial"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "partial"
    sql = scan["families"][2]
    assert sql["runs"][0]["status"] == family_status
    # The state of the SQL pass is on record: as the family's run and as its own tool run.
    tool_runs = {run["tool"]: run["status"] for run in scan["tool_runs"]}
    assert tool_runs[SQL_PASS] == ("partial" if tools.sql_pass == "partial" else tools.sql_pass)
    if family_status == "failed":
        assert "sql-injection" in scan["error_message"]
    assert (sql["units"], sql["review"], sql["filtered"]) == (4, 4, 0)
    units = _units(client, scan_id, family="sql-injection")
    assert {(u["priority"], u["disposition"], u["decision_id"]) for u in units} == {
        ("U", "review", decision)
    }
    assert {tuple(u["kept_because"]) for u in units} == {tuple(kept)}
    assert {u["evidence_state"] for u in units} == {"unavailable"}
    # The other two families are untouched by the SQL pass.
    for family in ("command-injection", "path-traversal"):
        assert sorted(map(_decided, _units(client, scan_id, family=family))) == sorted(
            map(_decided, _units(client, clean, family=family))
        )
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    exported = [r for run in sarif["runs"] for r in run["results"]]
    assert len(exported) == 17
    assert not [
        r
        for r in exported
        if r["properties"]["securityTriage"]["analysisFamily"] == "sql-injection"
        and "suppressions" in r
    ]


def test_a_detection_profile_cannot_be_scanned_alone(engine):
    # Its queries need the database another member creates.
    storage = FakeStorage()
    scan_id = _scan(engine, storage, {"app.py": SOURCE}, "sql-alone")
    settings = get_settings()
    alone = settings.model_copy(
        update={
            "scan_profiles": {
                **settings.scan_profiles,
                "sql-alone": settings.scan_profiles[PROFILE].replace("multi-cwe-v0.2", SQL),
            }
        }
    )
    with pytest.raises(ValueError, match="only runs as a member of a composite profile"):
        with Session(engine) as session:
            scan = session.get_one(Scan, uuid.UUID(scan_id))
            scan_task.scan_snapshot(
                scan.id,
                session.get_one(SourceSnapshot, scan.snapshot_id),
                settings=alone,
                storage=storage,  # type: ignore[arg-type]
                profile_id="sql-alone",
                run_pipeline_fn=_never_invoked,
                invoke_fn=_never_invoked,
            )


def test_the_family_table_knows_the_new_family():
    assert families.FAMILIES["sql-injection"].cwe == "CWE-89"
    assert families.FAMILY_OF_PROFILE[SQL] == "sql-injection"
    assert service.family_cwe("sql-injection") == "CWE-89"
    # The pass name must fit the tool-run column.
    assert len(SQL_PASS) <= 32
