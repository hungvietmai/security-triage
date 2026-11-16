"""The sql-injection family with Semgrep, Bandit and CodeQL (sql-injection-v0.2, multi-cwe-v0.3).

The sources are synthetic test data and every tool is scripted at its boundary: the command
member's tools (`Tools.pipeline`), CodeQL passes on the shared database (`analyze`) and the SQL
member's own Semgrep and Bandit passes (`member_pass`). Everything between the tools' output
and the API is the real code: classification, the SQL call locator, merging, persistence, the
report and the SARIF export.

What must hold: CWE-78 and CWE-22 come out exactly as in multi-cwe-v0.2; alerts of several
tools are merged only inside one located SQL execution call; every SQL alert sits in exactly
one unit in the review list; a failed pass of one tool leaves the others' alerts in place.
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
from app.features.findings.models import Finding as FindingRow
from app.features.scans.models import Scan, ToolRun
from app.scanners.profile import DetectionProfile, load_member_profile
from app.workflows.scans import task as scan_task
from app.workflows.scans.detection import (
    DETECTION_UNIT_VERSION_V2,
    KEPT_DECISION,
    NO_FILTER_CONDITION,
    canonical_rule_id,
)
from app.workflows.scans.families import (
    NOT_RANKED_DECISION,
    CompositeResult,
    compose,
    scan_language_families,
)
from tests.workflows.scans.fakes import FakeStorage
from tests.workflows.scans.test_composite_scan import _detail, _never_invoked, _units
from tests.workflows.scans.test_families import (
    COMMAND,
    PATH,
    SNAPSHOT,
    SOURCE,
    STEP,
    _finding,
    _profile,
    _workspace,
)
from tests.workflows.scans.test_legacy_golden import fixed_archive
from tests.workflows.scans.test_sql_family import SqlTools, standard_pack  # noqa: F401

SQL2 = "sql-injection-v0.2"
PROFILE = "multi-cwe-v0.3"
SEMGREP_PASS = "semgrep-sql-injection"
BANDIT_PASS = "bandit-sql-injection"
CODEQL_PASS = "codeql-sql-injection"
# Line 4: the query is built inside the call. Line 5: it is built apart and run on line 6.
# Line 7: one execute call inside another; the inner one runs the tainted query.
DB_SOURCE = (
    "import sqlite3\n"
    "from flask import request\n"
    "cur = sqlite3.connect('db').cursor()\n"
    "cur.execute('SELECT * FROM t WHERE a = ' + request.args['a'])\n"
    "query = 'SELECT * FROM t WHERE b = ' + request.args['b']\n"
    "cur.execute(query)\n"
    "cur.execute(str(cur.execute('SELECT 1 WHERE c = ' + request.args['c'])))\n"
)
FILES = {"app.py": SOURCE, "db.py": DB_SOURCE}


def _db_region(line: int, text: str) -> dict[str, Any]:
    column = DB_SOURCE.splitlines()[line - 1].index(text) + 1
    return {
        "startLine": line,
        "startColumn": column,
        "endLine": line,
        "endColumn": column + len(text),
    }


LINE4 = _db_region(4, "'SELECT * FROM t WHERE a = ' + request.args['a']")
LINE5 = _db_region(5, "'SELECT * FROM t WHERE b = ' + request.args['b']")
LINE6 = _db_region(6, "query")
LINE7 = _db_region(7, "'SELECT 1 WHERE c = ' + request.args['c']")
# CodeQL writes a one-line region without endLine; SARIF says it ends on its start line.
CODEQL_LINE4 = {key: value for key, value in LINE4.items() if key != "endLine"}


def _sql2_profile() -> Any:
    settings = get_settings()
    return load_member_profile(settings.triage_root, f"profiles/{SQL2}/profile.json")


def _semgrep_rule_id(canonical: str, language: str = "python") -> str:
    """The rule ID Semgrep reports for a pinned rule staged by `run_semgrep_pass`."""
    rules = _sql2_profile().configs[language]["semgrep_rules"]
    index = next(i for i, rule in enumerate(rules) if rule["canonical_rule_id"] == canonical)
    return f"tmp.work.{language}.{SEMGREP_PASS}-rules.r{index:02d}.{rules[index]['rule_id']}"


FLASK = "python.flask.security.injection.tainted-sql-string.tainted-sql-string"
FORMATTED = "python.lang.security.audit.formatted-sql-query.formatted-sql-query"


def _db(raw_id: str, tool: str, rule: str, region: dict[str, Any], cwes: list[str]) -> Any:
    finding = _finding(raw_id, tool, rule, region, cwes)
    finding["reported_path"] = "db.py"
    return finding


@dataclasses.dataclass
class MultiTools(SqlTools):
    """SqlTools, with the SQL alerts in db.py and the SQL member's Semgrep and Bandit passes."""

    semgrep_pass: str = "completed"
    bandit_pass: str = "completed"
    semgrep_rule: str = ""
    calls: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    def _sql_alerts(self, name: str) -> list[Any]:
        return [
            _db(f"{name}:0:{index}", name, self.sql_rule, region, ["cwe-089"])
            for index, region in enumerate((CODEQL_LINE4, LINE6, LINE7))
        ]

    def member_pass(self, tool: str, **kwargs: Any) -> tuple[Any, list[Any], bool]:
        name = kwargs["name"]
        self.calls.append((tool, name))
        config = kwargs["config"]
        assert kwargs["repository_root"] == _sql2_profile().root
        status = self.semgrep_pass if tool == "semgrep" else self.bandit_pass
        if status == "failed":
            raise RuntimeError("Scanner produced no SARIF output")
        if tool == "semgrep":
            assert name == SEMGREP_PASS and len(config["semgrep_rules"]) == 25
            rule = self.semgrep_rule or _semgrep_rule_id(FLASK)
            found = [
                _db(
                    f"{name}:0:0", name, rule, LINE4, ["CWE-704: Incorrect Type Conversion or Cast"]
                ),
                _db(f"{name}:0:1", name, _semgrep_rule_id(FORMATTED), LINE5, ["CWE-89"]),
            ]
        else:
            assert name == BANDIT_PASS and config["bandit"]["rules"] == ["B608", "B610", "B611"]
            found = [
                _db(f"{name}:0:{index}", name, "B608", region, ["CWE-89"])
                for index, region in enumerate((LINE4, LINE5, LINE7))
            ]
        for finding in found:
            finding["tool"] = tool
        (kwargs["output"] / f"{name}.sarif").write_text('{"runs": []}\n', encoding="utf-8")
        record = {**STEP, "status": status, "seconds": 2.0, "raw_findings": len(found)}
        return record, found, status == "completed"


def _compose(tmp_path: Path, tools: MultiTools, sql: str = SQL2) -> CompositeResult:
    source, output = _workspace(tmp_path, "multi", FILES)
    settings = get_settings()
    sql_profile = load_member_profile(settings.triage_root, f"profiles/{sql}/profile.json")
    return scan_language_families(
        "python",
        members=compose([_profile(COMMAND), _profile(PATH), sql_profile]),
        settings=settings,
        source=source,
        files=sorted(FILES),
        output=output,
        snapshot_sha256=SNAPSHOT,
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
        pass_fn=tools.member_pass,
    )


def _family(result: CompositeResult, name: str) -> Any:
    return next(family for family in result.families if family.family == name)


def _scan(
    engine: Engine, tools: MultiTools, profile: str = PROFILE
) -> tuple[str, str, FakeStorage]:
    storage = FakeStorage()
    archive = fixed_archive(FILES)
    storage.objects[("sources", "snapshots/s.tgz")] = archive
    from tests.workflows.scans.test_composite_scan import _scan as _seed

    scan_id = _seed(engine, storage, FILES, profile)
    status = scan_task.execute_scan(
        uuid.UUID(scan_id),
        session_factory=lambda: Session(engine),
        storage=storage,  # type: ignore[arg-type]
        run_pipeline_fn=tools.pipeline,
        invoke_fn=_never_invoked,
        analyze_fn=tools.analyze,
        pass_fn=tools.member_pass,
    )
    return scan_id, status, storage


# --- Profile ------------------------------------------------------------------------------


def test_the_multi_tool_member_pins_its_tools_rules_and_merge():
    profile = _sql2_profile()
    assert isinstance(profile, DetectionProfile)
    assert (profile.profile_id, profile.unit_merge, profile.priority) == (
        SQL2,
        "sql-call-site-v1",
        "U",
    )
    python, javascript = profile.configs["python"], profile.configs["javascript"]
    assert python["scanners"] == ["semgrep", "bandit", "codeql"]
    assert javascript["scanners"] == ["semgrep", "codeql"]
    assert (len(python["semgrep_rules"]), len(javascript["semgrep_rules"])) == (25, 12)
    assert python["bandit"]["rules"] == ["B608", "B610", "B611"]
    # Every rule a pass can report is pinned with its mapped CWEs.
    assert FLASK in profile.rules["python"] and "B608" in profile.rules["python"]
    assert profile.rules["javascript"]["js/sql-injection"] == ["CWE-89", "CWE-90", "CWE-943"]
    v01 = load_member_profile(profile.root, "profiles/sql-injection-v0.1/profile.json")
    assert isinstance(v01, DetectionProfile) and v01.unit_merge is None
    # CodeQL is the same query as the CodeQL-only member.
    assert python["codeql_query_sha256"] == v01.configs["python"]["codeql_query_sha256"]


def test_a_semgrep_rule_is_named_by_the_pinned_file_it_was_staged_from():
    config = _sql2_profile().configs["python"]
    finding = {"tool": "semgrep", "rule_id": _semgrep_rule_id(FLASK)}
    assert canonical_rule_id(finding, config) == FLASK
    # The rule ID after the folder must be that file's rule; anything else is unknown.
    wrong = {"tool": "semgrep", "rule_id": _semgrep_rule_id(FLASK).replace("tainted", "other")}
    assert canonical_rule_id(wrong, config) is None
    assert (
        canonical_rule_id({"tool": "semgrep", "rule_id": "tmp.x.tainted-sql-string"}, config)
        is None
    )
    assert canonical_rule_id({"tool": "semgrep", "rule_id": "tmp.r99.x"}, config) is None
    assert canonical_rule_id({"tool": "bandit", "rule_id": "B608"}, config) == "B608"


# --- Composition --------------------------------------------------------------------------


def test_alerts_are_merged_only_inside_one_located_sql_call(tmp_path):
    result = _compose(tmp_path, MultiTools())
    sql = _family(result, "sql-injection")
    assert (sql.status, sql.error) == ("completed", None)
    by_kind = Counter(unit["sink_kind"] for unit in sql.units)
    assert by_kind == {"sql-execution-call": 3, "reported-location": 2}
    # Line 4: all three tools report inside the one call: one unit.
    line4 = next(u for u in sql.units if u["sink_span"] and u["sink_span"]["startLine"] == 4)
    assert line4["sink_kind"] == "sql-execution-call" and line4["callee"] == "cur.execute"
    assert sorted(line4["tools"]) == ["bandit", "codeql", "semgrep"]
    # Line 5: the query is built apart from any call; Semgrep and Bandit report the same
    # region there, but nothing shows they mean the same execution point: two units.
    line5 = [u for u in sql.units if u["reported_region"]["startLine"] == 5]
    assert sorted(tuple(u["tools"]) for u in line5) == [("bandit",), ("semgrep",)]
    assert {u["sink_kind"] for u in line5} == {"reported-location"}
    # Line 6: CodeQL alone at the call that runs it.
    line6 = next(u for u in sql.units if u["sink_span"] and u["sink_span"]["startLine"] == 6)
    assert line6["tools"] == ["codeql"]
    # Line 7: the alerts sit in the inner call, the one that runs the tainted query.
    line7 = next(u for u in sql.units if u["sink_span"] and u["sink_span"]["startLine"] == 7)
    assert line7["sink_span"]["startColumn"] == DB_SOURCE.splitlines()[6].index("cur.execute('") + 1
    assert sorted(line7["tools"]) == ["bandit", "codeql"]
    assert len(sql.units) == 5
    # Every SQL finding is in exactly one unit; nothing is ranked or filtered.
    assert result.conservation["families"]["sql-injection"] == {
        "routed": 8,
        "in_units": 8,
        "not_ranked": 0,
        "units": 5,
        "held_units": 0,
    }
    assert {a["disposition"] for a in sql.assessments} == {"review"}
    assert {(a["priority"], a["decision_id"]) for a in sql.assessments} == {("U", KEPT_DECISION)}
    assert {tuple(a["adjudication"]["kept_because"]) for a in sql.assessments} == {
        (NO_FILTER_CONDITION,)
    }
    assert {a["candidate"]["basis"] for a in sql.assessments} == {
        "same_call_site",
        "single_location",
    }
    assert sql.result is not None and sql.result.unit_version == DETECTION_UNIT_VERSION_V2


def test_each_tool_runs_in_a_named_pass_and_keeps_its_labels(tmp_path):
    tools = MultiTools()
    result = _compose(tmp_path, tools)
    assert tools.calls == [("semgrep", SEMGREP_PASS), ("bandit", BANDIT_PASS)]
    for name in (SEMGREP_PASS, BANDIT_PASS, CODEQL_PASS):
        step = result.steps[name]
        assert (step["kind"], step["serves"], step["status"]) == (
            "detection",
            ["sql-injection"],
            "completed",
        )
    assert result.steps["sink-locator-sql-injection"]["kind"] == "locator"
    records = {
        r["raw_id"]: r for r in result.classification if r["analysis_family"] == "sql-injection"
    }
    assert Counter(r["tool_pass"] for r in records.values()) == {
        SEMGREP_PASS: 2,
        BANDIT_PASS: 3,
        CODEQL_PASS: 3,
    }
    assert {r["family_basis"] for r in records.values()} == {"pass_provenance"}
    flask = records[f"{SEMGREP_PASS}:0:0"]
    # The tool's own label stays as written; the mapped CWE comes from the pinned manifest.
    assert flask["reported_cwes"] == ["CWE-704: Incorrect Type Conversion or Cast"]
    assert flask["mapped_cwes"] == ["CWE-89"]
    evidence = [
        record
        for assessment in _family(result, "sql-injection").assessments
        for record in assessment["finding_evidence"]
    ]
    canonical = {record["raw_id"]: record["canonical_rule_id"] for record in evidence}
    assert canonical[f"{SEMGREP_PASS}:0:0"] == FLASK
    assert canonical[f"{BANDIT_PASS}:0:0"] == "B608"
    assert canonical[f"{CODEQL_PASS}:0:0"] == "py/sql-injection"


def test_the_command_and_path_families_are_those_of_multi_cwe_v0_2(tmp_path):
    tools = MultiTools()
    three = _compose(tmp_path / "v03", tools)
    two = _compose(tmp_path / "v02", MultiTools(), sql="sql-injection-v0.1")
    for name in ("command-injection", "path-traversal"):
        ours, theirs = _family(three, name), _family(two, name)
        assert (ours.status, ours.units, ours.assessments) == (
            theirs.status,
            theirs.units,
            theirs.assessments,
        )
    # The CodeQL-only member sees the same CodeQL alerts, one unit per reported location.
    codeql_v02 = _family(two, "sql-injection")
    assert len(codeql_v02.units) == 3
    assert {tuple(u["tools"]) for u in codeql_v02.units} == {("codeql",)}


@pytest.mark.parametrize(
    ("tools", "failed_pass"),
    [
        (MultiTools(semgrep_pass="failed"), SEMGREP_PASS),
        (MultiTools(bandit_pass="failed"), BANDIT_PASS),
        (MultiTools(sql_pass="failed"), CODEQL_PASS),
    ],
)
def test_a_failed_pass_leaves_the_other_tools_alerts_in_place(tmp_path, tools, failed_pass):
    result = _compose(tmp_path / "broken", tools)
    clean = _compose(tmp_path / "clean", MultiTools())
    for name in ("command-injection", "path-traversal"):
        assert _family(result, name).units == _family(clean, name).units
    sql = _family(result, "sql-injection")
    assert sql.status == "partial" and result.status == "partial"
    assert result.steps[failed_pass]["status"] == "failed"
    # The other passes' alerts are ranked as usual, marked as coming from an incomplete run.
    assert sql.units and result.held == []
    assert {tuple(a["adjudication"]["kept_because"]) for a in sql.assessments} == {
        ("run_incomplete", NO_FILTER_CONDITION)
    }
    assert {a["disposition"] for a in sql.assessments} == {"review"}
    tool = failed_pass.split("-", 1)[0]
    assert all(tool not in unit["tools"] for unit in sql.units)
    routed = {r["raw_id"] for r in result.classification if r["analysis_family"] == "sql-injection"}
    assert routed == {raw_id for unit in sql.units for raw_id in unit["raw_finding_ids"]}


def test_every_pass_failing_ranks_nothing_and_holds_nothing_unreported(tmp_path):
    result = _compose(
        tmp_path, MultiTools(semgrep_pass="failed", bandit_pass="failed", sql_pass="failed")
    )
    sql = _family(result, "sql-injection")
    assert (sql.status, sql.units, sql.raw_finding_ids) == ("failed", [], [])
    assert result.held == []


def test_an_unpinned_semgrep_rule_holds_the_familys_alerts_unranked(tmp_path):
    result = _compose(tmp_path, MultiTools(semgrep_rule="tmp.work.python.unknown-rule"))
    sql = _family(result, "sql-injection")
    assert sql.status == "failed" and "Unexpected rule" in str(sql.error)
    (held,) = result.held
    assert held.family == "sql-injection"
    assert {a["decision_id"] for a in held.assessments} == {NOT_RANKED_DECISION}
    assert sum(len(u["raw_finding_ids"]) for u in held.units) == 8
    assert {a["disposition"] for a in held.assessments} == {"review"}


# --- Worker, database, API, report and SARIF -----------------------------------------------


def test_a_three_tool_scan_is_stored_with_a_tool_run_per_pass(client, engine):
    scan_id, status, storage = _scan(engine, MultiTools())
    assert status == "completed"
    with Session(engine) as session:
        scan = session.get_one(Scan, uuid.UUID(scan_id))
        runs = {run.tool: run for run in session.scalars(select(ToolRun))}
        for name, version in (
            (SEMGREP_PASS, "1.178.0"),
            (BANDIT_PASS, "1.9.4"),
            (CODEQL_PASS, "2.27.1"),
        ):
            assert (runs[name].status, runs[name].tool_version) == ("completed", version)
            assert str(runs[name].result_key).endswith(f"python/{name}.sarif")
        stored = {
            row.evidence["raw_id"]: row
            for row in session.scalars(
                select(FindingRow).where(FindingRow.tool_run_id == runs[SEMGREP_PASS].id)
            )
        }
        flask = stored[f"{SEMGREP_PASS}:0:0"]
        # The pinned rule's full ID is stored; what Semgrep wrote is kept next to it.
        assert flask.rule_id == FLASK
        assert flask.evidence["raw_rule_id"] == _semgrep_rule_id(FLASK)
        assert flask.cwe_ids == ["CWE-704: Incorrect Type Conversion or Cast"]
        assert [m["profile_id"] for m in scan.config["composition"]["members"]] == [
            COMMAND,
            PATH,
            SQL2,
        ]
        record = json.loads(
            storage.objects[(get_settings().s3_bucket, scan.artifacts["python/run.json"]["key"])]
        )
        assert record["steps"]["sink-locator-sql-injection"]["status"] == "completed"


def test_every_sql_alert_is_in_the_review_list_and_unsuppressed_in_sarif(client, engine):
    scan_id, _, _ = _scan(engine, MultiTools())
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    sql = next(f for f in scan["families"] if f["family"] == "sql-injection")
    assert (sql["profile_id"], sql["units"], sql["review"], sql["filtered"]) == (SQL2, 5, 5, 0)
    assert sql["runs"][0]["status"] == "completed"
    units = _units(client, scan_id, family="sql-injection")
    assert len(units) == 5
    assert {(u["priority"], u["disposition"], u["evidence_state"]) for u in units} == {
        ("U", "review", "insufficient")
    }
    assert len(_units(client, scan_id, family="sql-injection", tool="semgrep")) == 2
    assert len(_units(client, scan_id, family="sql-injection", tool="bandit")) == 3
    merged = next(u for u in units if sorted(u["tools"]) == ["bandit", "codeql", "semgrep"])
    detail = _detail(client, scan_id, merged)
    assert sorted((f["tool"], f["tool_pass"]) for f in detail["findings"]) == [
        ("bandit", BANDIT_PASS),
        ("codeql", CODEQL_PASS),
        ("semgrep", SEMGREP_PASS),
    ]
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    family = next(f for f in report["families"] if f["family"] == "sql-injection")
    assert (family["raw_alerts"], family["detection_alerts"], family["units"]) == (8, 8, 5)
    assert (family["main_list"], family["filtered"]) == (5, 0)
    assert report["raw_alerts"][SEMGREP_PASS] == 2 and report["raw_alerts"][BANDIT_PASS] == 3
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    runs = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    assert {
        name: len(runs[name]["results"]) for name in (SEMGREP_PASS, BANDIT_PASS, CODEQL_PASS)
    } == {
        SEMGREP_PASS: 2,
        BANDIT_PASS: 3,
        CODEQL_PASS: 3,
    }
    assert runs[SEMGREP_PASS]["tool"]["driver"]["version"] == "1.178.0"
    flask = next(
        r
        for r in runs[SEMGREP_PASS]["results"]
        if r["properties"]["securityTriage"]["reportedCwes"][0].startswith("CWE-704")
    )
    assert flask["ruleId"] == FLASK
    assert flask["properties"]["securityTriage"]["mappedCwes"] == ["CWE-89"]
    for run in (runs[SEMGREP_PASS], runs[BANDIT_PASS], runs[CODEQL_PASS]):
        for result in run["results"]:
            triage = result["properties"]["securityTriage"]
            assert (triage["analysisFamily"], triage["disposition"], triage["ranked"]) == (
                "sql-injection",
                "review",
                True,
            )
            assert "suppressions" not in result
            assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "db.py"
    assert sum(len(run["results"]) for run in sarif["runs"]) == report["stages"]["raw_alerts"]


def test_a_failed_semgrep_pass_is_stored_as_a_partial_scan_with_the_other_alerts(client, engine):
    scan_id, status, _ = _scan(engine, MultiTools(semgrep_pass="failed"))
    assert status == "partial"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    runs = {run["tool"]: run["status"] for run in scan["tool_runs"]}
    assert runs[SEMGREP_PASS] == "failed" and runs[BANDIT_PASS] == "completed"
    sql = next(f for f in scan["families"] if f["family"] == "sql-injection")
    assert sql["runs"][0]["status"] == "partial"
    units = _units(client, scan_id, family="sql-injection")
    assert units and {(u["disposition"], u["evidence_state"]) for u in units} == {
        ("review", "unavailable")
    }
    assert all("semgrep" not in u["tools"] for u in units)
