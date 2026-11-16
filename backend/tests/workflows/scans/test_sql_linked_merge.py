"""multi-cwe-v0.4: a Bandit B608 alert on a SQL-building statement joins the call that runs it.

Same scripted tools and synthetic sources as test_sql_multitool, with Bandit reporting what it
really reports for a query built on its own line: the string literal (line 5 of db.py). The
query is bound to `query` and run once by `cur.execute(query)` on line 6, where CodeQL reports.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.triage.models import UnitFinding
from app.workflows.scans.detection import (
    DETECTION_UNIT_VERSION_V2,
    DETECTION_UNIT_VERSION_V3,
    LINKED_RULES,
    SITE_WITHOUT_OTHER_TOOL,
)
from app.workflows.scans.sql_sites import LINK_LOCATOR_VERSION
from tests.workflows.scans.test_composite_scan import _detail, _units
from tests.workflows.scans.test_sql_family import standard_pack  # noqa: F401
from tests.workflows.scans.test_sql_multitool import (
    BANDIT_PASS,
    CODEQL_LINE4,
    CODEQL_PASS,
    DB_SOURCE,
    LINE4,
    LINE7,
    SEMGREP_PASS,
    SQL2,
    MultiTools,
    _compose,
    _db_region,
    _family,
    _scan,
)

SQL3 = "sql-injection-v0.3"
PROFILE = "multi-cwe-v0.4"
# Bandit reports the literal of the query built on line 5, not the whole expression.
LITERAL5 = _db_region(5, "'SELECT * FROM t WHERE b = '")


def _tools(**options: Any) -> MultiTools:
    return MultiTools(bandit_regions=(LINE4, LITERAL5, LINE7), **options)


def _at(units: list[Any], line: int) -> list[Any]:
    return [u for u in units if (u["sink_span"] or u["reported_region"])["startLine"] == line]


def test_the_b608_alert_on_the_building_line_joins_the_codeql_alert_at_the_call(tmp_path):
    sql = _family(_compose(tmp_path, _tools(), sql=SQL3), "sql-injection")
    assert sql.status == "completed"
    assert sql.result is not None and sql.result.unit_version == DETECTION_UNIT_VERSION_V3
    assert sql.result.locator_version == LINK_LOCATOR_VERSION
    line6 = _at(sql.units, 6)
    assert len(line6) == 1 and line6[0]["sink_kind"] == "sql-execution-call"
    assert line6[0]["tools"] == ["bandit", "codeql"]
    mappings = {m["raw_id"]: m["mapping_method"] for m in line6[0]["mappings"]}
    assert mappings == {f"{CODEQL_PASS}:0:1": "containment", f"{BANDIT_PASS}:0:1": "explicit_link"}
    # The linked alert keeps its own region; the unit says why it is there.
    assessment = next(a for a in sql.assessments if a["unit_id"] == line6[0]["unit_id"])
    linked = next(e for e in assessment["finding_evidence"] if e["tool"] == "bandit")
    assert linked["linked_by"]["variable"] == "query"
    assert linked["linked_by"]["statement"]["startLine"] == 5
    assert assessment["predicate_values"]["linked_sql_string"] is True
    assert "`query`" in assessment["reason"]
    # Semgrep's alert on line 5 is not a linked rule: it stays where it was reported.
    assert [u["tools"] for u in _at(sql.units, 5)] == [["semgrep"]]
    # Lines 4 and 7 are merged by containment, as in v0.3.
    assert [sorted(u["tools"]) for u in _at(sql.units, 4)] == [["bandit", "codeql", "semgrep"]]
    assert [sorted(u["tools"]) for u in _at(sql.units, 7)] == [["bandit", "codeql"]]
    assert len(sql.units) == 4
    assert sorted(r for u in sql.units for r in u["raw_finding_ids"]) == sorted(
        [f"{tool}:0:{i}" for tool in (BANDIT_PASS, CODEQL_PASS) for i in range(3)]
        + [f"{SEMGREP_PASS}:0:{i}" for i in range(2)]
    )
    assert ("bandit", "B608") in LINKED_RULES


def test_the_same_alerts_under_v0_3_stay_apart(tmp_path):
    sql = _family(_compose(tmp_path, _tools()), "sql-injection")
    assert sql.result is not None and sql.result.unit_version == DETECTION_UNIT_VERSION_V2
    assert sorted(tuple(u["tools"]) for u in _at(sql.units, 5)) == [("bandit",), ("semgrep",)]
    assert [u["tools"] for u in _at(sql.units, 6)] == [["codeql"]]
    assert len(sql.units) == 5


def test_a_call_without_a_codeql_or_semgrep_alert_takes_no_bandit_alert(tmp_path):
    # CodeQL reports nothing at line 6: there is no other tool's alert there to join.
    tools = _tools(codeql_regions=(CODEQL_LINE4, LINE7))
    result = _compose(tmp_path, tools, sql=SQL3)
    sql = _family(result, "sql-injection")
    line5 = _at(sql.units, 5)
    assert sorted(tuple(u["tools"]) for u in line5) == [("bandit",), ("semgrep",)]
    assert _at(sql.units, 6) == []
    assert {m["mapping_method"] for u in sql.units for m in u["mappings"]} <= {
        "containment",
        "exact_span",
    }
    assert SITE_WITHOUT_OTHER_TOOL == "call_has_no_codeql_or_semgrep_alert"


def test_a_query_built_and_bound_twice_is_not_linked(tmp_path, monkeypatch):
    rebound = DB_SOURCE.replace(
        "cur.execute(query)\n", "query = query + ' LIMIT 1'\ncur.execute(query)\n"
    )
    from tests.workflows.scans import test_sql_multitool

    monkeypatch.setitem(test_sql_multitool.FILES, "db.py", rebound)
    sql = _family(_compose(tmp_path, _tools(), sql=SQL3), "sql-injection")
    assert all(
        "explicit_link" not in {m["mapping_method"] for m in u["mappings"]} for u in sql.units
    )


def test_a_linked_unit_is_stored_traceable_to_every_original_alert(client, engine):
    scan_id, status, _ = _scan(engine, _tools(), profile=PROFILE)
    assert status == "completed"
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    sql = next(f for f in scan["families"] if f["family"] == "sql-injection")
    assert (sql["profile_id"], sql["units"], sql["review"], sql["filtered"]) == (SQL3, 4, 4, 0)
    units = _units(client, scan_id, family="sql-injection")
    linked = next(
        u for u in units if sorted(u["tools"]) == ["bandit", "codeql"] and u["start_line"] == 6
    )
    detail = _detail(client, scan_id, linked)
    assert sorted((f["tool"], f["tool_pass"], f["start_line"]) for f in detail["findings"]) == [
        ("bandit", BANDIT_PASS, 5),
        ("codeql", CODEQL_PASS, 6),
    ]
    with Session(engine) as session:
        rules = {row.match_rule for row in session.scalars(select(UnitFinding))}
        assert "explicit_link" in rules
        versions = {row.reconciler_version for row in session.scalars(select(UnitFinding))}
        assert DETECTION_UNIT_VERSION_V3 in versions
    # Every alert is exported as the tool reported it, each with its own location.
    sarif = client.get(f"/api/v1/scans/{scan_id}/report.sarif").json()
    bandit = next(run for run in sarif["runs"] if run["tool"]["driver"]["name"] == BANDIT_PASS)
    lines = sorted(
        r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in bandit["results"]
    )
    assert lines == [4, 5, 7]
    report = client.get(f"/api/v1/scans/{scan_id}/report").json()
    assert sum(len(run["results"]) for run in sarif["runs"]) == report["stages"]["raw_alerts"]
    family = next(f for f in report["families"] if f["family"] == "sql-injection")
    assert (family["raw_alerts"], family["units"], family["filtered"]) == (8, 4, 0)
    assert uuid.UUID(scan_id)
    assert SQL2 != SQL3
