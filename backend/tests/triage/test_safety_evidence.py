"""Boundary rules of ranking baseline alerts by an evidence query's results."""

from typing import Any

import pytest

from app.triage.safety_evidence import HIDDEN, KEPT, assess_with_evidence

BASELINE, EVIDENCE = "st/cwe-22/none", "st/cwe-22/all"


def _alert(raw_id: str, rule_id: str, line: int | None, path: str = "app.py") -> dict[str, Any]:
    region = {"startLine": line, "startColumn": 5, "endLine": line, "endColumn": 9} if line else {}
    return {
        "raw_id": raw_id,
        "tool": "codeql",
        "rule_id": rule_id,
        "reported_path": path,
        "reported_region": region,
        "message": "flow",
    }


def _assess(findings: list[dict[str, Any]]) -> tuple[list[Any], list[dict[str, Any]]]:
    return assess_with_evidence(
        findings,
        snapshot_sha256="s" * 64,
        baseline_rule=BASELINE,
        evidence_rule=EVIDENCE,
        provenance={"policy_version": "0.2"},
    )


def test_alerts_at_one_location_form_one_unit_kept_by_any_evidence_alert():
    units, assessments = _assess(
        [
            _alert("codeql:0:0", BASELINE, 7),
            _alert("codeql:0:1", BASELINE, 7),
            _alert("codeql:0:2", EVIDENCE, 7),
        ]
    )
    assert len(units) == 1
    assert units[0]["raw_finding_ids"] == ["codeql:0:0", "codeql:0:1", "codeql:0:2"]
    assert (assessments[0]["priority"], assessments[0]["decision_id"]) == ("P1", KEPT)
    assert assessments[0]["policy_version"] == "0.2"


def test_units_are_ordered_and_identified_by_location_not_raw_id():
    first, _ = _assess([_alert("codeql:0:0", BASELINE, 9), _alert("codeql:0:1", BASELINE, 3)])
    again, assessments = _assess(
        [_alert("codeql:0:5", BASELINE, 3), _alert("codeql:0:6", BASELINE, 9)]
    )
    assert [u["sink_span"]["startLine"] for u in again] == [3, 9]
    assert [u["unit_id"] for u in again] == [u["unit_id"] for u in first]
    assert [a["decision_id"] for a in assessments] == [HIDDEN, HIDDEN]


def test_an_alert_without_a_region_is_kept_as_an_unmapped_unit():
    units, assessments = _assess([_alert("codeql:0:0", BASELINE, None)])
    assert (units[0]["mapping_status"], units[0]["sink_span"]) == ("unmapped", None)
    assert assessments[0]["priority"] == "P4"


@pytest.mark.parametrize(
    ("findings", "message"),
    [
        ([_alert("codeql:0:0", EVIDENCE, 4)], "outside the baseline"),
        ([_alert("codeql:0:0", BASELINE, 4), _alert("codeql:0:1", EVIDENCE, 5)], "outside"),
        ([_alert("codeql:0:0", "py/path-injection", 4)], "Unexpected rule"),
    ],
)
def test_results_the_queries_cannot_produce_fail_the_scan(findings, message):
    with pytest.raises(ValueError, match=message):
        _assess(findings)
