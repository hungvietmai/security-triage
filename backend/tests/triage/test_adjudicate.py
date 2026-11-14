"""Candidate grouping and the boundary rules of evidence-based filtering."""

from typing import Any

import pytest

from app.triage import adjudicate as adj
from app.triage.reconcile import reconcile_findings
from app.triage.sinks_python import locate_python_sinks

SNAPSHOT = "s" * 64
# Line 3: a shell call. Line 4: a list-form call. Line 5: a second shell call right below.
SOURCE = (
    "import os\nimport subprocess\nos.system(cmd)\nsubprocess.run([tool, arg])\nos.system(other)\n"
)
SINKS = locate_python_sinks("app.py", SOURCE)
BASELINE, CONTROL, EVIDENCE = "py/command-line-injection", "st/cwe-78/none", "st/cwe-78/all"


def _sink(line: int) -> Any:
    return next(sink for sink in SINKS if sink["span"]["startLine"] == line)


def _finding(raw_id: str, rule_id: str, region: dict[str, int], **raw: Any) -> dict[str, Any]:
    return {
        "raw_id": raw_id,
        "tool": raw_id.split(":")[0],
        "snapshot_sha256": SNAPSHOT,
        "rule_id": rule_id,
        "reported_path": "app.py",
        "reported_region": dict(region),
        "message": "",
        "raw_result": raw,
    }


def _argument(line: int, position: int = 0) -> dict[str, int]:
    return next(a["span"] for a in _sink(line)["args"] if a["position"] == position)


def _run(
    findings: list[dict[str, Any]],
    *,
    families: dict[str, str] | None = None,
    proofs: set[int] | None = None,
    complete: bool = True,
    evidence: dict[str, Any] | None = None,
    semgrep: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Reconcile for real, then adjudicate minimal assessments built from the units."""
    units = reconcile_findings(findings, SINKS, {"app.py": SOURCE})
    assessments = [
        {
            "unit_id": unit["unit_id"],
            "priority": "P3",
            "finding_evidence": [
                {"raw_id": raw_id, "claim_family": (families or {}).get(raw_id, "audit")}
                for raw_id in unit["raw_finding_ids"]
            ],
            "blocker_proof": {"id": "whole_command_literal_v1"}
            if unit["sink_span"] and unit["sink_span"]["startLine"] in (proofs or set())
            else None,
        }
        for unit in units
    ]
    return adj.adjudicate(
        units,
        assessments,
        findings,
        complete=complete,
        codeql_evidence=evidence,
        semgrep_evidence=semgrep,
    )


def _evidence(control: list[dict[str, Any]], kept: list[dict[str, Any]], **overrides: Any) -> Any:
    alerts = [{**f, "rule_id": CONTROL} for f in control] + [
        {**f, "rule_id": EVIDENCE} for f in kept
    ]
    return {
        "tool": "codeql-safety-evidence",
        "tool_version": "CodeQL 2.27.1, evidence pack 0.2",
        "status": "completed",
        "baseline_rules": [BASELINE],
        "evidence_rule": EVIDENCE,
        "query_sha256": {"queries/cwe78_all.ql": "a" * 64},
        "locations": adj.codeql_evidence_index(
            alerts, baseline_rule=CONTROL, evidence_rule=EVIDENCE
        ),
        **overrides,
    }


def test_two_tools_reporting_one_call_at_different_positions_form_one_candidate():
    # CodeQL highlights the executable; Bandit highlights the whole call, so the unit key's
    # argument role differs and the reconciler keeps two units. They are still one call.
    findings = [
        _finding("codeql:0:0", BASELINE, _sink(4)["args"][0]["sequence_items"][0]),
        _finding("bandit:0:0", "B603", _sink(4)["span"]),
    ]
    result = _run(findings, families={"codeql:0:0": "flow"})
    assert len(result) == 2
    assert len({a["candidate"]["key"] for a in result}) == 1
    candidate = result[0]["candidate"]
    assert (candidate["basis"], candidate["tools"]) == ("same_call_site", ["bandit", "codeql"])
    assert len(candidate["unit_ids"]) == 2


def test_alerts_on_adjacent_lines_about_different_calls_stay_separate():
    findings = [
        _finding("semgrep:0:0", "subprocess-shell-true", _argument(3)),
        _finding("bandit:0:0", "B605", _sink(5)["span"]),
    ]
    result = _run(findings)
    assert len({a["candidate"]["key"] for a in result}) == 2
    assert [a["candidate"]["tools"] for a in result] == [["semgrep"], ["bandit"]]


def test_an_alert_without_a_matching_call_is_its_own_candidate_and_is_kept():
    elsewhere = {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 10}
    (assessment,) = _run([_finding("bandit:0:0", "B604", elsewhere)])
    assert assessment["candidate"]["basis"] == "unmatched_location"
    assert assessment["disposition"] == "review"
    assert assessment["adjudication"]["kept_because"] == [adj.NO_EVIDENCE]


def _refutable() -> list[dict[str, Any]]:
    """One call with a CodeQL flow and two audit alerts of the screening tools."""
    return [
        _finding("codeql:0:0", BASELINE, _argument(3)),
        _finding("semgrep:0:0", "subprocess-shell-true", _argument(3)),
        _finding("bandit:0:0", "B605", _sink(3)["span"], properties={"issue_severity": "HIGH"}),
    ]


def test_a_flow_the_evidence_query_no_longer_reports_filters_the_whole_candidate():
    findings = _refutable()
    result = _run(
        findings,
        families={"codeql:0:0": "flow"},
        evidence=_evidence(control=findings[:1], kept=[]),
    )
    assert {a["disposition"] for a in result} == {"filtered"}
    record = result[0]["adjudication"]
    assert (record["status"], record["rule"]) == ("filtered", adj.CODEQL_SAFETY_EVIDENCE)
    assert record["evidence"][0]["refuted_raw_ids"] == ["codeql:0:0"]
    assert EVIDENCE in record["reason"]
    # Filtering keeps the units and every original alert.
    assert sorted(i for a in result for i in a["candidate"]["tools"]) == sorted(
        ["bandit", "codeql", "semgrep"] * len(result)
    )


def _kept(findings: list[dict[str, Any]], **kwargs: Any) -> list[str]:
    result = _run(findings, **kwargs)
    assert {a["disposition"] for a in result} == {"review"}
    return list(result[0]["adjudication"]["kept_because"])


def test_missing_conflicting_or_incomplete_evidence_keeps_the_candidate():
    findings = _refutable()
    flow = {"codeql:0:0": "flow"}
    refuting = _evidence(control=findings[:1], kept=[])

    # The evidence query still reports the flow.
    still = _evidence(control=findings[:1], kept=findings[:1])
    assert _kept(findings, families=flow, evidence=still) == [adj.FLOW_STILL_REPORTED]
    # The pack's control query never reported this alert: nothing to compare with.
    unmatched = _evidence(control=[], kept=[])
    assert _kept(findings, families=flow, evidence=unmatched) == [adj.EVIDENCE_QUERY_MISMATCH]
    # Another tool claims a data flow to the same call.
    conflict = {**flow, "semgrep:0:0": "flow"}
    assert _kept(findings, families=conflict, evidence=refuting) == [adj.INDEPENDENT_FLOW_CLAIM]
    # A CodeQL query that has no evidence variant reported the call.
    other = [_finding("codeql:0:0", "py/shell-command-constructed-from-input", _argument(3))]
    uncovered = _evidence(control=other, kept=[])
    assert _kept(other, families=flow, evidence=uncovered) == [adj.FLOW_WITHOUT_EVIDENCE_QUERY]
    # The evidence step failed, or the scan itself is incomplete.
    failed = {**refuting, "status": "failed"}
    assert _kept(findings, families=flow, evidence=failed) == [adj.EVIDENCE_STEP_FAILED]
    assert _kept(findings, families=flow, evidence=refuting, complete=False) == [adj.RUN_INCOMPLETE]
    # No evidence run at all, and no CodeQL alert to refute.
    assert _kept(findings, families=flow) == [adj.NO_EVIDENCE]
    assert _kept(findings[1:], evidence=refuting) == [adj.NO_EVIDENCE]


def _literal(severity: str | None) -> list[dict[str, Any]]:
    findings = [_finding("semgrep:0:0", "subprocess-shell-true", _argument(3))]
    if severity is not None:
        properties = {"issue_severity": severity}
        findings.append(_finding("bandit:0:0", "B605", _sink(3)["span"], properties=properties))
    return findings


def test_a_literal_command_is_filtered_only_when_bandit_also_rates_it_literal():
    result = _run(_literal("LOW"), proofs={3})
    assert {a["disposition"] for a in result} == {"filtered"}
    record = result[0]["adjudication"]
    assert record["rule"] == adj.LITERAL_COMMAND
    assert [item["tool"] for item in record["evidence"]] == ["security-triage", "bandit"]


@pytest.mark.parametrize(
    ("severity", "proofs", "families", "expected"),
    [
        (None, {3}, {}, adj.LITERAL_WITHOUT_SECOND_SOURCE),  # no Bandit alert at the call
        ("HIGH", {3}, {}, adj.LITERAL_WITHOUT_SECOND_SOURCE),  # Bandit sees a built command
        ("LOW", set(), {}, adj.NO_EVIDENCE),  # Bandit alone is not enough
        ("LOW", {3}, {"semgrep:0:0": "flow"}, adj.NO_EVIDENCE),  # a flow claim blocks the rule
    ],
)
def test_a_literal_command_without_two_sources_or_with_a_flow_claim_is_kept(
    severity, proofs, families, expected
):
    assert _kept(_literal(severity), proofs=proofs, families=families) == [expected]


def test_the_candidate_takes_the_best_priority_of_its_units():
    findings = [
        _finding("codeql:0:0", BASELINE, _sink(4)["args"][0]["sequence_items"][0]),
        _finding("bandit:0:0", "B603", _sink(4)["span"]),
    ]
    units = reconcile_findings(findings, SINKS, {"app.py": SOURCE})
    assessments: list[dict[str, Any]] = [
        {
            "unit_id": unit["unit_id"],
            "priority": tier,
            "finding_evidence": [],
            "blocker_proof": None,
        }
        for unit, tier in zip(units, ("P3", "P1"), strict=True)
    ]
    result = adj.adjudicate(units, assessments, findings, complete=True)
    assert [a["candidate"]["priority"] for a in result] == ["P1", "P1"]
    # The unit's own tier is unchanged.
    assert [a["priority"] for a in result] == ["P3", "P1"]


DEAD_LINE = 2  # where the synthetic "assignment in a branch that never runs" sits


def _trace(*lines: int) -> dict[str, Any]:
    """A SARIF code flow with one reported path through the given lines of app.py."""
    steps = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }
        }
        for line in lines
    ]
    return {"threadFlows": [{"locations": steps}]}


def _semgrep(*, baseline: bool = True, survives: bool = False, **overrides: Any) -> dict[str, Any]:
    """Semgrep's evidence run: control rule at the line-3 command, optionally the evidence rule."""
    command = _argument(3)
    dead = {"startLine": DEAD_LINE, "startColumn": 9, "endLine": DEAD_LINE, "endColumn": 14}
    alerts = [_finding("semgrep-evidence:0:0", "tmp.st-dead-assignment", dead)]
    if baseline:
        alerts.append(_finding("semgrep-evidence:0:1", "tmp.st-cmd-flow-none", command))
    if survives:
        alerts.append(_finding("semgrep-evidence:0:2", "tmp.st-cmd-flow-all", command))
    return {
        "tool": "semgrep",
        "tool_version": "Semgrep CE 1.178.0, evidence rules 0.1",
        "status": "completed",
        "baseline_rule": "st-cmd-flow-none",
        "evidence_rule": "st-cmd-flow-all",
        "dead_code_rule": "st-dead-assignment",
        "rules_sha256": "b" * 64,
        "locations": adj.semgrep_evidence_index(
            alerts,
            baseline_rule="st-cmd-flow-none",
            evidence_rule="st-cmd-flow-all",
            dead_code_rule="st-dead-assignment",
        ),
        **overrides,
    }


def _dead_flow(*lines: int) -> list[dict[str, Any]]:
    """A CodeQL flow whose reported path runs through `lines`, plus two audit alerts."""
    return [
        _finding("codeql:0:0", BASELINE, _argument(3), codeFlows=[_trace(*lines)]),
        _finding("semgrep:0:0", "subprocess-shell-true", _argument(3)),
        _finding("bandit:0:0", "B605", _sink(3)["span"], properties={"issue_severity": "HIGH"}),
    ]


def test_a_flow_that_exists_only_through_a_dead_branch_is_filtered_on_semgrep_evidence():
    findings = _dead_flow(1, DEAD_LINE, 3)
    result = _run(findings, families={"codeql:0:0": "flow"}, semgrep=_semgrep())
    assert {a["disposition"] for a in result} == {"filtered"}
    record = result[0]["adjudication"]
    assert (record["rule"], record["rules"]) == (
        adj.SEMGREP_DEAD_BRANCH,
        [adj.SEMGREP_DEAD_BRANCH],
    )
    evidence = record["evidence"][0]
    assert (evidence["tool"], evidence["flows_through_dead_code"]) == ("semgrep", ["codeql:0:0"])
    assert evidence["dead_lines"] == [["app.py", DEAD_LINE, DEAD_LINE]]


def test_both_evidence_sources_are_recorded_when_each_refutes_the_flow():
    findings = _dead_flow(1, DEAD_LINE, 3)
    result = _run(
        findings,
        families={"codeql:0:0": "flow"},
        semgrep=_semgrep(),
        evidence=_evidence(control=findings[:1], kept=[]),
    )
    record = result[0]["adjudication"]
    assert record["rules"] == [adj.SEMGREP_DEAD_BRANCH, adj.CODEQL_SAFETY_EVIDENCE]
    assert [item["rule"] for item in record["evidence"]] == record["rules"]
    assert adj.CODEQL_SAFETY_EVIDENCE in record["reason"]


def test_audit_alerts_at_a_call_whose_only_request_flow_is_dead_are_filtered():
    # No tool claims a flow; Semgrep's evidence shows the request data cannot reach the command.
    findings = _dead_flow(1, DEAD_LINE, 3)[1:]
    result = _run(findings, semgrep=_semgrep())
    assert result[0]["adjudication"]["rules"] == [adj.SEMGREP_DEAD_BRANCH]
    assert result[0]["adjudication"]["evidence"][0]["flows_through_dead_code"] == []


def test_dead_branch_evidence_never_overrides_a_live_or_unchecked_flow():
    flow = {"codeql:0:0": "flow"}
    through = _dead_flow(1, DEAD_LINE, 3)

    # The evidence rule still reports the command: some flow does not use the dead branch.
    assert _kept(through, families=flow, semgrep=_semgrep(survives=True)) == [adj.NO_EVIDENCE]
    # Semgrep's control rule saw no flow here at all: nothing was shown to be dead.
    assert _kept(through, families=flow, semgrep=_semgrep(baseline=False)) == [adj.NO_EVIDENCE]
    # CodeQL's reported path does not pass through the dead assignment.
    around = _dead_flow(1, 3)
    assert _kept(around, families=flow, semgrep=_semgrep()) == [adj.FLOW_NOT_THROUGH_DEAD_CODE]
    # One of two reported paths avoids it.
    two = _dead_flow(1, DEAD_LINE, 3)
    two[0]["raw_result"]["codeFlows"].append(_trace(1, 3))
    assert _kept(two, families=flow, semgrep=_semgrep()) == [adj.FLOW_NOT_THROUGH_DEAD_CODE]
    # A flow claim without any reported path cannot be compared with the dead code.
    untraced = [
        _finding("semgrep:0:0", "dangerous-system-call", _argument(3)),
        _finding("bandit:0:0", "B605", _sink(3)["span"]),
    ]
    assert _kept(untraced, families={"semgrep:0:0": "flow"}, semgrep=_semgrep()) == [
        adj.FLOW_WITHOUT_TRACE
    ]
    # CodeQL's own evidence query, which models constant branches, still reports the flow.
    still = _evidence(control=through[:1], kept=through[:1])
    assert _kept(through, families=flow, semgrep=_semgrep(), evidence=still) == [
        adj.FLOW_STILL_REPORTED
    ]
    # The Semgrep evidence step failed, or the scan is incomplete.
    assert _kept(through, families=flow, semgrep=_semgrep(status="failed")) == [
        adj.EVIDENCE_STEP_FAILED
    ]
    assert _kept(through, families=flow, semgrep=_semgrep(), complete=False) == [adj.RUN_INCOMPLETE]


def test_dead_branch_evidence_applies_only_to_the_call_it_was_reported_at():
    # Semgrep's control rule fired at the line-3 command; the alert is at the line-5 command.
    elsewhere = [_finding("semgrep:0:0", "subprocess-shell-true", _argument(5))]
    assert _kept(elsewhere, semgrep=_semgrep()) == [adj.NO_EVIDENCE]
