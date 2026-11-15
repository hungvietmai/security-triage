"""JavaScript matching with the v1 sink locator and the constant-command filter rule (G4).

Every source here is synthetic test data. Locator results are written as the Semgrep JSON the
worker reads; reconciliation, candidate grouping and adjudication are the real code.
"""

import json
from typing import Any

import pytest

from app.triage import adjudicate as adj
from app.triage.reconcile import reconcile_findings
from app.triage.sinks_javascript import parse_javascript_sink_output

SNAPSHOT = "s" * 64
PATH = "index.js"
# Lines 4 and 5: two calls through a two-step alias, one right below the other.
# Line 7: a call that looks similar but is not a child_process call.
# Line 9: a spawn call. Line 10: a call nested in another call.
SOURCE = """\
var childProcess = require('child_process');
var exec = childProcess.exec;
function kill(name) {
  exec('taskkill /F /IM ' + name + '.exe /T');
  exec(command);
}
function note(name) { log('pkill -f ' + name); }
function unpack(file) {
  childProcess.spawn(tool, ['-xf', file]);
  wrap(exec(inner));
}
"""
CALLS = {
    4: "exec('taskkill /F /IM ' + name + '.exe /T')",
    5: "exec(command)",
    9: "childProcess.spawn(tool, ['-xf', file])",
    10: "exec(inner)",
}


def _position(offset: int) -> dict[str, int]:
    before = SOURCE[:offset]
    return {
        "line": before.count("\n") + 1,
        "col": len(before.rsplit("\n", 1)[-1]) + 1,
        "offset": offset,
    }


def _span(text: str) -> dict[str, int]:
    start = _position(SOURCE.index(text))
    end = _position(SOURCE.index(text) + len(text))
    return {
        "startLine": start["line"],
        "startColumn": start["col"],
        "endLine": end["line"],
        "endColumn": end["col"],
    }


def _sinks() -> Any:
    results = []
    for line, text in CALLS.items():
        rule = "namespace" if line == 9 else "member-alias"
        results.append(
            {
                "check_id": f"rules.sink-locator-v1-child-process-{rule}",
                "path": PATH,
                "start": _position(SOURCE.index(text)),
                "end": _position(SOURCE.index(text) + len(text)),
            }
        )
    return parse_javascript_sink_output(json.dumps({"results": results}), {PATH: SOURCE})


def _finding(raw_id: str, rule_id: str, region: dict[str, int]) -> dict[str, Any]:
    return {
        "raw_id": raw_id,
        "tool": raw_id.split(":")[0],
        "snapshot_sha256": SNAPSHOT,
        "rule_id": rule_id,
        "reported_path": PATH,
        "reported_region": dict(region),
        "message": "",
        "raw_result": {},
    }


def _eslint(line: int) -> dict[str, Any]:
    return _finding(f"eslint:{line}", "security/detect-child-process", _span(CALLS[line]))


def _constant(*lines: int, status: str = "completed") -> dict[str, Any]:
    """Constant-command evidence as the scan analysis builds it."""
    found = [
        _finding(f"semgrep-evidence:{line}", "rules.st-js-constant-command", _span(CALLS[line]))
        for line in lines
    ]
    return {
        "tool": "semgrep",
        "tool_version": "Semgrep CE test, evidence rules js-0.1",
        "status": status,
        "evidence_rule": "st-js-constant-command",
        "rules_sha256": "0" * 64,
        "locations": adj.constant_evidence_index(found, rule="st-js-constant-command"),
    }


def _run(
    findings: list[dict[str, Any]],
    *,
    constant: dict[str, Any] | None = None,
    complete: bool = True,
    families: dict[str, str] | None = None,
) -> dict[int | None, dict[str, Any]]:
    """Reconcile and adjudicate; the result is keyed by the start line of the candidate's call."""
    units = reconcile_findings(findings, _sinks(), {PATH: SOURCE})
    assessments = [
        {
            "unit_id": unit["unit_id"],
            "priority": "P3",
            "finding_evidence": [
                {"raw_id": raw_id, "claim_family": (families or {}).get(raw_id, "audit")}
                for raw_id in unit["raw_finding_ids"]
            ],
            "blocker_proof": None,
        }
        for unit in units
    ]
    decided = adj.adjudicate(
        units, assessments, findings, complete=complete, constant_evidence=constant
    )
    lines: dict[str, int | None] = {
        unit["unit_id"]: unit["sink_span"]["startLine"] if unit["sink_span"] else None
        for unit in units
    }
    return {lines[item["unit_id"]]: item for item in decided}


def test_calls_through_a_two_step_alias_are_located_with_their_real_function():
    kinds = {sink["span"]["startLine"]: sink["sink_kind"] for sink in _sinks()}
    assert kinds == {
        4: "child_process.exec",
        5: "child_process.exec",
        9: "child_process.spawn",
        10: "child_process.exec",
    }


def test_alerts_on_two_adjacent_alias_calls_join_their_own_call_only():
    # ESLint reports both calls; CodeQL reports the string built inside the first one.
    concatenation = _span("'taskkill /F /IM ' + name + '.exe /T'")
    findings = [
        _eslint(4),
        _eslint(5),
        _finding("codeql:4", "js/shell-command-constructed-from-input", concatenation),
    ]
    decided = _run(findings)
    assert set(decided) == {4, 5}
    assert decided[4]["candidate"]["tools"] == ["codeql", "eslint"]
    assert decided[5]["candidate"]["tools"] == ["eslint"]
    assert decided[4]["candidate"]["key"] != decided[5]["candidate"]["key"]
    assert {item["candidate"]["basis"] for item in decided.values()} == {"same_call_site"}


def test_an_alert_on_a_call_that_is_not_a_located_sink_stays_alone_and_is_kept():
    # log(...) on line 7 is not a child_process call: there is nothing to merge the alert into.
    stray = _finding("eslint:7", "security/detect-child-process", _span("log('pkill -f ' + name)"))
    decided = _run([_eslint(5), stray], constant=_constant(5))
    assert decided[None]["candidate"]["basis"] == "unmatched_location"
    assert decided[None]["disposition"] == "review"
    assert decided[None]["adjudication"]["kept_because"] == [adj.NO_EVIDENCE]


def test_a_pattern_alert_on_a_constant_shell_command_is_filtered_with_its_evidence():
    decided = _run([_eslint(4), _eslint(5)], constant=_constant(5))
    filtered = decided[5]
    assert filtered["disposition"] == "filtered"
    record = filtered["adjudication"]
    assert (record["rule"], record["version"]) == (adj.JS_CONSTANT_COMMAND, "adjudicate-v0.3")
    (evidence,) = record["evidence"]
    assert evidence["kind"] == "command_is_a_compile_time_constant"
    assert evidence["call"] == {"path": PATH, **_span(CALLS[5])}
    assert evidence["evidence_rule"] == "st-js-constant-command"
    # The neighbouring call has no evidence: it stays, and nothing was deleted.
    assert decided[4]["disposition"] == "review"
    assert decided[4]["adjudication"]["kept_because"] == [adj.NO_EVIDENCE]
    assert filtered["candidate"]["tools"] == ["eslint"]


@pytest.mark.parametrize(
    ("line", "extra", "options", "kept_because"),
    [
        # Another tool claims a data flow to the command: the conflict is kept.
        (5, ("codeql", "js/command-line-injection"), {}, [adj.INDEPENDENT_FLOW_CLAIM]),
        # A Semgrep rule of the flow family counts as a flow claim as well.
        (5, ("semgrep", "detect-child-process"), {"flow": True}, [adj.INDEPENDENT_FLOW_CLAIM]),
        # The evidence step did not complete.
        (5, None, {"status": "partial"}, [adj.EVIDENCE_STEP_FAILED]),
        # A scanner of the run was partial or failed.
        (5, None, {"complete": False}, [adj.RUN_INCOMPLETE]),
        # spawn takes arguments: a constant program proves nothing about them.
        (9, None, {}, [adj.NO_EVIDENCE]),
    ],
)
def test_constant_command_evidence_never_filters_without_every_condition(
    line: int, extra: tuple[str, str] | None, options: dict[str, Any], kept_because: list[str]
):
    findings = [_eslint(line)]
    families = {}
    if extra is not None:
        tool, rule = extra
        findings.append(_finding(f"{tool}:{line}", rule, _span(CALLS[line])))
        if options.get("flow"):
            families[f"{tool}:{line}"] = "flow"
    decided = _run(
        findings,
        constant=_constant(line, status=options.get("status", "completed")),
        complete=options.get("complete", True),
        families=families,
    )
    assert decided[line]["disposition"] == "review"
    assert decided[line]["adjudication"]["kept_because"] == kept_because


def test_evidence_about_another_call_on_the_same_line_does_not_filter():
    # The rule reported the outer wrap(...) call, not the exec call inside it.
    outer = _finding(
        "semgrep-evidence:outer", "rules.st-js-constant-command", _span("wrap(exec(inner))")
    )
    evidence = {
        **_constant(),
        "locations": adj.constant_evidence_index([outer], rule="st-js-constant-command"),
    }
    decided = _run([_eslint(10)], constant=evidence)
    assert decided[10]["disposition"] == "review"


def test_without_the_evidence_step_nothing_changes_for_javascript():
    # Profiles before v0.3 pass no constant evidence.
    decided = _run([_eslint(5)])
    assert decided[5]["disposition"] == "review"
    assert decided[5]["adjudication"]["kept_because"] == [adj.NO_EVIDENCE]
