"""Group units into review candidates and filter the ones a tool proves false; no I/O.

Detection is broad: every alert of every tool becomes part of a unit, and units that point at
the same call form one candidate, so a reviewer sees one item per call however many tools and
argument roles reported it. Filtering is narrow: a candidate leaves the main review list only
when a rule below finds specific evidence that its alerts are false. Missing evidence, a
conflicting flow claim or an incomplete run always keeps the candidate. A filtered candidate is
never deleted: its units, original alerts, the rules and the evidence stay available.

Rules, in the order they are recorded:

  G3  Semgrep CE proves that request data reaches the command only through an assignment in a
      branch that never runs, and every flow another tool reported passes through that branch.
  G1  CodeQL's safety-evidence query no longer reports the flow its default query reported.
  G2  The whole command is a string literal, by this project's proof and by Bandit's rating.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from app.triage.reconcile import _canonical_id, _region, contains, normalized_path
from app.triage.types import Span

ADJUDICATION_VERSION = "adjudicate-v0.2"
Disposition = Literal["review", "filtered"]
REVIEW: Disposition = "review"
FILTERED: Disposition = "filtered"

# Filter rules. Each names the tool whose output is the evidence.
SEMGREP_DEAD_BRANCH = "G3_SEMGREP_DEAD_BRANCH"
CODEQL_SAFETY_EVIDENCE = "G1_CODEQL_SAFETY_EVIDENCE"
LITERAL_COMMAND = "G2_LITERAL_COMMAND"
# Reasons a candidate stays in the main list, recorded so a reviewer sees what was missing.
RUN_INCOMPLETE = "run_incomplete"
NO_EVIDENCE = "no_refuting_evidence"
EVIDENCE_STEP_FAILED = "evidence_step_failed"
FLOW_STILL_REPORTED = "evidence_query_still_reports_flow"
FLOW_WITHOUT_EVIDENCE_QUERY = "flow_rule_without_evidence_query"
EVIDENCE_QUERY_MISMATCH = "evidence_baseline_does_not_report_this_alert"
INDEPENDENT_FLOW_CLAIM = "independent_flow_claim"
LITERAL_WITHOUT_SECOND_SOURCE = "literal_proof_without_second_source"
FLOW_NOT_THROUGH_DEAD_CODE = "reported_flow_avoids_the_dead_branch"
FLOW_WITHOUT_TRACE = "flow_claim_without_a_trace_to_check"

# Bandit tests that rate a call LOW exactly when its command argument is a string literal
# (bandit/plugins/injection_shell.py, _evaluate_shell_call).
_BANDIT_LITERAL_TESTS = frozenset({"B602", "B605"})
_TIER_ORDER = {"P1": 0, "P2": 1, "U": 2, "P3": 3, "P4": 4}

_REASONS = {
    SEMGREP_DEAD_BRANCH: "Đã gạn khỏi danh sách rà chính: Semgrep chứng minh phép gán đưa dữ liệu "
    "đầu vào tới lệnh này nằm trong nhánh không bao giờ chạy (điều kiện là phép so sánh số nguyên "
    "hằng). Luật đối chứng của Semgrep có báo luồng tới lệnh, luật có bằng chứng không còn báo, "
    "và mọi đường đi mà công cụ khác báo đều đi qua nhánh đó. Cảnh báo gốc được giữ để xem lại.",
    CODEQL_SAFETY_EVIDENCE: "Đã gạn khỏi danh sách rà chính: truy vấn gốc của CodeQL có báo luồng "
    "tới lời gọi này, nhưng truy vấn có bằng chứng an toàn ({evidence_rule}) không còn báo luồng "
    "nào. Không công cụ nào khác khẳng định luồng dữ liệu ở đây; các cảnh báo còn lại chỉ bắt "
    "mẫu cú pháp. Cảnh báo gốc được giữ để xem lại.",
    LITERAL_COMMAND: "Đã gạn khỏi danh sách rà chính: toàn bộ lệnh là chuỗi hằng theo hai nguồn "
    "độc lập (chứng minh whole_command_literal_v1 của hệ thống và Bandit xếp lời gọi ở mức LOW "
    "dành cho đối số lệnh là hằng). Không công cụ nào khẳng định luồng dữ liệu tới lệnh. Cảnh "
    "báo gốc được giữ để xem lại.",
}
_KEPT = {
    RUN_INCOMPLETE: "Lượt quét chưa hoàn tất nên không gạn cảnh báo nào.",
    NO_EVIDENCE: "Không có bằng chứng cụ thể cho thấy đây là cảnh báo sai.",
    EVIDENCE_STEP_FAILED: "Bước chạy truy vấn bằng chứng không hoàn tất nên không đối chiếu được.",
    FLOW_STILL_REPORTED: "Truy vấn có bằng chứng an toàn vẫn báo luồng tới lời gọi này.",
    FLOW_WITHOUT_EVIDENCE_QUERY: "Có luồng do một truy vấn CodeQL chưa có truy vấn bằng chứng "
    "tương ứng báo.",
    EVIDENCE_QUERY_MISMATCH: "Truy vấn đối chứng của gói bằng chứng không báo cảnh báo CodeQL "
    "này, nên không thể đối chiếu.",
    INDEPENDENT_FLOW_CLAIM: "Một công cụ khác vẫn khẳng định luồng dữ liệu tới lời gọi này.",
    LITERAL_WITHOUT_SECOND_SOURCE: "Hệ thống chứng minh được lệnh là hằng nhưng chưa có nguồn "
    "thứ hai xác nhận, nên chỉ hạ ưu tiên.",
    FLOW_NOT_THROUGH_DEAD_CODE: "Semgrep thấy luồng tới lệnh chỉ qua nhánh không bao giờ chạy, "
    "nhưng một đường đi do công cụ khác báo không đi qua nhánh đó.",
    FLOW_WITHOUT_TRACE: "Semgrep thấy luồng tới lệnh chỉ qua nhánh không bao giờ chạy, nhưng một "
    "công cụ khác khẳng định luồng mà không kèm đường đi để đối chiếu.",
}

Location = tuple[str | None, tuple[int, int, int, int]]
DeadLines = tuple[str | None, int, int]
Finding = Mapping[str, Any]
# (evidence records when the rule filters, otherwise None; reasons it did not filter)
Verdict = tuple[list[dict[str, Any]] | None, list[str]]


def _location(finding: Finding) -> Location | None:
    span = _region(finding.get("reported_region"))
    if span is None:
        return None
    corners = (span["startLine"], span["startColumn"], span["endLine"], span["endColumn"])
    return normalized_path(finding.get("reported_path")), corners


def candidate_identity(unit: Mapping[str, Any]) -> tuple[str, str]:
    """(key, basis): units mapped to one call share a key; anything unmapped stays alone."""
    span, path = unit.get("sink_span"), unit.get("path")
    if span is not None and path is not None:
        identity = {"snapshot_sha256": unit["snapshot_sha256"], "path": path, "sink_span": span}
        return _canonical_id(identity), "same_call_site"
    return unit["unit_id"], "unmatched_location"


def codeql_evidence_index(
    findings: Sequence[Finding],
    *,
    baseline_rule: str,
    evidence_rule: str,
) -> dict[str, set[Location]]:
    """Alert locations of the evidence pack's control query and of its evidence query."""
    index: dict[str, set[Location]] = {"baseline": set(), "evidence": set()}
    for finding in findings:
        location = _location(finding)
        if location is None:
            continue
        if finding.get("rule_id") == baseline_rule:
            index["baseline"].add(location)
        elif finding.get("rule_id") == evidence_rule:
            index["evidence"].add(location)
    return index


def semgrep_evidence_index(
    findings: Sequence[Finding],
    *,
    baseline_rule: str,
    evidence_rule: str,
    dead_code_rule: str,
) -> dict[str, Any]:
    """Command locations the control and evidence rules report, and the lines of dead assignments.

    Semgrep prefixes a rule ID with the path of its staged file, so rules match by suffix.
    """
    index: dict[str, Any] = {"baseline": set(), "evidence": set(), "dead": set()}
    for finding in findings:
        location = _location(finding)
        rule = str(finding.get("rule_id") or "").rsplit(".", 1)[-1]
        if location is None:
            continue
        if rule == baseline_rule:
            index["baseline"].add(location)
        elif rule == evidence_rule:
            index["evidence"].add(location)
        elif rule == dead_code_rule:
            path, (start_line, _, end_line, _) = location
            index["dead"].add((path, start_line, end_line))
    return index


def _bandit_literal(finding: Finding) -> bool | None:
    """True/False for a Bandit shell test's literal classification; None for any other alert."""
    if finding.get("tool") != "bandit" or finding.get("rule_id") not in _BANDIT_LITERAL_TESTS:
        return None
    properties = finding.get("raw_result", {}).get("properties", {})
    return bool(isinstance(properties, dict) and properties.get("issue_severity") == "LOW")


def _codeql_rule(
    codeql: Sequence[Finding], other_flow: Sequence[str], evidence: Mapping[str, Any] | None
) -> Verdict:
    """G1: every CodeQL flow at the call is one the evidence query no longer reports."""
    if not codeql or evidence is None:
        return None, []
    if evidence["status"] != "completed":
        return None, [EVIDENCE_STEP_FAILED]
    baseline_rules = set(evidence["baseline_rules"])
    locations = evidence["locations"]
    if any(finding.get("rule_id") not in baseline_rules for finding in codeql):
        return None, [FLOW_WITHOUT_EVIDENCE_QUERY]
    if any(_location(finding) not in locations["baseline"] for finding in codeql):
        return None, [EVIDENCE_QUERY_MISMATCH]
    if any(_location(finding) in locations["evidence"] for finding in codeql):
        return None, [FLOW_STILL_REPORTED]
    if other_flow:
        return None, [INDEPENDENT_FLOW_CLAIM]
    record = {
        "rule": CODEQL_SAFETY_EVIDENCE,
        "tool": evidence["tool"],
        "tool_version": evidence["tool_version"],
        "kind": "safety_evidence_query_removed_every_flow",
        "baseline_rules": sorted(baseline_rules),
        "evidence_rule": evidence["evidence_rule"],
        "refuted_raw_ids": sorted(finding["raw_id"] for finding in codeql),
        "query_sha256": dict(evidence["query_sha256"]),
    }
    return [record], []


def _trace_lines(finding: Finding) -> list[set[tuple[str | None, int]]]:
    """(path, line) of every step, one set per reported path of a flow alert."""
    traces = []
    flows = finding.get("raw_result", {}).get("codeFlows")
    for flow in flows if isinstance(flows, list) else []:
        threads = flow.get("threadFlows") if isinstance(flow, dict) else None
        for thread in threads if isinstance(threads, list) else []:
            steps = set()
            locations = thread.get("locations") if isinstance(thread, dict) else None
            for step in locations if isinstance(locations, list) else []:
                physical = step.get("location", {}).get("physicalLocation", {})
                span = _region(physical.get("region"))
                if span is not None:
                    path = normalized_path(physical.get("artifactLocation", {}).get("uri"))
                    steps.add((path, span["startLine"]))
            traces.append(steps)
    return traces


def _semgrep_rule(
    calls: Sequence[tuple[str, Span]],
    flow_claims: Sequence[Finding],
    evidence: Mapping[str, Any] | None,
    codeql_reasons: Sequence[str],
) -> Verdict:
    """G3: request data reaches the command only through a branch that never runs."""
    if evidence is None or not calls:
        return None, []
    if evidence["status"] != "completed":
        return None, [EVIDENCE_STEP_FAILED]
    locations = evidence["locations"]

    def at_call(found: set[Location]) -> bool:
        return any(
            path == call_path
            and contains(
                span,
                {"startLine": a, "startColumn": b, "endLine": c, "endColumn": d},
            )
            for path, (a, b, c, d) in found
            for call_path, span in calls
        )

    if not at_call(locations["baseline"]) or at_call(locations["evidence"]):
        return None, []
    # A CodeQL evidence query that models constant branches and still reports the flow
    # contradicts the claim; a failed evidence step leaves it unchecked.
    blocked = [r for r in codeql_reasons if r in {FLOW_STILL_REPORTED, EVIDENCE_STEP_FAILED}]
    if blocked:
        return None, blocked
    dead: set[DeadLines] = locations["dead"]
    crossed = []
    for claim in flow_claims:
        traces = _trace_lines(claim)
        if not traces:
            return None, [FLOW_WITHOUT_TRACE]
        for steps in traces:
            if not any(
                path == dead_path and first <= line <= last
                for path, line in steps
                for dead_path, first, last in dead
            ):
                return None, [FLOW_NOT_THROUGH_DEAD_CODE]
        crossed.append(claim["raw_id"])
    record = {
        "rule": SEMGREP_DEAD_BRANCH,
        "tool": evidence["tool"],
        "tool_version": evidence["tool_version"],
        "kind": "request_flow_only_through_a_branch_that_never_runs",
        "baseline_rule": evidence["baseline_rule"],
        "evidence_rule": evidence["evidence_rule"],
        "dead_code_rule": evidence["dead_code_rule"],
        "dead_lines": sorted(
            [path, first, last] for path, first, last in dead if any(path == p for p, _ in calls)
        ),
        "flows_through_dead_code": sorted(crossed),
        "rules_sha256": evidence["rules_sha256"],
    }
    return [record], []


def _literal_rule(
    members: Sequence[Mapping[str, Any]],
    findings: Sequence[Finding],
    flow_claims: Sequence[Finding],
) -> Verdict:
    """G2: the command is a string literal by this project's proof and by Bandit's rating."""
    proofs = [member["blocker_proof"] for member in members if member.get("blocker_proof")]
    if not proofs or flow_claims:
        return None, []
    rated = [finding for finding in findings if _bandit_literal(finding) is not None]
    if not rated or not all(_bandit_literal(finding) for finding in rated):
        return None, [LITERAL_WITHOUT_SECOND_SOURCE]
    return [
        {"rule": LITERAL_COMMAND, "tool": "security-triage", **proofs[0]},
        {
            "rule": LITERAL_COMMAND,
            "tool": "bandit",
            "kind": "literal_command_rating",
            "raw_ids": sorted(finding["raw_id"] for finding in rated),
            "issue_severity": "LOW",
        },
    ], []


def _decide(
    units: Sequence[Mapping[str, Any]],
    members: Sequence[Mapping[str, Any]],
    findings: Sequence[Finding],
    *,
    complete: bool,
    codeql_evidence: Mapping[str, Any] | None,
    semgrep_evidence: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """One candidate's decision. Every rule is checked; any satisfied rule filters."""
    if not complete:
        return {
            "status": "kept",
            "rule": None,
            "rules": [],
            "kept_because": [RUN_INCOMPLETE],
            "evidence": [],
        }
    claims = {
        record["raw_id"]: record for member in members for record in member["finding_evidence"]
    }
    codeql = [finding for finding in findings if finding["tool"] == "codeql"]
    flow_claims = [
        finding
        for finding in findings
        if finding["tool"] == "codeql"
        or claims.get(finding["raw_id"], {}).get("claim_family") == "flow"
    ]
    other_flow = [finding["raw_id"] for finding in flow_claims if finding["tool"] != "codeql"]
    calls = [(unit["path"], unit["sink_span"]) for unit in units if unit.get("sink_span")]

    codeql_verdict = _codeql_rule(codeql, other_flow, codeql_evidence)
    verdicts = [
        _semgrep_rule(calls, flow_claims, semgrep_evidence, codeql_verdict[1]),
        codeql_verdict,
        _literal_rule(members, findings, flow_claims),
    ]
    evidence = [record for records, _ in verdicts if records for record in records]
    rules = list(dict.fromkeys(record["rule"] for record in evidence))
    if rules:
        return {
            "status": "filtered",
            "rule": rules[0],
            "rules": rules,
            "kept_because": [],
            "evidence": evidence,
        }
    kept = list(dict.fromkeys(code for _, codes in verdicts for code in codes))
    return {
        "status": "kept",
        "rule": None,
        "rules": [],
        "kept_because": kept or [NO_EVIDENCE],
        "evidence": [],
    }


def adjudicate(
    units: Sequence[Mapping[str, Any]],
    assessments: Sequence[Mapping[str, Any]],
    findings: Sequence[Finding],
    *,
    complete: bool,
    codeql_evidence: Mapping[str, Any] | None = None,
    semgrep_evidence: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return the assessments with their candidate, disposition and adjudication record.

    `codeql_evidence` describes a run of CodeQL's safety-evidence queries: {tool, tool_version,
    status, baseline_rules, evidence_rule, query_sha256, locations}, with locations from
    `codeql_evidence_index`. `semgrep_evidence` describes a run of Semgrep's dead-branch rules:
    {tool, tool_version, status, baseline_rule, evidence_rule, dead_code_rule, rules_sha256,
    locations}, with locations from `semgrep_evidence_index`. `complete` is False when any
    scanner of the run was partial or failed; nothing is filtered then.
    """
    by_unit = {assessment["unit_id"]: assessment for assessment in assessments}
    by_raw_id = {finding["raw_id"]: finding for finding in findings}
    groups: dict[str, list[Mapping[str, Any]]] = {}
    basis: dict[str, str] = {}
    for unit in units:
        key, how = candidate_identity(unit)
        groups.setdefault(key, []).append(unit)
        basis[key] = how

    result: dict[str, dict[str, Any]] = {}
    for key, members in groups.items():
        member_assessments = [by_unit[unit["unit_id"]] for unit in members]
        member_findings = [
            by_raw_id[raw_id] for unit in members for raw_id in unit["raw_finding_ids"]
        ]
        decision = _decide(
            members,
            member_assessments,
            member_findings,
            complete=complete,
            codeql_evidence=codeql_evidence,
            semgrep_evidence=semgrep_evidence,
        )
        if decision["rules"]:
            reason = " ".join(
                _REASONS[rule].format(
                    evidence_rule=(codeql_evidence or {}).get("evidence_rule", "")
                )
                for rule in decision["rules"][:1]
            )
            if len(decision["rules"]) > 1:
                reason += " Quy tắc khác cũng thỏa: " + ", ".join(decision["rules"][1:]) + "."
        else:
            reason = " ".join(_KEPT[code] for code in decision["kept_because"])
        candidate = {
            "key": key,
            "basis": basis[key],
            "unit_ids": sorted(unit["unit_id"] for unit in members),
            "tools": sorted({finding["tool"] for finding in member_findings}),
            "priority": min(
                (assessment["priority"] for assessment in member_assessments),
                key=_TIER_ORDER.__getitem__,
            ),
        }
        for assessment in member_assessments:
            result[assessment["unit_id"]] = {
                **assessment,
                "candidate": candidate,
                "disposition": FILTERED if decision["rules"] else REVIEW,
                "adjudication": {**decision, "version": ADJUDICATION_VERSION, "reason": reason},
            }
    return [result[assessment["unit_id"]] for assessment in assessments]
