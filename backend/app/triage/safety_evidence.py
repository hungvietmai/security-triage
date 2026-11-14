"""Rank a baseline query's alerts by whether safety evidence removes them.

A safety-evidence profile runs a baseline CodeQL query and the same query with proven safety
barriers and sink exclusions (rules/codeql/path-traversal-v0.2). Each baseline alert location
becomes one unit. If the evidence query still reports the location, the unit stays at P1: no
proof of safety. If it no longer does, the evidence removed every reported flow and the unit
drops to P4. No unit is deleted. Evidence can only remove flows, so an evidence alert outside
the baseline means the queries do not match and the scan fails.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.triage.reconcile import (
    MappingStatus,
    ReconciledUnit,
    UnitMapping,
    _canonical_id,
    _region,
)
from app.triage.types import Span

EVIDENCE_UNIT_VERSION = "safety-evidence-units-v1"
EVIDENCE_LOCATOR_VERSION = "codeql-reported-location"
SINK_KIND = "codeql-path-injection-sink"
KEPT = "EV_KEPT_NO_PROOF"
HIDDEN = "EV_HIDDEN_BY_EVIDENCE"
_REASONS = {
    KEPT: "Truy vấn có bằng chứng an toàn vẫn báo vị trí này: chưa chứng minh được an toàn, "
    "cần rà soát.",
    HIDDEN: "Bằng chứng an toàn chặn mọi luồng được báo tới vị trí này (barrier hoặc loại trừ "
    "sink đã được chứng minh). Cảnh báo được giữ ở mức ưu tiên thấp nhất, không bị xóa.",
}

Location = tuple[str | None, tuple[int, int, int, int] | None]
# A normalized scanner finding (app.scanners.sarif.Finding); triage stays scanner-agnostic.
Finding = Mapping[str, Any]


def _location(finding: Finding) -> tuple[Location, Span | None]:
    span = _region(finding["reported_region"])
    corners = (
        (span["startLine"], span["startColumn"], span["endLine"], span["endColumn"])
        if span
        else None
    )
    return (finding["reported_path"], corners), span


def assess_with_evidence(
    findings: Sequence[Finding],
    *,
    snapshot_sha256: str,
    baseline_rule: str,
    evidence_rule: str,
    provenance: Mapping[str, str],
) -> tuple[list[ReconciledUnit], list[dict[str, Any]]]:
    """One unit per baseline alert location, assessed P1 (kept) or P4 (hidden by evidence)."""
    baseline: dict[Location, list[Finding]] = {}
    evidence: dict[Location, list[Finding]] = {}
    spans: dict[Location, Span | None] = {}
    for finding in findings:
        location, span = _location(finding)
        if finding["rule_id"] == baseline_rule:
            baseline.setdefault(location, []).append(finding)
            spans[location] = span
        elif finding["rule_id"] == evidence_rule:
            evidence.setdefault(location, []).append(finding)
        else:
            raise ValueError(f"Unexpected rule in a safety-evidence scan: {finding['rule_id']!r}")
    outside = set(evidence) - set(baseline)
    if outside:
        raise ValueError(f"Evidence query reported {len(outside)} location(s) outside the baseline")

    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    for location in sorted(baseline, key=lambda key: (key[0] or "", key[1] or ())):
        path, corners = location
        span = spans[location]
        status: MappingStatus = "mapped" if span else "unmapped"
        reported = [*baseline[location], *evidence.get(location, [])]
        unit_id = _canonical_id(
            {
                "snapshot_sha256": snapshot_sha256,
                "path": path,
                "span": list(corners) if corners else None,
                "baseline_rule": baseline_rule,
            }
        )
        mappings: list[UnitMapping] = [
            {
                "raw_id": finding["raw_id"],
                "tool": finding["tool"],
                "mapping_status": status,
                "mapping_method": "exact_span" if span else None,
            }
            for finding in reported
        ]
        units.append(
            {
                "unit_id": unit_id,
                "snapshot_sha256": snapshot_sha256,
                "path": path,
                "sink_span": span,
                "reported_region": dict(baseline[location][0]["reported_region"].items()),
                "argument_role": None,
                "sink_kind": SINK_KIND,
                "callee": None,
                "mapping_status": status,
                "raw_finding_ids": [finding["raw_id"] for finding in reported],
                "tools": ["codeql"],
                "mappings": mappings,
            }
        )
        kept = location in evidence
        decision = KEPT if kept else HIDDEN
        assessments.append(
            {
                "unit_id": unit_id,
                "priority": "P1" if kept else "P4",
                "decision_id": decision,
                "matched_conditions": [
                    "baseline_alert",
                    "retained_by_evidence_query" if kept else "removed_by_safety_evidence",
                ],
                "reason": _REASONS[decision],
                "tools": ["codeql"],
                "predicate_values": {"baseline_alert": True, "retained_by_evidence_query": kept},
                "unknown_fields": [],
                "baseline_rule": baseline_rule,
                "evidence_rule": evidence_rule,
                "finding_evidence": [
                    {
                        "raw_id": finding["raw_id"],
                        "rule_id": finding["rule_id"],
                        "query": "baseline" if finding["rule_id"] == baseline_rule else "evidence",
                        "message": finding["message"],
                    }
                    for finding in reported
                ],
                **provenance,
            }
        )
    return units, assessments
