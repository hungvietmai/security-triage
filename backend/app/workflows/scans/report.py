"""Before/after report of one scan and its merged SARIF export. Functions take a Session.

"Before" is everything the detection tools reported. "After" is the main review list: the
candidates left once alerts of one call are merged and the candidates that meet a filter
condition of their family are filtered. Filtered candidates stay in the report with the rule
that removed them; the count is not a count of verified false positives.

A scan with several analysis families reports the same counts per family as well; a candidate
belongs to exactly one family.

Two kinds of stored result are counted apart from the alerts, so "before" is not overstated
and nothing is silently dropped:

  evidence results  what a safety-evidence query reported. Such a member links them to the unit
                    next to the detection alert they confirm; they are not alerts of their own.
  unranked alerts   results in no unit, because a single-profile run was incomplete and its
                    member ranked nothing. They are not in the review list; the report counts
                    them and the SARIF export carries them.
"""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.features.findings.models import Finding
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.workflows.scans import service
from app.workflows.scans.families import (
    FAMILIES,
    NOT_RANKED_DECISION,
    UNASSIGNED,
    UNRESOLVED_DECISION,
)
from app.workflows.scans.schemas import TIERS

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TIER_ORDER: dict[str, int] = {tier: index for index, tier in enumerate(TIERS)}
# Candidates the policy ranks below the tiers a reviewer reads first; still in the main list.
_DEMOTED = {"P3", "P4"}
_EVIDENCE_STATES = (
    "refuted",
    "not_refuted",
    "insufficient",
    "unavailable",
    "not_applicable",
    "not_assessed",
)


# The role a safety-evidence member records for each result of its unit ("baseline" or this).
_EVIDENCE_QUERY = "evidence"
_HELD_DECISIONS = (UNRESOLVED_DECISION, NOT_RANKED_DECISION)


def _evidence_results(assessment: UnitAssessment) -> set[str]:
    """Raw IDs of the unit's results that came from an evidence query, as its member recorded."""
    return {
        record["raw_id"]
        for record in assessment.evidence.get("finding_evidence", [])
        if isinstance(record, dict) and record.get("query") == _EVIDENCE_QUERY
    }


def _rows(session: Session, scan: Scan) -> list[tuple[LocationUnit, UnitAssessment]]:
    return [
        (unit, assessment)
        for unit, assessment in session.execute(
            select(LocationUnit, UnitAssessment)
            .join(UnitAssessment, UnitAssessment.unit_id == LocationUnit.id)
            .where(*service.result_filters(scan))
            .order_by(LocationUnit.path, LocationUnit.start_line, LocationUnit.unit_key)
        )
    ]


def _candidates(
    scan: Scan, rows: list[tuple[LocationUnit, UnitAssessment]], alerts: dict[Any, int]
) -> list[dict[str, Any]]:
    """One record per candidate; units written before candidates existed stand alone."""
    single = service.scan_family(scan)
    grouped: dict[str, list[tuple[LocationUnit, UnitAssessment]]] = {}
    for unit, assessment in rows:
        grouped.setdefault(unit.candidate_key or unit.unit_key, []).append((unit, assessment))
    candidates = []
    for key, members in grouped.items():
        first_unit, first = members[0]
        adjudication = first.evidence.get("adjudication")
        family = first_unit.analysis_family or single
        # Units of one candidate are decided together; "filtered" needs every one.
        disposition = (
            "filtered" if all(a.disposition == "filtered" for _, a in members) else "review"
        )
        candidates.append(
            {
                "candidate_key": key,
                "basis": (first.evidence.get("candidate") or {}).get("basis", "single_unit"),
                "path": first_unit.path,
                "start_line": first_unit.start_line,
                "sink_kind": first_unit.sink_kind,
                "tools": sorted({tool for _, a in members for tool in a.evidence.get("tools", [])}),
                "priority": min((a.priority for _, a in members), key=_TIER_ORDER.__getitem__),
                "disposition": disposition,
                "filter_rule": (adjudication or {}).get("rule"),
                # Every rule whose evidence was complete, not only the first.
                "filter_rules": (adjudication or {}).get("rules")
                or [rule for rule in [(adjudication or {}).get("rule")] if rule],
                "reason": (adjudication or {}).get("reason") or first.reason,
                "unit_ids": [unit.id for unit, _ in members],
                "raw_alerts": sum(alerts.get(unit.id, 0) for unit, _ in members),
                "analysis_family": family,
                "cwe": service.family_cwe(family),
                "evidence_state": service.evidence_state(
                    disposition, first.decision_id, adjudication
                ),
            }
        )
    candidates.sort(
        key=lambda c: (
            c["disposition"] == "filtered",
            _TIER_ORDER[c["priority"]],
            c["path"] or "",
            c["start_line"] or 0,
            c["candidate_key"],
        )
    )
    return candidates


def _by_rule(filtered: list[dict[str, Any]]) -> dict[str, int]:
    """A candidate is counted under every rule that filtered it, so the sum can exceed them."""
    by_rule: dict[str, int] = {}
    for candidate in filtered:
        for rule in candidate["filter_rules"] or ["unspecified"]:
            by_rule[rule] = by_rule.get(rule, 0) + 1
    return by_rule


def _family_reports(
    candidates: list[dict[str, Any]], rows: list[tuple[LocationUnit, UnitAssessment]], scan: Scan
) -> list[dict[str, Any]]:
    single = service.scan_family(scan)
    units: dict[str, int] = {}
    evidence: dict[str, int] = {}
    for unit, assessment in rows:
        family = unit.analysis_family or single
        if family is not None:
            units[family] = units.get(family, 0) + 1
            evidence[family] = evidence.get(family, 0) + len(_evidence_results(assessment))
    reports = []
    for name in (*FAMILIES, UNASSIGNED):
        mine = [c for c in candidates if c["analysis_family"] == name]
        if not mine:
            continue
        main = [c for c in mine if c["disposition"] == "review"]
        filtered = [c for c in mine if c["disposition"] == "filtered"]
        reports.append(
            {
                "family": name,
                "cwe": service.family_cwe(name),
                "label": FAMILIES[name].label if name in FAMILIES else "Chưa xác định nhóm",
                "raw_alerts": sum(c["raw_alerts"] for c in mine),
                "evidence_results": evidence.get(name, 0),
                "detection_alerts": sum(c["raw_alerts"] for c in mine) - evidence.get(name, 0),
                "units": units.get(name, 0),
                "candidates": len(mine),
                "main_list": len(main),
                "filtered": len(filtered),
                "main_list_by_priority": {
                    tier: sum(c["priority"] == tier for c in main) for tier in TIERS
                },
                "filtered_by_rule": _by_rule(filtered),
                "evidence_states": {
                    state: count
                    for state in _EVIDENCE_STATES
                    if (count := sum(c["evidence_state"] == state for c in mine))
                },
            }
        )
    return reports


def build_report(session: Session, scan: Scan) -> dict[str, Any]:
    rows = _rows(session, scan)
    alerts = {
        unit_id: count
        for unit_id, count in session.execute(
            select(UnitFinding.unit_id, func.count())
            .where(UnitFinding.unit_id.in_([unit.id for unit, _ in rows]))
            .group_by(UnitFinding.unit_id)
        )
    }
    runs = session.scalars(
        select(ToolRun).where(ToolRun.scan_id == scan.id).order_by(ToolRun.language, ToolRun.tool)
    ).all()
    raw_alerts = {
        tool: count
        for tool, count in session.execute(
            select(ToolRun.tool, func.count(Finding.id))
            .join(Finding, Finding.tool_run_id == ToolRun.id)
            .where(ToolRun.scan_id == scan.id)
            .group_by(ToolRun.tool)
        )
    }
    candidates = _candidates(scan, rows, alerts)
    evidence_results = sum(len(_evidence_results(assessment)) for _, assessment in rows)
    main = [c for c in candidates if c["disposition"] == "review"]
    filtered = [c for c in candidates if c["disposition"] == "filtered"]
    tools = sorted({tool for c in candidates for tool in c["tools"]})
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "profile": scan.config.get("profile_id") or scan.config.get("profile"),
        "profile_sha256": scan.config.get("profile_sha256"),
        "policy_version": scan.policy_version,
        "reconciler_version": scan.reconciler_version,
        "snapshot": session.get_one(SourceSnapshot, scan.snapshot_id),
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "tool_versions": {
            f"{run.language}/{run.tool}": run.tool_version for run in runs if run.tool_version
        },
        "steps": scan.config.get("steps", {}),
        "raw_alerts": raw_alerts,
        "stages": {
            "raw_alerts": sum(raw_alerts.values()),
            "evidence_results": evidence_results,
            "detection_alerts": sum(raw_alerts.values()) - evidence_results,
            "unranked_alerts": sum(raw_alerts.values()) - sum(alerts.values()),
            "units": len(rows),
            "candidates": len(candidates),
            "main_list": len(main),
            "filtered": len(filtered),
            "demoted": sum(c["priority"] in _DEMOTED for c in main),
        },
        "sources": {
            tool: {
                "candidates": sum(tool in c["tools"] for c in candidates),
                # Candidates no other tool reported: what this source alone contributes.
                "only": sum(c["tools"] == [tool] for c in candidates),
            }
            for tool in tools
        },
        "main_list_by_priority": {tier: sum(c["priority"] == tier for c in main) for tier in TIERS},
        "filtered_by_rule": _by_rule(filtered),
        "families": _family_reports(candidates, rows, scan),
        "composition": scan.config.get("composition"),
        "candidates": candidates,
    }


def build_sarif(session: Session, scan: Scan) -> dict[str, Any]:
    """Every stored result, one run per tool pass, annotated with its candidate and disposition.

    A filtered candidate's alerts carry a SARIF suppression with the filter reason, so a SARIF
    viewer hides them by default without losing them. An alert also carries its analysis
    family and, when the scan classified it, the CWEs of its pinned rule next to the CWEs the
    tool itself reported.

    A result in no unit is exported too, marked `ranked: false`: an incomplete single-profile
    run ranked nothing, and its alerts must still reach the reader. `resultRole` tells a
    detection alert from the result of a safety-evidence query stored with the same unit; it
    is "unknown" where no member recorded the role (unranked results and units the
    composition holds).
    """
    rows = _rows(session, scan)
    by_unit = {unit.id: (unit, assessment) for unit, assessment in rows}
    evidence_results = {
        (unit.id, raw_id) for unit, assessment in rows for raw_id in _evidence_results(assessment)
    }
    single = service.scan_family(scan)
    found = session.execute(
        select(Finding, ToolRun, UnitFinding.unit_id)
        .join(ToolRun, ToolRun.id == Finding.tool_run_id)
        .outerjoin(UnitFinding, UnitFinding.finding_id == Finding.id)
        .where(ToolRun.scan_id == scan.id)
        .order_by(ToolRun.language, ToolRun.tool, Finding.result_index)
    ).all()
    runs: dict[tuple[str, str], dict[str, Any]] = {}
    for finding, run, unit_id in found:
        if unit_id is not None and unit_id not in by_unit:
            continue
        unit, assessment = by_unit[unit_id] if unit_id is not None else (None, None)
        raw = finding.evidence.get("raw_result", {})
        # The rule table of the original run is not exported, so its indexes would dangle.
        result = {key: value for key, value in raw.items() if key not in {"ruleIndex", "rule"}}
        result["ruleId"] = finding.rule_id
        result.setdefault("message", {"text": finding.message})
        if finding.file_path is not None and finding.start_line is not None:
            region = {
                key: value
                for key, value in {
                    "startLine": finding.start_line,
                    "startColumn": finding.start_column,
                    "endLine": finding.end_line,
                    "endColumn": finding.end_column,
                }.items()
                if value is not None
            }
            # Paths relative to the source root, also for tools that report absolute URIs.
            location = {"artifactLocation": {"uri": finding.file_path}, "region": region}
            result["locations"] = [{"physicalLocation": location}]
        triage: dict[str, Any]
        if unit is None or assessment is None:
            adjudication = None
            # Never ranked, so never filtered: the alert stays for review, with no evidence.
            triage = {
                "candidateKey": None,
                "unitKey": None,
                "priority": None,
                "decisionId": None,
                "disposition": "review",
                "filterRule": None,
                "analysisFamily": single,
                "cwe": service.family_cwe(single),
                "evidenceState": "unavailable",
                "reportedCwes": finding.cwe_ids,
                "ranked": False,
                "resultRole": "unknown",
            }
        else:
            adjudication = assessment.evidence.get("adjudication")
            family = unit.analysis_family or single
            if (unit.id, finding.evidence.get("raw_id")) in evidence_results:
                role = "evidence_query"
            else:
                role = "unknown" if assessment.decision_id in _HELD_DECISIONS else "detection"
            triage = {
                "candidateKey": unit.candidate_key or unit.unit_key,
                "unitKey": unit.unit_key,
                "priority": assessment.priority,
                "decisionId": assessment.decision_id,
                "disposition": assessment.disposition,
                "filterRule": (adjudication or {}).get("rule"),
                "analysisFamily": family,
                "cwe": service.family_cwe(family),
                "evidenceState": service.evidence_state(
                    assessment.disposition, assessment.decision_id, adjudication
                ),
                "reportedCwes": finding.cwe_ids,
                "ranked": True,
                "resultRole": role,
            }
        classification = finding.evidence.get("classification")
        if classification is not None:
            triage["mappedCwes"] = classification["mapped_cwes"]
            triage["familyStatus"] = classification["family_status"]
            triage["familyBasis"] = classification["family_basis"]
        result["properties"] = {
            **(raw.get("properties") if isinstance(raw.get("properties"), dict) else {}),
            "securityTriage": triage,
        }
        if assessment is not None and assessment.disposition == "filtered":
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": (adjudication or {}).get("reason") or assessment.reason,
                }
            ]
        entry = runs.setdefault(
            (run.language, run.tool),
            {
                "tool": {"driver": {"name": run.tool, "version": run.tool_version or "unknown"}},
                "properties": {"language": run.language, "scanId": str(scan.id)},
                "results": [],
            },
        )
        entry["results"].append(result)
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": list(runs.values())}
