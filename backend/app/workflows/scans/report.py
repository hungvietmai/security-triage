"""Before/after report of one scan and its merged SARIF export. Functions take a Session.

"Before" is everything the detection tools reported. "After" is the main review list: the
candidates left once alerts of one call are merged and the candidates a tool proved false are
filtered. Filtered candidates stay in the report with the rule that removed them.
"""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.features.findings.models import Finding
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.workflows.scans.schemas import TIERS

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TIER_ORDER: dict[str, int] = {tier: index for index, tier in enumerate(TIERS)}
# Candidates the policy ranks below the tiers a reviewer reads first; still in the main list.
_DEMOTED = {"P3", "P4"}


def _rows(session: Session, scan: Scan) -> list[tuple[LocationUnit, UnitAssessment]]:
    return [
        (unit, assessment)
        for unit, assessment in session.execute(
            select(LocationUnit, UnitAssessment)
            .join(UnitAssessment, UnitAssessment.unit_id == LocationUnit.id)
            .where(
                LocationUnit.scan_id == scan.id,
                LocationUnit.reconciler_version == scan.reconciler_version,
                UnitAssessment.policy_version == scan.policy_version,
            )
            .order_by(LocationUnit.path, LocationUnit.start_line, LocationUnit.unit_key)
        )
    ]


def _candidates(
    rows: list[tuple[LocationUnit, UnitAssessment]], alerts: dict[Any, int]
) -> list[dict[str, Any]]:
    """One record per candidate; units written before candidates existed stand alone."""
    grouped: dict[str, list[tuple[LocationUnit, UnitAssessment]]] = {}
    for unit, assessment in rows:
        grouped.setdefault(unit.candidate_key or unit.unit_key, []).append((unit, assessment))
    candidates = []
    for key, members in grouped.items():
        first_unit, first = members[0]
        adjudication = first.evidence.get("adjudication") or {}
        candidates.append(
            {
                "candidate_key": key,
                "basis": (first.evidence.get("candidate") or {}).get("basis", "single_unit"),
                "path": first_unit.path,
                "start_line": first_unit.start_line,
                "sink_kind": first_unit.sink_kind,
                "tools": sorted({tool for _, a in members for tool in a.evidence.get("tools", [])}),
                "priority": min((a.priority for _, a in members), key=_TIER_ORDER.__getitem__),
                # Units of one candidate are decided together; "filtered" needs every one.
                "disposition": "filtered"
                if all(a.disposition == "filtered" for _, a in members)
                else "review",
                "filter_rule": adjudication.get("rule"),
                # Every rule whose evidence was complete, not only the first.
                "filter_rules": adjudication.get("rules")
                or ([adjudication["rule"]] if adjudication.get("rule") else []),
                "reason": adjudication.get("reason") or first.reason,
                "unit_ids": [unit.id for unit, _ in members],
                "raw_alerts": sum(alerts.get(unit.id, 0) for unit, _ in members),
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
    candidates = _candidates(rows, alerts)
    main = [c for c in candidates if c["disposition"] == "review"]
    filtered = [c for c in candidates if c["disposition"] == "filtered"]
    tools = sorted({tool for c in candidates for tool in c["tools"]})
    # A candidate is counted under every rule that filtered it, so the sum can exceed
    # the number of filtered candidates.
    by_rule: dict[str, int] = {}
    for candidate in filtered:
        for rule in candidate["filter_rules"] or ["unspecified"]:
            by_rule[rule] = by_rule.get(rule, 0) + 1
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
        "filtered_by_rule": by_rule,
        "candidates": candidates,
    }


def build_sarif(session: Session, scan: Scan) -> dict[str, Any]:
    """Every original alert, one run per tool, annotated with its candidate and disposition.

    A filtered candidate's alerts carry a SARIF suppression with the filter reason, so a SARIF
    viewer hides them by default without losing them.
    """
    by_unit = {unit.id: (unit, assessment) for unit, assessment in _rows(session, scan)}
    found = session.execute(
        select(Finding, ToolRun, UnitFinding.unit_id)
        .join(ToolRun, ToolRun.id == Finding.tool_run_id)
        .join(UnitFinding, UnitFinding.finding_id == Finding.id)
        .where(ToolRun.scan_id == scan.id)
        .order_by(ToolRun.language, ToolRun.tool, Finding.result_index)
    ).all()
    runs: dict[tuple[str, str], dict[str, Any]] = {}
    for finding, run, unit_id in found:
        if unit_id not in by_unit:
            continue
        unit, assessment = by_unit[unit_id]
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
        adjudication = assessment.evidence.get("adjudication") or {}
        result["properties"] = {
            **(raw.get("properties") if isinstance(raw.get("properties"), dict) else {}),
            "securityTriage": {
                "candidateKey": unit.candidate_key or unit.unit_key,
                "unitKey": unit.unit_key,
                "priority": assessment.priority,
                "decisionId": assessment.decision_id,
                "disposition": assessment.disposition,
                "filterRule": adjudication.get("rule"),
            },
        }
        if assessment.disposition == "filtered":
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": adjudication.get("reason") or assessment.reason,
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
