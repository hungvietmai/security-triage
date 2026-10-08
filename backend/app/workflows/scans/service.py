"""Scan creation and result queries. Functions take a Session and never touch HTTP concerns."""

import uuid
from typing import Any

from sqlalchemy import ColumnElement, case, exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.pagination import PageParams, PageResult, paginate
from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.scanners.sources import github_coordinate, npm_coordinate
from app.workflows.scans.exceptions import UnitNotFound
from app.workflows.scans.schemas import TIERS, NpmSource, ScanCreate, Tier, Tool

# Queue order for display only (policy: ranking evaluation uses uniform order within a tier).
_QUEUE_ORDER = case(
    {tier: index for index, tier in enumerate(TIERS)}, value=UnitAssessment.priority
)


def _snapshot_fields(data: ScanCreate) -> dict[str, Any]:
    source = data.source
    if isinstance(source, NpmSource):
        return {
            "source_kind": "npm_tarball",
            "source_coordinate": npm_coordinate(source.package, source.version),
            "ecosystem": "npm",
            "package_name": source.package,
            "package_version": source.version,
        }
    return {
        "source_kind": "github_tarball",
        "source_coordinate": github_coordinate(source.owner, source.repo, source.commit),
        "repository_url": f"https://github.com/{source.owner}/{source.repo}",
        "resolved_commit": source.commit,
    }


def create_scan(session: Session, project: Project, data: ScanCreate, *, bucket: str) -> Scan:
    """Queue a scan, reusing the project's snapshot of the same named source when one exists."""
    fields = _snapshot_fields(data)
    lookup = select(SourceSnapshot).where(
        SourceSnapshot.project_id == project.id,
        SourceSnapshot.source_coordinate == fields["source_coordinate"],
    )
    snapshot = session.scalar(lookup)
    if snapshot is None:
        snapshot_id = uuid.uuid4()
        snapshot = SourceSnapshot(
            id=snapshot_id,
            project_id=project.id,
            bucket=bucket,
            object_key=f"snapshots/{snapshot_id}.tgz",
            status="validating",
            **fields,
        )
        session.add(snapshot)
        try:
            session.flush()
        except IntegrityError:
            # A concurrent request created it first; the unique coordinate makes that one win.
            session.rollback()
            snapshot = session.scalar(lookup)
            if snapshot is None:
                raise
    if snapshot.status == "failed":
        snapshot.status, snapshot.error_message = "validating", None  # try the download again
    scan = Scan(snapshot_id=snapshot.id, config={"profile": data.profile})
    session.add(scan)
    session.commit()
    return scan


def _results(scan: Scan) -> list[ColumnElement[bool]]:
    """Units and assessments of exactly the versions this scan was written with."""
    return [
        LocationUnit.scan_id == scan.id,
        LocationUnit.reconciler_version == scan.reconciler_version,
        UnitAssessment.policy_version == scan.policy_version,
    ]


def describe_scan(session: Session, scan: Scan) -> dict[str, Any]:
    snapshot = session.get_one(SourceSnapshot, scan.snapshot_id)
    runs = session.scalars(
        select(ToolRun).where(ToolRun.scan_id == scan.id).order_by(ToolRun.language, ToolRun.tool)
    ).all()
    counted = session.execute(
        select(UnitAssessment.priority, func.count())
        .join(LocationUnit, LocationUnit.id == UnitAssessment.unit_id)
        .where(*_results(scan))
        .group_by(UnitAssessment.priority)
    ).all()
    counts = dict.fromkeys(TIERS, 0) | {priority: count for priority, count in counted}
    return {
        "id": scan.id,
        "project_id": snapshot.project_id,
        "status": scan.status,
        "profile": scan.config.get("profile_id") or scan.config.get("profile"),
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "error_message": scan.error_message,
        "reconciler_version": scan.reconciler_version,
        "policy_version": scan.policy_version,
        "snapshot": snapshot,
        "tool_runs": runs,
        "unit_counts": counts,
    }


def _summary(
    unit: LocationUnit, *, priority: str, decision_id: str, reason: str, tools: list[str]
) -> dict[str, Any]:
    return {
        "id": unit.id,
        "unit_key": unit.unit_key,
        "path": unit.path,
        "start_line": unit.start_line,
        "end_line": unit.end_line,
        "start_column": unit.start_column,
        "end_column": unit.end_column,
        "sink_kind": unit.sink_kind,
        "argument_role": unit.argument_role,
        "mapping_status": unit.mapping_status,
        "priority": priority,
        "decision_id": decision_id,
        "reason": reason,
        "tools": tools,
    }


def list_units(
    session: Session, scan: Scan, *, page: PageParams, tier: Tier | None, tool: Tool | None
) -> PageResult[dict[str, Any]]:
    """P1, P2, U, P3, P4, then unit_key: a total order, so pages never overlap."""
    statement = (
        select(LocationUnit)
        .join(UnitAssessment, UnitAssessment.unit_id == LocationUnit.id)
        .where(*_results(scan))
        .order_by(_QUEUE_ORDER, LocationUnit.unit_key)
    )
    if tier is not None:
        statement = statement.where(UnitAssessment.priority == tier)
    if tool is not None:
        statement = statement.where(
            exists()
            .where(UnitFinding.unit_id == LocationUnit.id)
            .where(Finding.id == UnitFinding.finding_id)
            .where(ToolRun.id == Finding.tool_run_id)
            .where(ToolRun.tool == tool)
        )
    result = paginate(session, statement, page)
    assessments = {}
    if result.items:
        # Lists only need tool names; complete trace/evidence JSON is reserved for detail reads.
        assessments = {
            row.unit_id: row
            for row in session.execute(
                select(
                    UnitAssessment.unit_id,
                    UnitAssessment.priority,
                    UnitAssessment.decision_id,
                    UnitAssessment.reason,
                    UnitAssessment.evidence["tools"].label("tools"),
                ).where(
                    UnitAssessment.unit_id.in_([unit.id for unit in result.items]),
                    UnitAssessment.policy_version == scan.policy_version,
                )
            )
        }
    return PageResult(
        items=[
            _summary(
                unit,
                priority=assessments[unit.id].priority,
                decision_id=assessments[unit.id].decision_id,
                reason=assessments[unit.id].reason,
                tools=assessments[unit.id].tools or [],
            )
            for unit in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
    )


def get_unit(session: Session, scan: Scan, unit_id: uuid.UUID) -> dict[str, Any]:
    row = session.execute(
        select(LocationUnit, UnitAssessment)
        .join(UnitAssessment, UnitAssessment.unit_id == LocationUnit.id)
        .where(LocationUnit.id == unit_id, *_results(scan))
    ).one_or_none()
    if row is None:
        raise UnitNotFound()
    unit, assessment = row
    findings = session.execute(
        select(Finding, ToolRun)
        .join(UnitFinding, UnitFinding.finding_id == Finding.id)
        .join(ToolRun, ToolRun.id == Finding.tool_run_id)
        .where(UnitFinding.unit_id == unit.id)
        .order_by(ToolRun.tool, Finding.result_index)
    ).all()
    evidence = assessment.evidence
    return {
        **_summary(
            unit,
            priority=assessment.priority,
            decision_id=assessment.decision_id,
            reason=assessment.reason,
            tools=evidence.get("tools", []),
        ),
        "matched_conditions": assessment.matched_conditions,
        "predicate_values": evidence.get("predicate_values", {}),
        "unknown_fields": evidence.get("unknown_fields", []),
        "source_types": evidence.get("source_types", []),
        "shell_state": evidence.get("shell_state"),
        "blocker_proof": evidence.get("blocker_proof"),
        "finding_evidence": evidence.get("finding_evidence", []),
        "policy_id": assessment.policy_id,
        "policy_version": assessment.policy_version,
        "policy_sha256": assessment.policy_sha256,
        "spec_sha256": assessment.spec_sha256,
        "rule_claims_version": assessment.rule_claims_version,
        "rule_claims_sha256": assessment.rule_claims_sha256,
        "reconciler_version": unit.reconciler_version,
        "findings": [
            {
                "id": finding.id,
                "tool": run.tool,
                "language": run.language,
                "raw_id": finding.evidence.get("raw_id"),
                "rule_id": finding.rule_id,
                "raw_rule_id": finding.evidence.get("raw_rule_id"),
                "file_path": finding.file_path,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "start_column": finding.start_column,
                "end_column": finding.end_column,
                "message": finding.message,
                "cwe_ids": finding.cwe_ids,
                "raw_result": finding.evidence.get("raw_result", {}),
            }
            for finding, run in findings
        ],
    }
