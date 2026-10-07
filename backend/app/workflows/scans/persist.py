"""Persist one scan's results in a single transaction: replace, never duplicate, never half-write.

Lives in the workflows layer because it writes across features (sources, scans, findings,
triage), which features themselves may not import.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.features.findings.models import Finding
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.scanners.pipeline import PipelineResult
from app.triage.reconcile import RECONCILIATION_VERSION, ReconciledUnit

LOCATOR_VERSION = "sink-locator-v0"
SCANNERS = ("semgrep", "codeql")
# The process layer reports timeouts; the tool-run status vocabulary records them as failures.
_TOOL_STATUS = {"completed": "completed", "partial": "partial"}


@dataclass(frozen=True, slots=True)
class LanguageResult:
    language: str
    pipeline: PipelineResult
    tool_versions: dict[str, str]
    units: list[ReconciledUnit]
    assessments: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: str
    error: str | None
    languages: list[LanguageResult]
    # Uploaded objects by name ("python/codeql.sarif"): {"key", "sha256", "size"}.
    artifacts: dict[str, dict[str, Any]]
    provenance: dict[str, Any]
    source_file_count: int


def claim_scan(session: Session, scan_id: uuid.UUID, *, now: datetime) -> bool:
    """Mark a queued scan running. A redelivered or retried task may resume a running one."""
    result = session.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_(("queued", "running")))
        .values(status="running", started_at=now, finished_at=None, error_message=None)
    )
    session.commit()
    return bool(result.rowcount)  # type: ignore[attr-defined]


def mark_scan_failed(session: Session, scan_id: uuid.UUID, reason: str, *, now: datetime) -> None:
    session.rollback()
    session.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(status="failed", finished_at=now, error_message=reason[:4000])
    )
    session.commit()


def _coordinates(region: dict[str, Any]) -> dict[str, int | None]:
    """SARIF region -> finding columns; anything the schema's ordering checks reject is None."""

    def positive(key: str) -> int | None:
        value = region.get(key)
        return value if type(value) is int and value >= 1 else None

    start_line, end_line = positive("startLine"), positive("endLine")
    start_column, end_column = positive("startColumn"), positive("endColumn")
    if start_line is None:
        return dict.fromkeys(("start_line", "end_line", "start_column", "end_column"))
    if end_line is not None and end_line < start_line:
        end_line = None
    if end_line in (None, start_line) and None not in (start_column, end_column):
        if end_column < start_column:  # type: ignore[operator]
            end_column = None
    return {
        "start_line": start_line,
        "end_line": end_line,
        "start_column": start_column,
        "end_column": end_column,
    }


def _write_language(
    session: Session,
    scan_id: uuid.UUID,
    result: LanguageResult,
    artifacts: dict[str, dict[str, Any]],
) -> None:
    def key(name: str) -> str | None:
        artifact = artifacts.get(f"{result.language}/{name}")
        return artifact["key"] if artifact else None

    # Claims name each finding's pinned rule; Semgrep's raw ID carries a staging-path prefix.
    canonical = {
        record["raw_id"]: record["canonical_rule_id"]
        for assessment in result.assessments
        for record in assessment["finding_evidence"]
        if record.get("canonical_rule_id")
    }
    finding_ids: dict[str, uuid.UUID] = {}
    for tool in SCANNERS:
        step = result.pipeline.steps.get(tool)
        if step is None:
            continue
        run = ToolRun(
            scan_id=scan_id,
            tool=tool,
            language=result.language,
            attempt=1,
            status=_TOOL_STATUS.get(step["status"], "failed"),
            tool_version=result.tool_versions.get(tool),
            config={k: v for k, v in step.items() if k not in {"status", "exit_code", "error"}},
            result_key=key(f"{tool}.sarif"),
            log_key=key(f"{tool}.stderr.log"),
            exit_code=step.get("exit_code"),
            error_message=step.get("error")
            or (step["status"] if step["status"] == "timeout" else None),
        )
        session.add(run)
        session.flush()
        tool_findings = [f for f in result.pipeline.findings if f["tool"] == tool]
        for index, finding in enumerate(tool_findings):
            row = Finding(
                tool_run_id=run.id,
                result_index=index,
                rule_id=canonical.get(finding["raw_id"]) or finding["rule_id"] or "",
                file_path=finding["reported_path"],
                **_coordinates(finding["reported_region"]),
                message=finding["message"],
                cwe_ids=finding["reported_cwes"],
                mapping_version=RECONCILIATION_VERSION,
                evidence={
                    "raw_id": finding["raw_id"],
                    "raw_rule_id": finding["rule_id"],
                    "raw_result": finding["raw_result"],
                },
            )
            session.add(row)
            session.flush()
            finding_ids[finding["raw_id"]] = row.id

    units: dict[str, LocationUnit] = {}
    for unit in result.units:
        span = unit["sink_span"]
        units[unit["unit_id"]] = LocationUnit(
            scan_id=scan_id,
            unit_key=unit["unit_id"],
            path=unit["path"],
            start_line=span["startLine"] if span else None,
            end_line=span["endLine"] if span else None,
            start_column=span["startColumn"] if span else None,
            end_column=span["endColumn"] if span else None,
            sink_kind=unit["sink_kind"],
            argument_role=unit["argument_role"],
            mapping_status=unit["mapping_status"],
            reconciler_version=RECONCILIATION_VERSION,
            locator_version=LOCATOR_VERSION,
        )
    session.add_all(units.values())
    session.flush()
    for unit in result.units:
        for mapping in unit["mappings"]:
            session.add(
                UnitFinding(
                    unit_id=units[unit["unit_id"]].id,
                    finding_id=finding_ids[mapping["raw_id"]],
                    reconciler_version=RECONCILIATION_VERSION,
                    match_rule=mapping["mapping_method"],
                )
            )
    for assessment in result.assessments:
        session.add(
            UnitAssessment(
                unit_id=units[assessment["unit_id"]].id,
                evidence=assessment,
                priority=assessment["priority"],
                decision_id=assessment["decision_id"],
                matched_conditions=assessment["matched_conditions"],
                reason=assessment["reason"],
                policy_id=assessment["policy_id"],
                policy_version=assessment["policy_version"],
                policy_sha256=assessment["policy_sha256"],
                spec_sha256=assessment["spec_sha256"],
                rule_claims_version=assessment["rule_claims_version"],
                rule_claims_sha256=assessment["rule_claims_sha256"],
            )
        )


def persist_scan_result(
    session: Session, scan_id: uuid.UUID, result: ScanResult, *, now: datetime
) -> None:
    """Replace everything this scan produced before with `result`, atomically."""
    try:
        scan = session.get_one(Scan, scan_id)
        # Database cascades remove findings, unit links and assessments with these rows.
        session.execute(delete(ToolRun).where(ToolRun.scan_id == scan_id))
        session.execute(delete(LocationUnit).where(LocationUnit.scan_id == scan_id))
        for language in result.languages:
            _write_language(session, scan_id, language, result.artifacts)
        snapshot = session.get_one(SourceSnapshot, scan.snapshot_id)
        snapshot.provenance_verified_at = now
        if snapshot.file_count is None:
            snapshot.file_count = result.source_file_count
        scan.status = result.status
        scan.finished_at = now
        scan.error_message = result.error
        scan.artifacts = result.artifacts
        scan.config = {**scan.config, **result.provenance}
        scan.reconciler_version = result.provenance["reconciler_version"]
        scan.policy_version = result.provenance["policy_version"]
        session.commit()
    except BaseException:
        session.rollback()
        raise
