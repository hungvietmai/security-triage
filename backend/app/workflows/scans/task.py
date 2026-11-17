"""run_scan: take one queued scan from its source snapshot to persisted, prioritized results.

Only infrastructure errors (database, object storage) are retried. Scanner, archive, profile
and triage failures are final: the pinned tools would produce the same result again.
"""

import json
import logging
import tempfile
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from celery import Task, shared_task
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import SessionLocal
from app.core.storage import get_s3_client
from app.features.scans.models import Scan
from app.features.sources.models import SourceSnapshot
from app.scanners.acquisition import SOURCE_EXTENSIONS
from app.scanners.codeql import run_codeql_evidence
from app.scanners.passes import run_member_pass
from app.scanners.pipeline import PipelineStatus, run_pipeline
from app.scanners.process import InvokeCallable, invoke
from app.scanners.profile import (
    CompositeProfile,
    DetectionProfile,
    EvidenceProfile,
    LoadedProfile,
    ScanProfile,
    load_any_profile,
)
from app.scanners.provenance import digest
from app.scanners.sources import Fetch, fetch_allowlisted
from app.triage.reconcile import RECONCILIATION_VERSION
from app.triage.safety_evidence import EVIDENCE_UNIT_VERSION
from app.workflows.scans.analysis import RunPipeline, scan_language, scan_language_evidence
from app.workflows.scans.detection import DETECTION_UNIT_VERSION
from app.workflows.scans.exceptions import INFRA_ERRORS
from app.workflows.scans.families import (
    COMPOSITION_VERSION,
    FAMILY_OF_PROFILE,
    MEMBER_PASS_TOOLS,
    AnalyzePass,
    MemberPass,
    family_summaries,
    hold_unranked,
    members_of,
    scan_language_families,
    to_language_result,
)
from app.workflows.scans.persist import claim_scan, mark_scan_failed, persist_scan_result
from app.workflows.scans.results import LanguageResult, ScanResult
from app.workflows.scans.snapshots import acquire_snapshot, prepare_snapshot

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
# The soft limit must cover every step of the largest profile running to its timeout
# (`worst_case_seconds`): multi-cwe-v0.6 needs 13560 s, multi-cwe-v0.5 12360 s, multi-cwe-v0.3
# and v0.4 11760 s, multi-cwe-v0.2 9960 s, multi-cwe-v0.1 8760 s, command-injection-v0.3 7560 s.
# A test keeps this above every profile, and TIME_LIMIT below the broker's visibility timeout
# (app.workers.celery_app, 18000 s).
SOFT_TIME_LIMIT = 13800
# The soft limit interrupts only the main thread, which then waits for a scanner thread still
# running, bounded by that step's timeout, before it can mark the scan failed. The hard limit
# must leave that time, or the scan would be killed and stay "running". The longest step is
# path-traversal-v0.2's CodeQL at 1200 s; a test keeps this current. The hard limit stays
# below the broker's visibility timeout, or a running scan would be delivered again.
LONGEST_SCANNER_STEP = 1200
TIME_LIMIT = SOFT_TIME_LIMIT + LONGEST_SCANNER_STEP + 300


def _language_seconds(config: dict[str, Any], *, locator: bool) -> int:
    """Every process of one language run at its limit: version checks and timed steps."""
    scanners = config["scanners"]
    # CodeQL is two steps: database creation and analysis.
    steps = sum(2 if tool == "codeql" else 1 for tool in scanners)
    steps += sum(
        name in config.get("adjudication", {}) for name in ("semgrep_evidence", "codeql_evidence")
    )
    return len(scanners) * 60 + (steps + locator) * int(config["timeout_seconds"])


def worst_case_seconds(profile: LoadedProfile) -> int:
    """How long a scan with `profile` can spend in scanner processes, all languages present."""
    primary = profile.members[0][1] if isinstance(profile, CompositeProfile) else profile
    total = sum(
        # The JavaScript sink locator is a Semgrep run of its own; Python's runs in process.
        _language_seconds(
            config, locator=isinstance(primary, ScanProfile) and language == "javascript"
        )
        for language, config in primary.configs.items()
    )
    if isinstance(profile, CompositeProfile):
        # Every other member adds its own passes per language: one CodeQL analysis on the
        # shared database and, for a detection member, its own Semgrep and Bandit passes.
        total += sum(
            int(config["timeout_seconds"])
            * sum(tool in MEMBER_PASS_TOOLS for tool in config["scanners"])
            for _, member in profile.members[1:]
            for language, config in member.configs.items()
            if language in primary.configs
        )
    return total


def _now() -> datetime:
    return datetime.now(UTC)


def _upload(
    storage: "S3Client",
    bucket: str,
    scan_id: uuid.UUID,
    language: str,
    output: Path,
    *,
    workers: int = 4,
) -> dict[str, dict[str, Any]]:
    """Every regular file of a language run (SARIF, logs, JSON); the CodeQL database stays."""
    if not 1 <= workers <= 8:
        raise ValueError("Artifact upload workers must be between 1 and 8")
    paths = [path for path in sorted(output.iterdir()) if path.is_file()]

    def upload(path: Path) -> tuple[str, dict[str, Any]]:
        sha256 = digest(path)
        name = f"{language}/{path.name}"
        key = f"scans/{scan_id}/{name}"
        with path.open("rb") as body:
            storage.put_object(Bucket=bucket, Key=key, Body=body)
        return name, {"key": key, "sha256": sha256, "size": path.stat().st_size}

    if workers == 1 or len(paths) < 2:
        return dict(upload(path) for path in paths)
    # Joining before workspace cleanup closes every stream, including after an upload error.
    with ThreadPoolExecutor(
        max_workers=min(workers, len(paths)), thread_name_prefix="scan-upload"
    ) as pool:
        pending = [pool.submit(upload, path) for path in paths]
        try:
            uploaded = {}
            for future in as_completed(pending):
                name, metadata = future.result()
                uploaded[name] = metadata
        except BaseException:
            pool.shutdown(wait=True, cancel_futures=True)
            raise
    return {f"{language}/{path.name}": uploaded[f"{language}/{path.name}"] for path in paths}


def _overall(statuses: list[PipelineStatus]) -> PipelineStatus:
    """The pipeline's own rule, across languages: all completed, some usable, or none."""
    if all(status == "completed" for status in statuses):
        return "completed"
    return "partial" if any(s in {"completed", "partial"} for s in statuses) else "failed"


def load_scan_profile(settings: Settings, profile_id: str | None) -> LoadedProfile:
    """The scan's named profile, or the default for scans created before profiles were named."""
    if profile_id is None:
        manifest = settings.scan_profile
    elif profile_id in settings.scan_profiles:
        manifest = settings.scan_profiles[profile_id]
    else:
        raise ValueError(f"Unknown scan profile: {profile_id}")
    return load_any_profile(settings.triage_root, manifest)


def scan_snapshot(
    scan_id: uuid.UUID,
    snapshot: SourceSnapshot,
    *,
    settings: Settings,
    storage: "S3Client",
    profile_id: str | None = None,
    run_pipeline_fn: RunPipeline = run_pipeline,
    invoke_fn: InvokeCallable = invoke,
    analyze_fn: AnalyzePass = run_codeql_evidence,
    pass_fn: MemberPass = run_member_pass,
) -> ScanResult:
    """Scan, triage and upload artifacts in a work directory that never outlives the call."""
    profile = load_scan_profile(settings, profile_id)
    # A composite profile is refused here if it names a family this worker cannot handle.
    members = members_of(profile) if isinstance(profile, CompositeProfile) else None
    families: dict[str, list[dict[str, Any]]] = {}
    if snapshot.status != "ready" or not snapshot.sha256:
        raise ValueError(f"Snapshot is not ready (status {snapshot.status})")
    with tempfile.TemporaryDirectory(prefix=f"scan-{scan_id}-") as folder:
        work = Path(folder)
        source, files = prepare_snapshot(snapshot, storage=storage, work=work)
        languages = [
            language
            for language in profile.configs
            if any(Path(f).suffix.lower() in SOURCE_EXTENSIONS[language] for f in files)
        ]
        if not languages:
            raise ValueError("Snapshot has no source files in a profile language")
        results: list[LanguageResult] = []
        artifacts: dict[str, dict[str, Any]] = {}
        for language in languages:
            output = work / language
            output.mkdir()
            if isinstance(profile, CompositeProfile):
                assert members is not None
                composite = scan_language_families(
                    language,
                    members=members,
                    settings=settings,
                    source=source,
                    files=files,
                    output=output,
                    snapshot_sha256=snapshot.sha256,
                    run_pipeline_fn=run_pipeline_fn,
                    invoke_fn=invoke_fn,
                    analyze_fn=analyze_fn,
                    pass_fn=pass_fn,
                )
                language_result = to_language_result(composite)
                families[language] = family_summaries(composite, members)
                # The members wrote their own files per family; these are the scan's.
                for name, rows in (
                    ("units.json", language_result.units),
                    ("assessments.json", language_result.assessments),
                ):
                    (output / name).write_text(
                        json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                    )
            elif isinstance(profile, EvidenceProfile):
                language_result = scan_language_evidence(
                    language,
                    profile=profile,
                    settings=settings,
                    source=source,
                    output=output,
                    snapshot_sha256=snapshot.sha256,
                    run_pipeline_fn=run_pipeline_fn,
                    invoke_fn=invoke_fn,
                )
            elif isinstance(profile, DetectionProfile):
                # Its queries run on a database another member creates.
                raise ValueError(
                    f"Profile {profile.profile_id} only runs as a member of a composite profile"
                )
            else:
                language_result = scan_language(
                    language,
                    profile=profile,
                    settings=settings,
                    source=source,
                    files=files,
                    output=output,
                    snapshot_sha256=snapshot.sha256,
                    run_pipeline_fn=run_pipeline_fn,
                    invoke_fn=invoke_fn,
                )
            family = FAMILY_OF_PROFILE.get(profile.profile_id)
            if not isinstance(profile, CompositeProfile) and family is not None:
                ranked = language_result
                # Alerts the profile did not rank must still reach the review list.
                language_result = hold_unranked(ranked, family=family)
                if language_result is not ranked:
                    for name, rows in (
                        ("units.json", language_result.units),
                        ("assessments.json", language_result.assessments),
                    ):
                        (output / name).write_text(
                            json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                        )
            results.append(language_result)
            artifacts.update(
                _upload(
                    storage,
                    settings.s3_bucket,
                    scan_id,
                    language,
                    output,
                    workers=settings.artifact_upload_workers,
                )
            )
    status = _overall([result.pipeline.status for result in results])
    failed = [
        f"{result.language}/{tool}: {step.get('error') or step['status']}"
        for result in results
        for tool, step in result.pipeline.steps.items()
        if step.get("status") not in {"completed", "partial"}
    ] + [
        f"{language}/{family['family']}: {family['error']}"
        for language, summaries in families.items()
        for family in summaries
        if family["error"]
    ]
    return ScanResult(
        status=status,
        error=("; ".join(failed) or None) if status != "completed" else None,
        languages=results,
        artifacts=artifacts,
        provenance={
            "profile_id": profile.profile_id,
            "profile_sha256": profile.manifest_sha256,
            "languages": languages,
            **_versions(profile, families),
            "scanner_workers": settings.scanner_workers,
            "artifact_upload_workers": settings.artifact_upload_workers,
            # Status, seconds and alert count of every step, for the before/after report.
            "steps": {
                result.language: {
                    name: {
                        key: value
                        for key, value in step.items()
                        # A composite scan also says what each step is and whom it serves.
                        if key in {"status", "seconds", "raw_findings", "kind", "serves"}
                    }
                    for name, step in result.pipeline.steps.items()
                }
                for result in results
            },
        },
        source_file_count=len(files),
    )


def _versions(profile: LoadedProfile, families: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """How a scan's units and assessments were made, for the scan record."""
    if isinstance(profile, CompositeProfile):
        # Units and assessments carry their own family's versions; the scan names how the
        # families were combined, which members were pinned and what each family did.
        return {
            "reconciler_version": COMPOSITION_VERSION,
            "policy_version": COMPOSITION_VERSION,
            "composition": {
                "version": profile.composition,
                "specification_sha256": profile.specification_sha256,
                "members": [
                    {
                        "family": family,
                        "profile_id": member.profile_id,
                        "profile_sha256": member.manifest_sha256,
                    }
                    for family, member in profile.members
                ],
            },
            "families": families,
        }
    if isinstance(profile, EvidenceProfile):
        return {
            "reconciler_version": EVIDENCE_UNIT_VERSION,
            "policy_version": profile.policy_version,
        }
    if isinstance(profile, DetectionProfile):
        return {
            "reconciler_version": DETECTION_UNIT_VERSION,
            "policy_version": profile.policy_version,
        }
    return {
        "reconciler_version": RECONCILIATION_VERSION,
        "policy_version": profile.policy["policy_version"],
    }


def execute_scan(
    scan_id: uuid.UUID,
    *,
    session_factory: Callable[[], Session] | None = None,
    storage: "S3Client | None" = None,
    run_pipeline_fn: RunPipeline = run_pipeline,
    invoke_fn: InvokeCallable = invoke,
    analyze_fn: AnalyzePass = run_codeql_evidence,
    pass_fn: MemberPass = run_member_pass,
    fetch: Fetch = fetch_allowlisted,
) -> str:
    """Run one scan to a final state. Infrastructure errors propagate for the task to retry."""
    with (session_factory or SessionLocal)() as session:
        if not claim_scan(session, scan_id, now=_now()):
            return "skipped"
        scan = session.get_one(Scan, scan_id)
        snapshot_id, profile_id = scan.snapshot_id, scan.config.get("profile")
        try:
            storage = storage or get_s3_client()
            acquire_snapshot(session, snapshot_id, storage=storage, fetch=fetch, now=_now())
            result = scan_snapshot(
                scan_id,
                session.get_one(SourceSnapshot, snapshot_id),
                settings=get_settings(),
                storage=storage,
                profile_id=profile_id,
                run_pipeline_fn=run_pipeline_fn,
                invoke_fn=invoke_fn,
                analyze_fn=analyze_fn,
                pass_fn=pass_fn,
            )
            persist_scan_result(session, scan_id, result, now=_now())
        except INFRA_ERRORS:
            raise
        except Exception as exc:
            # Includes Celery's SoftTimeLimitExceeded: final, and never left half-written.
            mark_scan_failed(session, scan_id, f"{type(exc).__name__}: {exc}", now=_now())
            return "failed"
        return result.status


@shared_task(
    bind=True,
    name="scans.run_scan",
    acks_late=True,
    reject_on_worker_lost=True,
    soft_time_limit=SOFT_TIME_LIMIT,
    time_limit=TIME_LIMIT,
    max_retries=MAX_RETRIES,
)
def run_scan(self: "Task[[str], str]", scan_id: str) -> str:
    try:
        return execute_scan(uuid.UUID(scan_id))
    except INFRA_ERRORS as exc:
        if self.request.retries >= MAX_RETRIES:
            _fail_quietly(uuid.UUID(scan_id), f"Infrastructure error after retries: {exc}")
            raise
        raise self.retry(exc=exc, countdown=30 * 2**self.request.retries) from exc


def _fail_quietly(scan_id: uuid.UUID, reason: str) -> None:
    """Best effort: the database may be the infrastructure that is down."""
    try:
        with SessionLocal() as session:
            mark_scan_failed(session, scan_id, reason, now=_now())
    except INFRA_ERRORS:
        logger.exception("Could not mark scan %s failed after infrastructure retries", scan_id)
