"""run_scan: take one queued scan from its source snapshot to persisted, prioritized results.

Only infrastructure errors (database, object storage) are retried. Scanner, archive, profile
and triage failures are final: the pinned tools would produce the same result again.
"""

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
from app.scanners.pipeline import PipelineStatus, run_pipeline
from app.scanners.process import InvokeCallable, invoke
from app.scanners.profile import load_profile
from app.scanners.provenance import digest
from app.scanners.sources import Fetch, fetch_allowlisted
from app.triage.reconcile import RECONCILIATION_VERSION
from app.workflows.scans.analysis import RunPipeline, scan_language
from app.workflows.scans.exceptions import INFRA_ERRORS
from app.workflows.scans.persist import claim_scan, mark_scan_failed, persist_scan_result
from app.workflows.scans.results import LanguageResult, ScanResult
from app.workflows.scans.snapshots import acquire_snapshot, prepare_snapshot

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
# Per profile language: two version checks (60 s) and four steps bounded by the profile's
# timeout_seconds (Semgrep, CodeQL create, CodeQL analyze, sink locator). Both languages of
# command-injection-v0.1 at 600 s, plus transfer headroom; a test keeps this above the profile.
SCANNER_STEPS = 4
SOFT_TIME_LIMIT = 2 * (2 * 60 + SCANNER_STEPS * 600) + 600
# The soft limit interrupts only the main thread. With parallel scanners it then waits for the
# other thread's scanner, bounded by its own 600 s timeout, before it can mark the scan failed;
# the hard limit must leave that time, or the scan would be killed and stay "running".
TIME_LIMIT = SOFT_TIME_LIMIT + 600 + 300


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


def scan_snapshot(
    scan_id: uuid.UUID,
    snapshot: SourceSnapshot,
    *,
    settings: Settings,
    storage: "S3Client",
    run_pipeline_fn: RunPipeline = run_pipeline,
    invoke_fn: InvokeCallable = invoke,
) -> ScanResult:
    """Scan, triage and upload artifacts in a work directory that never outlives the call."""
    profile = load_profile(settings.triage_root, settings.scan_profile)
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
            results.append(
                scan_language(
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
            )
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
            "reconciler_version": RECONCILIATION_VERSION,
            "policy_version": profile.policy["policy_version"],
            "scanner_workers": settings.scanner_workers,
            "artifact_upload_workers": settings.artifact_upload_workers,
        },
        source_file_count=len(files),
    )


def execute_scan(
    scan_id: uuid.UUID,
    *,
    session_factory: Callable[[], Session] | None = None,
    storage: "S3Client | None" = None,
    run_pipeline_fn: RunPipeline = run_pipeline,
    invoke_fn: InvokeCallable = invoke,
    fetch: Fetch = fetch_allowlisted,
) -> str:
    """Run one scan to a final state. Infrastructure errors propagate for the task to retry."""
    with (session_factory or SessionLocal)() as session:
        if not claim_scan(session, scan_id, now=_now()):
            return "skipped"
        snapshot_id = session.get_one(Scan, scan_id).snapshot_id
        try:
            storage = storage or get_s3_client()
            acquire_snapshot(session, snapshot_id, storage=storage, fetch=fetch, now=_now())
            result = scan_snapshot(
                scan_id,
                session.get_one(SourceSnapshot, snapshot_id),
                settings=get_settings(),
                storage=storage,
                run_pipeline_fn=run_pipeline_fn,
                invoke_fn=invoke_fn,
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
