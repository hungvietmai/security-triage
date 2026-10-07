"""run_scan: take one queued scan from its source snapshot to persisted, prioritized results.

Only infrastructure errors (database, object storage) are retried. Scanner, archive, profile
and triage failures are final: the pinned tools would produce the same result again.
"""

import hashlib
import json
import tarfile
import tempfile
import urllib.error
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from botocore.exceptions import BotoCoreError, ClientError
from celery import Task, shared_task
from sqlalchemy import exc as sa_exc
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import SessionLocal
from app.core.storage import get_s3_client
from app.features.scans.models import Scan
from app.features.sources.models import SourceSnapshot
from app.scanners.acquisition import (
    MAX_ARCHIVE,
    MAX_FILES,
    MAX_UNPACKED,
    SOURCE_EXTENSIONS,
    list_source_files,
    load_source_texts,
    unpack,
    verify_source_identity,
)
from app.scanners.pipeline import PipelineResult, run_pipeline
from app.scanners.process import InvokeCallable, invoke
from app.scanners.profile import ScanProfile, load_profile
from app.scanners.provenance import digest
from app.scanners.semgrep import run_sink_locator
from app.scanners.sources import (
    Fetch,
    FetchedArchive,
    SourceError,
    fetch_allowlisted,
    fetch_github,
    fetch_npm,
)
from app.triage.assess import assert_finding_conservation, assess_units, verified_definitions
from app.triage.policy import validate_policy
from app.triage.reconcile import RECONCILIATION_VERSION, reconcile_findings
from app.triage.sinks_javascript import parse_javascript_sink_output
from app.triage.sinks_python import locate_python_sinks
from app.triage.types import SinkRecord
from app.workflows.scans.persist import (
    LanguageResult,
    ScanResult,
    claim_scan,
    mark_scan_failed,
    persist_scan_result,
)

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

INFRA_ERRORS: tuple[type[Exception], ...] = (
    sa_exc.OperationalError,
    sa_exc.InterfaceError,
    sa_exc.TimeoutError,
    BotoCoreError,
    ClientError,
    # Network trouble reaching the registry or codeload; HTTP 4xx is a SourceError instead.
    urllib.error.URLError,
    TimeoutError,
    ConnectionError,
)
MAX_RETRIES = 3
# Per profile language: two version checks (60 s) and four steps bounded by the profile's
# timeout_seconds (Semgrep, CodeQL create, CodeQL analyze, sink locator). Both languages of
# command-injection-v0.1 at 600 s, plus transfer headroom; a test keeps this above the profile.
SCANNER_STEPS = 4
SOFT_TIME_LIMIT = 2 * (2 * 60 + SCANNER_STEPS * 600) + 600
TIME_LIMIT = SOFT_TIME_LIMIT + 300

RunPipeline = Callable[..., PipelineResult]


def _now() -> datetime:
    return datetime.now(UTC)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download(storage: "S3Client", bucket: str, key: str, target: Path) -> None:
    try:
        body = storage.get_object(Bucket=bucket, Key=key)["Body"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
            raise ValueError(f"Snapshot archive missing: {key}") from error
        raise
    total = 0
    with target.open("wb") as out:
        while chunk := body.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE:
                raise ValueError("Snapshot archive exceeds the size limit")
            out.write(chunk)


def _archive_root(archive: Path) -> str:
    """Snapshots are gzip tars under one top-level directory; unpack() enforces the rest."""
    with tarfile.open(archive, "r:gz") as bundle:
        first = bundle.next()
    if first is None:
        raise ValueError("Snapshot archive is empty")
    return PurePosixPath(first.name).parts[0]


def _github_repository(snapshot: SourceSnapshot) -> tuple[str, str]:
    owner, _, repo = (
        (snapshot.repository_url or "").removeprefix("https://github.com/").partition("/")
    )
    return owner, repo


def _fetch_named(snapshot: SourceSnapshot, fetch: Fetch) -> FetchedArchive:
    if snapshot.source_kind == "npm_tarball":
        return fetch_npm(snapshot.package_name or "", snapshot.package_version or "", fetch=fetch)
    if snapshot.source_kind == "github_tarball":
        owner, repo = _github_repository(snapshot)
        return fetch_github(owner, repo, snapshot.resolved_commit or "", fetch=fetch)
    raise SourceError(f"Snapshot names no source to acquire (kind {snapshot.source_kind})")


def acquire_snapshot(
    session: Session,
    snapshot_id: uuid.UUID,
    *,
    storage: "S3Client",
    fetch: Fetch = fetch_allowlisted,
    now: datetime,
) -> None:
    """Download a named source once; its stored bytes are the snapshot from then on.

    The row lock serializes concurrent scans of one new snapshot: the first downloads,
    the others find it ready. A verification failure marks the snapshot failed.
    """
    snapshot = session.get_one(SourceSnapshot, snapshot_id, with_for_update=True)
    if snapshot.status != "validating":
        status, reason = snapshot.status, snapshot.error_message
        session.commit()
        if status == "ready":
            return
        raise SourceError(f"Snapshot is {status}: {reason}")
    try:
        archive = _fetch_named(snapshot, fetch)
        storage.put_object(Bucket=snapshot.bucket, Key=snapshot.object_key, Body=archive.data)
    except INFRA_ERRORS:
        session.rollback()
        raise
    except Exception as exc:
        snapshot.status = "failed"
        snapshot.error_message = f"{type(exc).__name__}: {exc}"[:4000]
        session.commit()
        raise
    snapshot.sha256 = archive.sha256
    snapshot.size_bytes = len(archive.data)
    snapshot.artifact_url = archive.artifact_url
    snapshot.provenance_kind = archive.provenance_kind
    snapshot.provenance_verified_at = now
    snapshot.status = "ready"
    snapshot.error_message = None
    session.commit()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _upload(
    storage: "S3Client", bucket: str, scan_id: uuid.UUID, language: str, output: Path
) -> dict[str, dict[str, Any]]:
    """Every regular file of a language run (SARIF, logs, JSON); the CodeQL database stays."""
    uploaded = {}
    for path in sorted(output.iterdir()):
        if not path.is_file():
            continue
        data = path.read_bytes()
        name = f"{language}/{path.name}"
        key = f"scans/{scan_id}/{name}"
        storage.put_object(Bucket=bucket, Key=key, Body=data)
        uploaded[name] = {"key": key, "sha256": _sha256(data), "size": len(data)}
    return uploaded


def _locate_sinks(
    language: str,
    profile: ScanProfile,
    source: Path,
    output: Path,
    sources: dict[str, str],
    config: dict[str, Any],
    invoke_fn: InvokeCallable,
) -> tuple[list[SinkRecord], dict[str, Any]]:
    if language == "python":
        sinks = [
            sink for path in sorted(sources) for sink in locate_python_sinks(path, sources[path])
        ]
        return sinks, {"status": "completed", "raw_findings": len(sinks)}
    record, text = run_sink_locator(
        binary="semgrep",
        source=source,
        output=output,
        rule=profile.sink_locators[language],
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
        invoke_fn=invoke_fn,
    )
    sinks = parse_javascript_sink_output(text, sources)
    return sinks, {**record, "raw_findings": len(sinks)}


def _scan_language(
    language: str,
    profile: ScanProfile,
    settings: Settings,
    source: Path,
    files: list[str],
    output: Path,
    snapshot_sha256: str,
    run_pipeline_fn: RunPipeline,
    invoke_fn: InvokeCallable,
) -> LanguageResult:
    config = profile.configs[language]
    pack_version = config["codeql_bundle"][f"{language}_query_pack"]
    pack = settings.codeql_home / f"qlpacks/codeql/{language}-queries/{pack_version}"
    result = run_pipeline_fn(
        scanners=config["scanners"],
        language=language,
        source=source,
        output=output,
        snapshot_sha256=snapshot_sha256,
        repository_root=profile.root,
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version=config["semgrep_version"],
        codeql_version=config["codeql_version"],
        semgrep_rules=config["semgrep_rules"],
        codeql_queries=config["codeql_queries"],
        codeql_query_sha256=config["codeql_query_sha256"],
        javascript_query_pack=pack if language == "javascript" else None,
        python_query_pack=pack if language == "python" else None,
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
        codeql_ram_mb=2048,
        invoke_fn=invoke_fn,
    )
    versions = {"semgrep": config["semgrep_version"], "codeql": config["codeql_version"]}
    units: list[Any] = []
    assessments: list[dict[str, Any]] = []
    if result.status != "failed":
        sources = load_source_texts(source, files, language)
        sinks, locator = _locate_sinks(
            language, profile, source, output, sources, config, invoke_fn
        )
        result.steps["sink-locator"] = locator  # type: ignore[assignment]
        units = reconcile_findings(result.findings, sinks, sources)
        assert_finding_conservation(result.findings, units)
        staged: list[tuple[str | None, object]] = []
        for index, rule in enumerate(config["semgrep_rules"]):
            path = output / f"rule-{index}.yaml"
            rule_id = profile.semgrep_rule_ids[rule["path"]]
            staged.append((digest(path) if path.is_file() else None, {"rules": [{"id": rule_id}]}))
        definitions = verified_definitions(
            language=language,
            semgrep_version=config["semgrep_version"],
            codeql_version=config["codeql_version"],
            semgrep_rules=config["semgrep_rules"],
            staged_rules=staged,
            expected_query_sha256=config["codeql_query_sha256"],
            observed_query_sha256=result.codeql_query_files,
            query_pack_version=pack_version,
        )
        assessments = assess_units(
            units,
            result.findings,
            sinks,
            sources,
            mapping=profile.rule_claims,
            definitions=definitions,
            policy=validate_policy(profile.policy),
            provenance={
                "policy_sha256": profile.policy_sha256,
                "spec_sha256": profile.specification_sha256,
                "rule_claims_version": profile.rule_claims["version"],
                "rule_claims_sha256": profile.rule_claims_sha256,
                "reconciler_version": RECONCILIATION_VERSION,
            },
        )
    _write_json(
        output / "run.json",
        {
            "language": language,
            "status": result.status,
            "steps": result.steps,
            "snapshot_sha256": snapshot_sha256,
            "profile_id": profile.profile_id,
            "profile_sha256": profile.manifest_sha256,
            "codeql_query_files": result.codeql_query_files,
            "raw_findings": len(result.findings),
            "unit_count": len(units),
        },
    )
    _write_json(output / "findings.json", result.findings)
    _write_json(output / "units.json", units)
    _write_json(output / "assessments.json", assessments)
    return LanguageResult(language, result, versions, units, assessments)


def _overall(statuses: list[str]) -> str:
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
        archive = work / "source.tgz"
        _download(storage, snapshot.bucket, snapshot.object_key, archive)
        if digest(archive) != snapshot.sha256:
            raise ValueError("Snapshot archive does not match its recorded SHA-256")
        root = _archive_root(archive)
        if snapshot.source_kind == "github_tarball":
            owner, repo = _github_repository(snapshot)
            if root != f"{repo}-{snapshot.resolved_commit}":
                raise SourceError(f"Archive root {root!r} does not match the requested commit")
        source = unpack(
            archive, work / "source", root, max_unpacked_bytes=MAX_UNPACKED, max_files=MAX_FILES
        )
        if snapshot.source_kind == "npm_tarball":
            # package.json must name the requested package and version.
            verify_source_identity(
                {
                    "source_kind": "npm_tarball",
                    "package_name": snapshot.package_name,
                    "package_version": snapshot.package_version,
                },
                source,
            )
        files = list_source_files(source)
        languages = [
            language
            for language in profile.configs
            if any(Path(f).suffix.lower() in SOURCE_EXTENSIONS[language] for f in files)
        ]
        if not languages:
            raise ValueError("Snapshot has no source files in a profile language")
        results, artifacts = [], {}
        for language in languages:
            output = work / language
            output.mkdir()
            results.append(
                _scan_language(
                    language,
                    profile,
                    settings,
                    source,
                    files,
                    output,
                    snapshot.sha256,
                    run_pipeline_fn,
                    invoke_fn,
                )
            )
            artifacts.update(_upload(storage, settings.s3_bucket, scan_id, language, output))
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
        storage = storage or get_s3_client()
        try:
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
        pass
