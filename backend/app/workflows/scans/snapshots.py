"""Acquire immutable source snapshots and validate them before scanning."""

import tarfile
import uuid
from contextlib import closing
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from app.features.sources.models import SourceSnapshot
from app.scanners.acquisition import (
    MAX_ARCHIVE,
    MAX_FILES,
    MAX_UNPACKED,
    list_source_files,
    unpack,
    verify_source_identity,
)
from app.scanners.provenance import digest
from app.scanners.sources import (
    Fetch,
    FetchedArchive,
    SourceError,
    fetch_allowlisted,
    fetch_github,
    fetch_npm,
)
from app.workflows.scans.exceptions import INFRA_ERRORS

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client


def _download(storage: "S3Client", bucket: str, key: str, target: Path) -> None:
    try:
        body = storage.get_object(Bucket=bucket, Key=key)["Body"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
            raise ValueError(f"Snapshot archive missing: {key}") from error
        raise
    total = 0
    with closing(body), target.open("wb") as out:
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


def prepare_snapshot(
    snapshot: SourceSnapshot, *, storage: "S3Client", work: Path
) -> tuple[Path, list[str]]:
    """Verify stored bytes and source identity, then safely extract into the scan workspace."""
    archive = work / "source.tgz"
    _download(storage, snapshot.bucket, snapshot.object_key, archive)
    if digest(archive) != snapshot.sha256:
        raise ValueError("Snapshot archive does not match its recorded SHA-256")
    root = _archive_root(archive)
    if snapshot.source_kind == "github_tarball":
        _, repo = _github_repository(snapshot)
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
    return source, files
