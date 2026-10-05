"""Pinned source acquisition for scanner workspaces."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import tarfile
import time
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from app.scanners.provenance import digest

MAX_ARCHIVE = 50 * 1024 * 1024
MAX_UNPACKED = 200 * 1024 * 1024
MAX_FILES = 5000


@dataclass(frozen=True, slots=True)
class AcquisitionLimits:
    """Resource limits applied while acquiring hostile source archives."""

    max_archive_bytes: int
    max_unpacked_bytes: int
    max_files: int


@dataclass(frozen=True, slots=True)
class AcquiredSource:
    """Verified source snapshot ready for scanner execution."""

    source_path: Path
    archive_path: Path
    snapshot_sha256: str
    source_files: list[str]
    transport: str
    seconds: float


def _required_str(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _string_mapping(value: object, *, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    result: dict[str, str] = {}
    for key, item in cast(dict[object, object], value).items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError(f"{field} must map strings to strings")
        result[key] = item
    return result


def fetch(url: str, target: Path, expected_hash: str, max_bytes: int) -> None:
    """Download one pinned HTTPS artifact with size and SHA-256 checks."""
    if not url.startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
        raise ValueError("HTTPS URL and exact SHA-256 required")
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("Insecure redirect")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("Download size limit or checksum mismatch")
    target.write_bytes(data)


def unpack(
    archive: Path,
    destination: Path,
    archive_root: str,
    *,
    max_unpacked_bytes: int,
    max_files: int,
) -> Path:
    """Extract ordinary files/directories without trusting archive metadata."""
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as bundle:
        members: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        paths: set[str] = set()
        total = 0
        for item in bundle:
            path = PurePosixPath(item.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in item.name
                or not path.parts
                or path.parts[0] != archive_root
                or not (item.isfile() or item.isdir())
            ):
                raise ValueError(f"Unsafe/unsupported archive entry: {item.name}")
            if path.as_posix() in paths:
                raise ValueError("Duplicate archive path")
            paths.add(path.as_posix())
            total += item.size
            if len(paths) > max_files or total > max_unpacked_bytes or item.size < 0:
                raise ValueError("Archive expansion limit exceeded")
            members.append((item, path))

        for item, path in members:
            out = destination.joinpath(*path.parts)
            if item.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(item)
            if source is None:
                raise ValueError(f"Archive member has no file data: {item.name}")
            with source, out.open("xb") as target:
                while data := source.read(1024 * 1024):
                    target.write(data)
    return destination / archive_root


def verify_source_identity(case: Mapping[str, object], source: Path) -> None:
    """Validate pinned source identity without importing or executing target code."""
    source_kind = _required_str(case, "source_kind")
    if source_kind == "npm_tarball":
        package_value = cast(object, json.loads((source / "package.json").read_text()))
        if not isinstance(package_value, dict):
            raise ValueError("package.json must contain an object")
        package = cast(dict[object, object], package_value)
        if (package.get("name"), package.get("version")) != (
            _required_str(case, "package_name"),
            _required_str(case, "package_version"),
        ):
            raise ValueError("Package identity mismatch")
        return

    if source_kind != "github_tarball":
        raise ValueError("Unsupported source kind")

    commit = _required_str(case, "source_commit")
    repository = _required_str(case, "repository")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        raise ValueError("GitHub repository and full source commit required")
    if _required_str(case, "artifact_url") != (
        f"https://codeload.github.com/{repository}/tar.gz/{commit}"
    ):
        raise ValueError("Archive URL must pin the source commit")
    if _required_str(case, "archive_root") != f"{repository.split('/')[1]}-{commit}":
        raise ValueError("Archive root does not match pinned commit")

    identity_files = _string_mapping(
        case.get("identity_files_sha256"), field="identity_files_sha256"
    )
    if not identity_files:
        raise ValueError("Source identity file hashes required")
    source_root = source.resolve()
    for relative, expected in identity_files.items():
        path = (source / relative).resolve()
        if Path(relative).is_absolute() or not path.is_relative_to(source_root):
            raise ValueError("Identity path escapes source root")
        if digest(path) != expected:
            raise ValueError(f"Source identity mismatch: {relative}")


def acquire_source(
    case: Mapping[str, object],
    output: Path,
    *,
    source_archive: Path | None,
    limits: AcquisitionLimits,
) -> AcquiredSource:
    """Acquire, verify, and unpack one immutable source snapshot."""
    begin = time.monotonic()
    archive = output / "source.tgz"
    artifact_hash = _required_str(case, "artifact_sha256")

    if source_archive is not None:
        if (
            source_archive.stat().st_size > limits.max_archive_bytes
            or digest(source_archive) != artifact_hash
        ):
            raise ValueError("Cached source size limit or checksum mismatch")
        shutil.copyfile(source_archive, archive)
        transport = "verified_local_archive"
    else:
        fetch(
            _required_str(case, "artifact_url"),
            archive,
            artifact_hash,
            limits.max_archive_bytes,
        )
        transport = "https"

    registry_integrity = case.get("registry_integrity")
    if registry_integrity is not None:
        if not isinstance(registry_integrity, str):
            raise ValueError("registry_integrity must be a string")
        actual_integrity = "sha512-" + base64.b64encode(
            hashlib.sha512(archive.read_bytes()).digest()
        ).decode()
        if actual_integrity != registry_integrity:
            raise ValueError("Registry integrity mismatch")

    source = unpack(
        archive,
        output / "source",
        _required_str(case, "archive_root"),
        max_unpacked_bytes=limits.max_unpacked_bytes,
        max_files=limits.max_files,
    )
    verify_source_identity(case, source)
    source_files = [
        str(path.relative_to(source)) for path in sorted(source.rglob("*")) if path.is_file()
    ]
    return AcquiredSource(
        source_path=source,
        archive_path=archive,
        snapshot_sha256=digest(archive),
        source_files=source_files,
        transport=transport,
        seconds=time.monotonic() - begin,
    )
