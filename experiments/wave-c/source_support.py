"""Bounded, non-executing acquisition of the already selected wave C snapshots."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 50 * 1024 * 1024
MAX_UNPACKED = 500 * 1024 * 1024
MAX_ENTRIES = 50_000
LIMITS = {"archive_bytes": MAX_ARCHIVE, "unpacked_bytes": MAX_UNPACKED, "entries": MAX_ENTRIES}
COORDINATE = re.compile(r"[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_.-]{1,100}")
HEX40 = re.compile(r"[a-f0-9]{40}")
HEX64 = re.compile(r"[a-f0-9]{64}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def write_json(path: Path, value: object) -> None:
    """Checkpoint only our own manifest; pinned successful records are never downloaded again."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded(value))
    temporary.replace(path)


def safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or any(part.endswith((".", " ")) for part in path.parts)
        or any(
            re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?", part)
            for part in path.parts
        )
    ):
        raise ValueError(f"Unsafe or nonportable path: {name!r}")
    return path


def local(root: Path, name: str) -> Path:
    target = root.joinpath(*safe_relative(name).parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes workspace: {name}")
    return target


def validate_repo(repository: str) -> str:
    value = repository.lower()
    if not COORDINATE.fullmatch(value) or value.split("/")[1] in {".", ".."}:
        raise ValueError(f"Invalid GitHub repository: {repository}")
    return value


class SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (
            new.scheme != "https"
            or new.hostname != old.hostname
            or new.port not in (None, 443)
            or new.username
            or new.password
        ):
            raise ValueError("Refused redirect outside the original HTTPS host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_bytes(url: str, limit: int) -> bytes:
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname not in {"api.github.com", "codeload.github.com"}
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
    ):
        raise ValueError("Not a canonical allowlisted download URL")
    request = urllib.request.Request(url, headers={"User-Agent": "security-triage-wave-c"})
    opener = urllib.request.build_opener(SameHostRedirects())
    # At most one retry for a transient transport/5xx failure, with identical input.
    for attempt in range(2):
        try:
            with opener.open(request, timeout=30) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError(f"Download exceeds {limit} bytes")
            return data
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt:
                raise
        time.sleep(1)
    raise AssertionError("unreachable")


def store(root: Path, cache: Path, data: bytes, suffix: str) -> dict:
    sha = digest(data)
    target = cache / f"{sha}{suffix}"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if file_digest(target) != sha:
            raise ValueError("Content-addressed acquisition cache is corrupt")
    else:
        with target.open("xb") as stream:
            stream.write(data)
    return {"path": target.relative_to(root).as_posix(), "sha256": sha, "size_bytes": len(data)}


def check_object(root: Path, entry: dict) -> Path:
    if not HEX64.fullmatch(entry["sha256"]):
        raise ValueError("Invalid cached-object digest")
    path = local(root, entry["path"])
    if path.stat().st_size != entry["size_bytes"] or file_digest(path) != entry["sha256"]:
        raise ValueError(f"Locked object checksum/size mismatch: {entry['path']}")
    return path


def inspect_archive(path: Path, archive_root: str) -> dict:
    """Reject all links and special files; inspect headers without running target code."""
    seen: set[str] = set()
    files: set[str] = set()
    parents: set[str] = set()
    python_files = []
    total = 0
    with tarfile.open(path, "r:gz") as bundle:
        for member in bundle:
            relative = safe_relative(member.name)
            if relative.parts[0] != archive_root or not (member.isdir() or member.isfile()):
                raise ValueError(f"Unsupported archive root/type: {member.name}")
            normalized = relative.as_posix().casefold()
            if normalized in seen:
                raise ValueError(f"Duplicate/case-colliding archive entry: {member.name}")
            seen.add(normalized)
            ancestors = {p.as_posix().casefold() for p in relative.parents if p.parts}
            if ancestors & files or (member.isfile() and normalized in parents):
                raise ValueError("File/directory collision in archive")
            parents.update(ancestors)
            if member.isfile():
                files.add(normalized)
                total += member.size
                if len(relative.parts) < 2:
                    raise ValueError("Archive top-level root must be a directory")
                if relative.suffix == ".py":
                    python_files.append(PurePosixPath(*relative.parts[1:]).as_posix())
            if member.size < 0 or len(seen) > MAX_ENTRIES or total > MAX_UNPACKED:
                raise ValueError("Archive expansion limit exceeded")
    if not files:
        raise ValueError("Empty source archive")
    return {
        "entries": len(seen),
        "regular_files": len(files),
        "unpacked_bytes": total,
        "python_files": sorted(python_files),
        "python_file_count": len(python_files),
    }


def extract_archive(path: Path, destination: Path, archive_root: str) -> Path:
    inspect_archive(path, archive_root)  # Validate the entire archive before any file is created.
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(path, "r:gz") as bundle:
        for member in bundle:
            relative = safe_relative(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("Missing archive member data")
                with source, target.open("xb") as output:
                    while data := source.read(1024 * 1024):
                        output.write(data)
    return destination / archive_root


def acquire_one(
    root: Path, cache: Path, candidate: dict, excluded: set[str], fetch=fetch_bytes
) -> dict:
    repository = validate_repo(candidate["repository"])
    commit = candidate["snapshot"]["commit"]
    if not HEX40.fullmatch(commit):
        raise ValueError("Full lowercase commit SHA required")
    record = {
        "rank": candidate["rank"],
        "repository": repository,
        "commit": commit,
        "attempted_at": datetime.now(UTC).isoformat(),
        "objects": {},
        "near_duplicate_review": "pending",
        "status": "acquisition_failed",
    }
    try:
        raw_metadata = fetch(f"https://api.github.com/repos/{repository}", 2 * 1024 * 1024)
        record["objects"]["repository_metadata"] = store(root, cache, raw_metadata, ".json")
        metadata = json.loads(raw_metadata)
        canonical = validate_repo(metadata["full_name"])
        if not isinstance(metadata.get("fork"), bool) or not isinstance(metadata.get("id"), int):
            raise ValueError("Missing GitHub repository identity/fork metadata")
        related = {canonical}
        for key in ("parent", "source"):
            if metadata.get(key):
                related.add(validate_repo(metadata[key]["full_name"]))
        if metadata["fork"] and not metadata.get("source"):
            raise ValueError("Fork metadata does not identify its source repository")
        group = validate_repo(metadata.get("source", {}).get("full_name", canonical))
        record.update(
            canonical_repository=canonical,
            repository_id=metadata["id"],
            is_fork=metadata["fork"],
            related_repositories=sorted(related),
            group_id=group,
            alias_resolved=canonical != repository,
        )
        if related & excluded:
            record.update(status="excluded_related", reason="repository/fork related to prior data")
            return record
        raw_commit = fetch(
            f"https://api.github.com/repos/{canonical}/commits/{commit}", 5 * 1024 * 1024
        )
        record["objects"]["commit_metadata"] = store(root, cache, raw_commit, ".json")
        if json.loads(raw_commit)["sha"] != commit:
            raise ValueError("GitHub commit identity mismatch")
        url = f"https://codeload.github.com/{repository}/tar.gz/{commit}"
        record["artifact_url"], record["provenance_kind"] = url, "tofu"
        raw_archive = fetch(url, MAX_ARCHIVE)
        if len(raw_archive) > MAX_ARCHIVE:
            raise ValueError("Archive download limit exceeded")
        record["objects"]["archive"] = store(root, cache, raw_archive, ".tgz")
        record["status"] = "rejected_archive"
        archive_root = f"{metadata['full_name'].split('/')[1]}-{commit}"
        record["archive_root"] = archive_root
        record["archive_inventory"] = inspect_archive(
            check_object(root, record["objects"]["archive"]), archive_root
        )
        record["status"] = "prepared"
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        record["error"] = f"{type(error).__name__}: {error}"
    return record


def verify_sources(root: Path, inventory: dict, lock: dict, inventory_sha256: str) -> None:
    if lock["inventory_sha256"] != inventory_sha256 or lock["limits"] != LIMITS:
        raise ValueError("Source lock belongs to a different inventory/limits")
    selected = [r for r in inventory["candidates"] if r["selection"] == "selected"]
    expected = {(r["rank"], r["repository"], r["snapshot"]["commit"]) for r in selected}
    seen = set()
    for record in lock["records"]:
        identity = record["rank"], record["repository"], record["commit"]
        if identity not in expected or identity in seen:
            raise ValueError("Source lock has duplicate/unselected snapshot")
        seen.add(identity)
        for entry in record["objects"].values():
            check_object(root, entry)
        if record["status"] == "prepared":
            archive = check_object(root, record["objects"]["archive"])
            if inspect_archive(archive, record["archive_root"]) != record["archive_inventory"]:
                raise ValueError("Source archive inventory mismatch")


def prepare(
    root: Path,
    inventory_path: Path,
    exclusions_path: Path,
    output: Path,
    cache: Path,
    *,
    fetch=fetch_bytes,
    check=False,
) -> dict:
    inventory_bytes = inventory_path.read_bytes()
    inventory = json.loads(inventory_bytes)
    if output.exists():
        lock = json.loads(output.read_bytes())
        verify_sources(root, inventory, lock, digest(inventory_bytes))
    else:
        if check:
            raise ValueError("Source lock does not exist")
        lock = {
            "version": "wave-c-sources-v1",
            "inventory_sha256": digest(inventory_bytes),
            "limits": LIMITS,
            "records": [],
        }
    if check:
        selected_count = sum(row["selection"] == "selected" for row in inventory["candidates"])
        if len(lock["records"]) != selected_count:
            raise ValueError("Source preparation is incomplete")
        return lock
    excluded = {
        row["repository"] for row in json.loads(exclusions_path.read_bytes())["repositories"]
    }
    done = {row["rank"] for row in lock["records"]}
    for candidate in inventory["candidates"]:
        if candidate["selection"] != "selected" or candidate["rank"] in done:
            continue
        record = acquire_one(root, cache, candidate, excluded, fetch)
        lock["records"].append(record)
        write_json(output, lock)
        print(
            f"{record['rank']:02d} {record['repository']}: {record['status']}"
            + (f" ({record['error']})" if record.get("error") else ""),
            flush=True,
        )
    return lock
