"""Download and lock pair archives through the day-5 allowlisted acquisition path.

No extraction or scanner invocation. Successful locks are immutable, including on
reruns: missing or changed cache bytes are an error, never a reason to refetch TOFU.
"""

# Direct CLI execution bootstraps the repository/backend before shared imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from experiments.make_pair_manifests import PAIRS, VERSIONS, load_manifests, sha256, write_json

from app.scanners.sources import FetchedArchive, fetch_github, fetch_npm

CACHE = ROOT / "artifacts/pair-sources"
_CACHE_WRITE_LOCK = Lock()


def cache_archive(cache: Path, value: dict[str, Any]) -> Path:
    digest = value.get("sha256")
    if (
        value.get("status") != "locked"
        or not isinstance(digest, str)
        or not re.fullmatch(r"[a-f0-9]{64}", digest)
    ):
        raise ValueError("Source version is not locked")
    archive = cache / f"{digest}.tgz"
    if sha256(archive) != digest or archive.stat().st_size != value["size_bytes"]:
        raise ValueError(f"Locked cache checksum/size mismatch: {digest}")
    return archive


def download(source: dict[str, str]) -> FetchedArchive:
    if source["source_kind"] == "npm_tarball":
        return fetch_npm(source["package_name"], source["package_version"])
    owner, repo = source["repository"].split("/")
    return fetch_github(owner, repo, source["commit"])


def lock_version(source: dict[str, str], cache: Path, download_fn=download) -> dict[str, Any]:
    attempted_at = datetime.now(UTC).isoformat()
    try:
        archive = download_fn(source)
        digest = hashlib.sha256(archive.data).hexdigest()
        if digest != archive.sha256:
            raise ValueError("Acquisition returned inconsistent SHA-256")
        cache.mkdir(parents=True, exist_ok=True)
        target = cache / f"{digest}.tgz"
        # Two versions/pairs may share bytes; avoid replacing a file another worker is reading.
        with _CACHE_WRITE_LOCK:
            if target.exists():
                if sha256(target) != digest:
                    raise ValueError("Existing content-addressed cache is corrupt")
            else:
                with tempfile.NamedTemporaryFile(
                    dir=cache, prefix=digest, suffix=".tmp", delete=False
                ) as stream:
                    stream.write(archive.data)
                    temporary = Path(stream.name)
                temporary.replace(target)
        return {
            "status": "locked",
            "sha256": digest,
            "provenance_kind": archive.provenance_kind,
            "artifact_url": archive.artifact_url,
            "archive_root": archive.archive_root,
            "size_bytes": len(archive.data),
            "source_reference": source["source_reference"],
            "locked_at": attempted_at,
        }
    except Exception as error:
        return {
            "status": "failed",
            "error": f"{type(error).__name__}: {error}",
            "source_reference": source["source_reference"],
            "attempted_at": attempted_at,
        }


def lock_sources(
    manifests,
    directory: Path,
    cache: Path,
    *,
    workers=4,
    retry_failures=False,
    download_fn=download,
):
    lock_path = directory / "sources.lock.json"
    locked = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {}
    jobs = []
    for manifest in manifests:
        pair_id = manifest["pair_id"]
        manifest_hash = sha256(directory / f"{pair_id}.json")
        entry = locked.setdefault(pair_id, {"manifest_sha256": manifest_hash})
        if entry["manifest_sha256"] != manifest_hash:
            raise ValueError(f"Manifest changed after locking: {pair_id}")
        for version in VERSIONS:
            previous = entry.get(version)
            if previous and previous["status"] == "locked":
                cache_archive(cache, previous)
            elif not previous or retry_failures:
                jobs.append((pair_id, version, manifest[f"{version}_source"]))
    write_json(lock_path, locked)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        tasks = {
            pool.submit(lock_version, source, cache, download_fn): (pair_id, version)
            for pair_id, version, source in jobs
        }
        for future in as_completed(tasks):
            pair_id, version = tasks[future]
            result = future.result()
            previous = locked[pair_id].get(version)
            if previous:
                result["previous_attempts"] = [
                    *previous.get("previous_attempts", []),
                    {key: value for key, value in previous.items() if key != "previous_attempts"},
                ]
            locked[pair_id][version] = result
            write_json(lock_path, locked)
            print(
                f"{pair_id}/{version}: {result['status']}"
                + (f" ({result['error']})" if result["status"] == "failed" else ""),
                flush=True,
            )
    return locked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=Path, default=PAIRS)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--retry-failures", action="store_true")
    args = parser.parse_args()
    manifests = load_manifests(args.pairs)
    locks = lock_sources(
        manifests, args.pairs, args.cache, workers=args.workers, retry_failures=args.retry_failures
    )
    failures = {
        pair_id: {
            version: entry.get(version, {"status": "not_attempted"})
            for version in VERSIONS
            if entry.get(version, {}).get("status") != "locked"
        }
        for pair_id, entry in locks.items()
        if any(entry.get(version, {}).get("status") != "locked" for version in VERSIONS)
    }
    report = {
        "pairs_attempted": len(manifests),
        "pairs_locked": len(manifests) - len(failures),
        "versions_locked": sum(
            entry.get(version, {}).get("status") == "locked"
            for entry in locks.values()
            for version in VERSIONS
        ),
        "failures": failures,
        "replacement_performed": False,
        "replacements": [],
        "scanner_invocations": 0,
        "cache_layout": "<sha256>.tgz",
        "lock_sha256": sha256(args.pairs / "sources.lock.json"),
    }
    write_json(args.pairs / "sources-report.json", report)
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "pairs_attempted",
                    "pairs_locked",
                    "versions_locked",
                    "scanner_invocations",
                )
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
