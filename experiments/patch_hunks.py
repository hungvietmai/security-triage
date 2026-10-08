"""Diff locked pair bytes, retaining exact renames and an auditable exclusion list."""

# Direct CLI execution bootstraps the repository/backend before shared imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
import tarfile
from collections import defaultdict
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from experiments.lock_pair_sources import CACHE, cache_archive
from experiments.make_pair_manifests import PAIRS, sha256, write_json

from app.scanners.acquisition import MAX_ARCHIVE, MAX_FILES, MAX_UNPACKED

EXCLUSION_POLICY = {
    "id": "pair-diff-exclusions-v0",
    "directories": [
        "test",
        "tests",
        "testing",
        "__tests__",
        "spec",
        "specs",
        "doc",
        "docs",
        "documentation",
    ],
    "lockfiles": [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
    ],
    "document_extensions": [".md", ".rst", ".adoc"],
    "document_names": [
        "readme",
        "license",
        "licence",
        "notice",
        "changelog",
        "contributing",
        "authors",
        "history",
        "copying",
    ],
}


def exclusion_reason(path: str) -> str | None:
    value = PurePosixPath(path.lower())
    if any(part in EXCLUSION_POLICY["directories"] for part in value.parts[:-1]):
        return (
            "test_directory"
            if any(part in EXCLUSION_POLICY["directories"][:6] for part in value.parts[:-1])
            else "documentation_directory"
        )
    if value.name in EXCLUSION_POLICY["lockfiles"]:
        return "lockfile"
    if (
        value.suffix in EXCLUSION_POLICY["document_extensions"]
        or value.stem in EXCLUSION_POLICY["document_names"]
    ):
        return "documentation"
    if (
        value.name.startswith("test_")
        or value.stem.endswith("_test")
        or ".test." in value.name
        or ".spec." in value.name
    ):
        return "test_file"
    return None


def read_snapshot(archive: Path, *, expected_root: str | None = None):
    """Read bounded ordinary files without extracting or executing target code."""
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Archive size limit exceeded")
    files, ignored, paths, roots = {}, [], set(), set()
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        for item in bundle:
            path = PurePosixPath(item.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in item.name
                or not path.parts
                or not (item.isfile() or item.isdir())
            ):
                raise ValueError(f"Unsafe/unsupported archive entry: {item.name}")
            if path.as_posix() in paths:
                raise ValueError(f"Duplicate archive path: {item.name}")
            paths.add(path.as_posix())
            roots.add(path.parts[0])
            total += item.size
            if len(paths) > MAX_FILES or total > MAX_UNPACKED or item.size < 0:
                raise ValueError("Archive expansion limit exceeded")
            if item.isdir():
                continue
            if len(path.parts) < 2:
                raise ValueError("Archive file is outside a top-level source directory")
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            reason = exclusion_reason(relative)
            if reason:
                ignored.append({"path": relative, "reason": reason})
                continue
            stream = bundle.extractfile(item)
            if stream is None:
                raise ValueError(f"Missing archive file bytes: {item.name}")
            with stream:
                data = stream.read()
            files[relative] = data
    if len(roots) != 1 or (expected_root is not None and roots != {expected_root}):
        raise ValueError("Archive root does not match source identity")
    return files, sorted(ignored, key=lambda item: item["path"])


def diff_files(vulnerable: dict[str, bytes], fixed: dict[str, bytes], *, context: int = 3):
    old_only, new_only = set(vulnerable) - set(fixed), set(fixed) - set(vulnerable)
    by_hash_old, by_hash_new = defaultdict(list), defaultdict(list)
    for path in sorted(old_only):
        by_hash_old[hashlib.sha256(vulnerable[path]).hexdigest()].append(path)
    for path in sorted(new_only):
        by_hash_new[hashlib.sha256(fixed[path]).hexdigest()].append(path)
    renames, ambiguities = [], []
    for digest in sorted(set(by_hash_old) & set(by_hash_new)):
        old, new = by_hash_old[digest], by_hash_new[digest]
        if len(old) == len(new) == 1:
            renames.append({"old_path": old[0], "new_path": new[0], "content_sha256": digest})
            old_only.remove(old[0])
            new_only.remove(new[0])
        else:
            ambiguities.append({"content_sha256": digest, "old_paths": old, "new_paths": new})
    comparisons = [(path, path) for path in sorted(set(vulnerable) & set(fixed))]
    comparisons += [(path, None) for path in sorted(old_only)] + [
        (None, path) for path in sorted(new_only)
    ]
    changes, skipped = [], []
    for old_path, new_path in comparisons:
        before = vulnerable[old_path] if old_path else b""
        after = fixed[new_path] if new_path else b""
        if before == after:
            continue
        try:
            if b"\x00" in before or b"\x00" in after:
                raise UnicodeError("Binary file")
            old_lines = before.decode("utf-8").splitlines(keepends=True)
            new_lines = after.decode("utf-8").splitlines(keepends=True)
        except UnicodeError:
            skipped.append(
                {"old_path": old_path, "new_path": new_path, "reason": "binary_or_non_utf8"}
            )
            continue
        hunks = []
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
        for group in matcher.get_grouped_opcodes(context):
            operations = [
                {
                    "operation": operation,
                    "old_start": i1 + 1,
                    "old_count": i2 - i1,
                    "new_start": j1 + 1,
                    "new_count": j2 - j1,
                    "old_lines": list(range(i1 + 1, i2 + 1))
                    if operation in {"replace", "delete"}
                    else [],
                }
                for operation, i1, i2, j1, j2 in group
                if operation != "equal"
            ]
            hunks.append(
                {
                    "old_start": group[0][1] + 1,
                    "old_count": group[-1][2] - group[0][1],
                    "new_start": group[0][3] + 1,
                    "new_count": group[-1][4] - group[0][3],
                    "changes": operations,
                }
            )
        changes.append(
            {
                "old_path": old_path,
                "new_path": new_path,
                "old_sha256": hashlib.sha256(before).hexdigest() if old_path else None,
                "new_sha256": hashlib.sha256(after).hexdigest() if new_path else None,
                "hunks": hunks,
                "unified_diff": "".join(
                    difflib.unified_diff(
                        old_lines,
                        new_lines,
                        fromfile=old_path or "/dev/null",
                        tofile=new_path or "/dev/null",
                        n=context,
                    )
                ),
            }
        )
    return {
        "files": changes,
        "renames": renames,
        "rename_ambiguities": ambiguities,
        "skipped_changes": skipped,
    }


def load_pair(pair_id: str, directory: Path, cache: Path):
    if not pair_id or PurePosixPath(pair_id).name != pair_id or "\\" in pair_id:
        raise ValueError("Unsafe pair ID")
    manifest_path = directory / f"{pair_id}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["split"] != "development":
        raise ValueError("Patch/known-location inspection is development-only")
    lock = json.loads((directory / "sources.lock.json").read_text(encoding="utf-8"))[pair_id]
    if lock["manifest_sha256"] != sha256(manifest_path):
        raise ValueError("Manifest changed since source locking")
    snapshots = {}
    for version in ("vulnerable", "fixed"):
        snapshots[version] = read_snapshot(
            cache_archive(cache, lock[version]), expected_root=lock[version]["archive_root"]
        )
    # Registry verification is transport evidence; verify package identity independently.
    for version, (files, _) in snapshots.items():
        source = manifest[f"{version}_source"]
        if source["source_kind"] == "npm_tarball":
            identity = json.loads(files["package.json"])
            if (identity.get("name"), identity.get("version")) != (
                source["package_name"],
                source["package_version"],
            ):
                raise ValueError("Package identity differs from pinned coordinates")
    return manifest, lock, snapshots


def extract_hunks(pair_id: str, directory: Path = PAIRS, cache: Path = CACHE):
    manifest, lock, snapshots = load_pair(pair_id, directory, cache)
    result = {
        "pair_id": pair_id,
        "split": manifest["split"],
        "snapshot_sha256": {version: lock[version]["sha256"] for version in snapshots},
        "generator_sha256": sha256(Path(__file__)),
        "exclusion_policy": EXCLUSION_POLICY,
        "ignored": {version: ignored for version, (_, ignored) in snapshots.items()},
        **diff_files(snapshots["vulnerable"][0], snapshots["fixed"][0]),
    }
    write_json(directory / pair_id / "patch-hunks.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", action="append", required=True)
    parser.add_argument("--pairs", type=Path, default=PAIRS)
    parser.add_argument("--cache", type=Path, default=CACHE)
    args = parser.parse_args()
    for pair_id in args.pair:
        result = extract_hunks(pair_id, args.pairs, args.cache)
        print(
            json.dumps(
                {
                    "pair_id": pair_id,
                    "changed_files": len(result["files"]),
                    "hunks": sum(len(file["hunks"]) for file in result["files"]),
                    "renames": len(result["renames"]),
                    "ignored_files": {
                        version: len(paths) for version, paths in result["ignored"].items()
                    },
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
