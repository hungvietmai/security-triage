"""Verify immutable repository-relative SHA-256 manifests without running research code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


def local_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "\\" in name
        or ":" in name
        or not relative.parts
    ):
        raise ValueError(f"Unsafe manifest path: {name}")
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes repository: {name}")
    return path


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(root: Path, manifest_name: str) -> int:
    manifest = local_path(root, manifest_name)
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError(f"Malformed manifest entry: {line}")
        expected, name = match.groups()
        path = local_path(root, name)
        canonical = path.resolve().as_posix().casefold()
        if canonical in seen:
            raise ValueError(f"Duplicate manifest path: {name}")
        seen.add(canonical)
        if sha256(path) != expected:
            raise ValueError(f"Hash mismatch: {name}")
    if not seen:
        raise ValueError("Empty manifest")
    return len(seen)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument(
        "--manifest", default="experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.sha256"
    )
    parser.add_argument("--metadata", help="Also verify the recorded manifest and archive hashes")
    args = parser.parse_args()
    try:
        count = verify(args.root, args.manifest)
        if args.metadata:
            metadata = json.loads(local_path(args.root, args.metadata).read_bytes())
            if metadata["manifest"]["path"] != args.manifest:
                raise ValueError("Metadata names a different manifest")
            for key in ("manifest", "archive"):
                entry = metadata[key]
                if sha256(local_path(args.root, entry["path"])) != entry["sha256"]:
                    raise ValueError(f"Metadata hash mismatch: {entry['path']}")
            if metadata["input_count"] != count:
                raise ValueError("Metadata input count mismatch")
        print(f"Verified {count} files: {args.manifest}")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Freeze verification failed: {error}\n")


if __name__ == "__main__":
    main()
