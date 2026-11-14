"""Artifact provenance helpers."""

import hashlib
from collections.abc import Mapping
from pathlib import Path


def digest(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def pinned_file(entry: Mapping[str, object], repository_root: Path) -> Path:
    """Resolve a configured {"path", "sha256"} file inside the repository and check its hash."""
    relative, expected = entry.get("path"), entry.get("sha256")
    if not isinstance(relative, str) or not relative or not isinstance(expected, str):
        raise ValueError("Pinned file needs a path and a sha256")
    root = repository_root.resolve()
    path = (root / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(root):
        raise ValueError(f"Pinned file must stay inside the repository: {relative}")
    if not path.is_file() or digest(path) != expected:
        raise ValueError(f"Pinned file missing or checksum mismatch: {relative}")
    return path
