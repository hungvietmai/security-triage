"""Artifact provenance helpers."""

import hashlib
from pathlib import Path


def digest(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()
