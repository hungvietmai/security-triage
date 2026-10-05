"""Artifact provenance helpers."""

import hashlib
from pathlib import Path


def digest(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()
