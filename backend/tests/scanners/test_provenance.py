"""Artifact hashing uses bounded memory even when scanner logs are large."""

import hashlib
import tracemalloc

from app.scanners.provenance import digest


def test_digest_streams_large_files_and_preserves_the_checksum(tmp_path):
    path = tmp_path / "large.log"
    block = b"x" * (1024 * 1024)
    expected = hashlib.sha256()
    with path.open("wb") as output:
        for _ in range(8):
            output.write(block)
            expected.update(block)

    tracemalloc.start()
    try:
        actual = digest(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert actual == expected.hexdigest()
    assert peak < 2 * 1024 * 1024
