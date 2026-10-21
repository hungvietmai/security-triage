"""Freeze verification CLI using synthetic local files, never frozen research pairs."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "experiments/v03-interprocedural-guard/scripts/verify_freeze.py"


class ResearchFreezeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = b"synthetic query bytes\n"
        (self.root / "query.ql").write_bytes(self.source)
        self.entry = hashlib.sha256(self.source).hexdigest() + "  query.ql\n"
        (self.root / "LOCK.sha256").write_text(self.entry, encoding="utf-8", newline="\n")

    def run_cli(self, *extra):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--root",
                str(self.root),
                "--manifest",
                "LOCK.sha256",
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_verify_manifest_and_archive_then_detect_tampering(self):
        (self.root / "archive.tar.gz").write_bytes(b"synthetic archive bytes")
        metadata = {"input_count": 1}
        for key, name in (("manifest", "LOCK.sha256"), ("archive", "archive.tar.gz")):
            metadata[key] = {
                "path": name,
                "sha256": hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
            }
        (self.root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        original = (self.root / "LOCK.sha256").read_bytes()
        self.assertEqual(self.run_cli("--metadata", "metadata.json").returncode, 0)
        (self.root / "archive.tar.gz").write_bytes(b"tampered")
        self.assertIn("Metadata hash mismatch", self.run_cli("--metadata", "metadata.json").stderr)
        (self.root / "query.ql").write_bytes(b"tampered query")
        self.assertIn("Hash mismatch", self.run_cli().stderr)
        self.assertEqual((self.root / "LOCK.sha256").read_bytes(), original)

    def test_missing_file_unsafe_path_duplicate_and_empty_manifest_are_rejected(self):
        (self.root / "query.ql").unlink()
        self.assertNotEqual(self.run_cli().returncode, 0)
        (self.root / "query.ql").write_bytes(self.source)
        for content, reason in (
            (self.entry.replace("query.ql", "../outside.ql"), "Unsafe manifest path"),
            (self.entry + self.entry, "Duplicate manifest path"),
            (self.entry + self.entry.replace("query.ql", "./query.ql"), "Duplicate manifest path"),
            ("", "Empty manifest"),
            ("invalid entry\n", "Malformed manifest entry"),
        ):
            with self.subTest(reason=reason):
                (self.root / "LOCK.sha256").write_text(content, encoding="utf-8", newline="\n")
                result = self.run_cli()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stderr)


if __name__ == "__main__":
    unittest.main()
