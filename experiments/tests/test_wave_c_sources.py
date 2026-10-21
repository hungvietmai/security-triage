"""Acquisition/persistence/extraction workflows with synthetic archives and a download boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "wave_c_source_support", ROOT / "experiments/wave-c/source_support.py"
)
SUPPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPORT)
SHA = "a" * 40


def archive_bytes(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as bundle:
        for name, value in entries:
            member = tarfile.TarInfo(name)
            if isinstance(value, bytes):
                member.size = len(value)
                bundle.addfile(member, io.BytesIO(value))
            else:
                member.type, member.linkname = tarfile.SYMTYPE, value
                bundle.addfile(member)
    return data.getvalue()


class WaveCSourcesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory = self.root / "inventory.json"
        self.exclusions = self.root / "exclusions.json"
        self.lock = self.root / "sources.lock.json"
        self.cache = self.root / "cache"
        self.candidate = {
            "rank": 1,
            "repository": "example/repo",
            "selection": "selected",
            "snapshot": {"commit": SHA},
        }
        self.inventory.write_text(json.dumps({"candidates": [self.candidate]}), encoding="utf-8")
        self.exclusions.write_text('{"repositories": []}', encoding="utf-8")
        self.metadata = {"id": 123, "full_name": "Example/Repo", "fork": False}
        self.archive = archive_bytes(
            [
                (f"Repo-{SHA}/app.py", b"raise RuntimeError('must never execute')\n"),
                (f"Repo-{SHA}/tests/test_app.py", b"# retained in extraction\n"),
            ]
        )
        self.calls = []

    def fetch(self, url, limit):
        self.calls.append(url)
        if "codeload.github.com" in url:
            return self.archive
        if "/commits/" in url:
            return json.dumps({"sha": SHA}).encode()
        return json.dumps(self.metadata).encode()

    def prepare(self, **kwargs):
        return SUPPORT.prepare(
            self.root,
            self.inventory,
            self.exclusions,
            self.lock,
            self.cache,
            fetch=self.fetch,
            **kwargs,
        )

    def test_acquire_lock_verify_reuse_and_extract_without_executing_source(self):
        prepared = self.prepare()
        record = prepared["records"][0]
        self.assertEqual(record["status"], "prepared")
        self.assertEqual(record["archive_inventory"]["python_file_count"], 2)
        self.assertEqual(len(self.calls), 3)
        locked_bytes = self.lock.read_bytes()
        self.prepare()
        self.prepare(check=True)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.lock.read_bytes(), locked_bytes)
        archive = SUPPORT.check_object(self.root, record["objects"]["archive"])
        extracted = SUPPORT.extract_archive(archive, self.root / "unpacked", record["archive_root"])
        self.assertTrue((extracted / "tests/test_app.py").is_file())
        self.assertIn("must never execute", (extracted / "app.py").read_text())
        archive.write_bytes(b"changed cache")
        with self.assertRaisesRegex(ValueError, "checksum/size mismatch"):
            self.prepare()
        self.assertEqual(len(self.calls), 3)

    def test_related_fork_is_recorded_without_downloading_archive(self):
        self.metadata.update(fork=True, source={"full_name": "legacy/held-out"})
        self.exclusions.write_text(
            json.dumps({"repositories": [{"repository": "legacy/held-out"}]}), encoding="utf-8"
        )
        record = self.prepare()["records"][0]
        self.assertEqual(record["status"], "excluded_related")
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.root / "unpacked").exists())

    def test_rejected_archive_keeps_original_bytes_and_does_not_retry_on_rerun(self):
        self.archive = archive_bytes([(f"Repo-{SHA}/link", "app.py")])
        record = self.prepare()["records"][0]
        self.assertEqual(record["status"], "rejected_archive")
        self.assertEqual(
            SUPPORT.check_object(self.root, record["objects"]["archive"]).read_bytes(), self.archive
        )
        self.prepare()
        self.assertEqual(len(self.calls), 3)

    def test_unsafe_archives_are_rejected_before_extraction(self):
        for entries in (
            [(f"Repo-{SHA}/../escape.py", b"x")],
            [(f"Repo-{SHA}/app.py", b"a"), (f"Repo-{SHA}/APP.py", b"b")],
            [(f"Repo-{SHA}/a/b.py", b"a"), (f"Repo-{SHA}/a", b"b")],
            [(f"Repo-{SHA}/con.txt", b"a")],
            [(f"wrong-{SHA}/app.py", b"x")],
        ):
            with self.subTest(entries=entries):
                archive = self.root / "unsafe.tgz"
                archive.write_bytes(archive_bytes(entries))
                target = self.root / "never-created"
                with self.assertRaises(ValueError):
                    SUPPORT.extract_archive(archive, target, f"Repo-{SHA}")
                self.assertFalse(target.exists())

    def test_commit_mismatch_does_not_download_archive_and_inventory_changes_are_rejected(self):
        def wrong_commit(url, limit):
            if "/commits/" in url:
                return json.dumps({"sha": "b" * 40}).encode()
            return self.fetch(url, limit)

        result = SUPPORT.prepare(
            self.root, self.inventory, self.exclusions, self.lock, self.cache, fetch=wrong_commit
        )
        self.assertEqual(result["records"][0]["status"], "acquisition_failed")
        self.assertFalse(any("codeload" in url for url in self.calls))
        self.inventory.write_text('{"candidates": []}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "different inventory"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
