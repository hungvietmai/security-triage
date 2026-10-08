"""Focused regressions for SourceLockTests."""

from __future__ import annotations

# Direct unittest discovery bootstraps the repository and shared backend imports.
# ruff: noqa: E402
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
import copy
import hashlib
import json
import tempfile

from experiments.lock_pair_sources import (
    cache_archive,
    lock_sources,
    lock_version,
    rebind_reassigned_manifests,
)
from experiments.make_pair_manifests import build_manifests, write_json
from experiments.tests.archive_fixtures import archive_bytes

from app.scanners.sources import FetchedArchive


class SourceLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.cache = self.directory / "cache"
        self.manifest = build_manifests()[0][0]
        write_json(self.directory / f"{self.manifest['pair_id']}.json", self.manifest)
        data = archive_bytes({"app.py": b"import os\nos.system(cmd)\n"})
        self.archive = FetchedArchive(
            data,
            hashlib.sha256(data).hexdigest(),
            "https://codeload.github.com/o/r/tar.gz/" + "a" * 40,
            "tofu",
            "package",
        )
        self.calls = []

    def download(self, source):
        self.calls.append(source)
        return self.archive

    def test_reruns_reuse_original_bytes_without_downloading(self):
        locks = lock_sources([self.manifest], self.directory, self.cache, download_fn=self.download)
        self.assertEqual(len(self.calls), 2)
        before = (self.directory / "sources.lock.json").read_bytes()
        lock_sources(
            [self.manifest],
            self.directory,
            self.cache,
            retry_failures=True,
            download_fn=lambda _: self.fail("Locked TOFU must never be fetched again"),
        )
        self.assertEqual((self.directory / "sources.lock.json").read_bytes(), before)
        entry = locks[self.manifest["pair_id"]]["vulnerable"]
        self.assertEqual(cache_archive(self.cache, entry).read_bytes(), self.archive.data)
        self.assertEqual(entry["provenance_kind"], "tofu")

    def test_missing_or_corrupt_cache_does_not_refetch(self):
        locks = lock_sources([self.manifest], self.directory, self.cache, download_fn=self.download)
        entry = locks[self.manifest["pair_id"]]["vulnerable"]
        archive = cache_archive(self.cache, entry)
        archive.write_bytes(b"changed upstream bytes")
        with self.assertRaisesRegex(ValueError, "checksum/size mismatch"):
            lock_sources(
                [self.manifest],
                self.directory,
                self.cache,
                download_fn=lambda _: self.fail("Must not refetch corrupt TOFU"),
            )
        archive.unlink()
        with self.assertRaises(FileNotFoundError):
            lock_sources(
                [self.manifest],
                self.directory,
                self.cache,
                download_fn=lambda _: self.fail("Must not refetch missing TOFU"),
            )

    def test_changed_manifest_cannot_rebind_a_successful_lock(self):
        lock_sources([self.manifest], self.directory, self.cache, download_fn=self.download)
        altered = copy.deepcopy(self.manifest)
        altered["fixed_ref"] = "b" * 40
        write_json(self.directory / f"{altered['pair_id']}.json", altered)
        with self.assertRaisesRegex(ValueError, "Manifest changed"):
            lock_sources([altered], self.directory, self.cache, download_fn=self.download)

    def test_failures_are_recorded_and_retry_is_explicit(self):
        def unavailable(_):
            raise ValueError("archive unavailable")

        locks = lock_sources([self.manifest], self.directory, self.cache, download_fn=unavailable)
        failure = locks[self.manifest["pair_id"]]["vulnerable"]
        self.assertEqual(failure["status"], "failed")
        self.assertIn("archive unavailable", failure["error"])
        lock_sources(
            [self.manifest],
            self.directory,
            self.cache,
            download_fn=lambda _: self.fail("Failure retry must be explicit"),
        )
        locks = lock_sources(
            [self.manifest],
            self.directory,
            self.cache,
            retry_failures=True,
            download_fn=self.download,
        )
        self.assertEqual(
            locks[self.manifest["pair_id"]]["vulnerable"]["previous_attempts"][0]["error"],
            failure["error"],
        )

    def test_download_hash_is_checked_before_caching(self):
        bad = FetchedArchive(b"bytes", "0" * 64, "https://example.com", "tofu", None)
        result = lock_version(self.manifest["vulnerable_source"], self.cache, lambda _: bad)
        self.assertEqual(result["status"], "failed")
        self.assertIn("inconsistent SHA-256", result["error"])


if __name__ == "__main__":
    unittest.main()


class SplitReassignmentRebindTests(unittest.TestCase):
    """Amendment 05: a lock follows a manifest only when its split alone was reassigned."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        manifest = copy.deepcopy(build_manifests()[0][0])
        self.pair_id = manifest["pair_id"]
        self.path = self.directory / f"{self.pair_id}.json"
        write_json(self.path, {**manifest, "split": "reserve"})
        self.locked_hash = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.archive_entry = {"status": "locked", "sha256": "a" * 64}
        write_json(
            self.directory / "sources.lock.json",
            {
                self.pair_id: {
                    "manifest_sha256": self.locked_hash,
                    "vulnerable": self.archive_entry,
                    "fixed": self.archive_entry,
                }
            },
        )
        self.manifest = {**manifest, "split": "development"}
        self.split = self.directory / "split.json"
        write_json(
            self.split,
            {
                "split_id": "split-test",
                "amendment": "experiments/amendments/AMENDMENT_05.md",
                "groups": [
                    {
                        "group_id": manifest["group_id"],
                        "pair_ids": [self.pair_id],
                        "assignment": "development",
                        "previous_assignment": "reserve",
                    }
                ],
            },
        )

    def lock(self):
        return json.loads((self.directory / "sources.lock.json").read_text(encoding="utf-8"))

    def test_rebinds_a_split_only_change_once_and_records_it(self):
        write_json(self.path, self.manifest)
        self.assertEqual(rebind_reassigned_manifests(self.directory, self.split), [self.pair_id])
        entry = self.lock()[self.pair_id]
        self.assertEqual(entry["manifest_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(entry["vulnerable"], self.archive_entry)
        self.assertEqual(
            entry["rebinds"],
            [
                {
                    "previous_manifest_sha256": self.locked_hash,
                    "field": "split",
                    "from": "reserve",
                    "to": "development",
                    "split_id": "split-test",
                    "reference": "experiments/amendments/AMENDMENT_05.md",
                }
            ],
        )
        self.assertEqual(rebind_reassigned_manifests(self.directory, self.split), [])
        self.assertEqual(len(self.lock()[self.pair_id]["rebinds"]), 1)

    def test_refuses_any_change_beyond_the_split(self):
        write_json(self.path, {**self.manifest, "fixed_ref": "something-else"})
        with self.assertRaisesRegex(ValueError, "beyond its split assignment"):
            rebind_reassigned_manifests(self.directory, self.split)
        self.assertEqual(self.lock()[self.pair_id]["manifest_sha256"], self.locked_hash)

    def test_requires_an_authorizing_amendment(self):
        split = json.loads(self.split.read_text(encoding="utf-8"))
        del split["amendment"]
        write_json(self.split, split)
        with self.assertRaisesRegex(ValueError, "no amendment"):
            rebind_reassigned_manifests(self.directory, self.split)
