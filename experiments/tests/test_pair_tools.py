"""Offline regressions for split selection, immutable locks, diff and source locations."""

from __future__ import annotations

# unittest discovery also works without manually setting PYTHONPATH.
# ruff: noqa: E402
import copy
import csv
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import textwrap
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from experiments.known_locations import locate_javascript, resolve_pyvul, resolve_secbench
from experiments.lock_pair_sources import cache_archive, lock_sources, lock_version
from experiments.make_pair_manifests import (
    INVENTORY,
    SCHEMA,
    SPLIT,
    build_manifests,
    sha256,
    write_json,
)
from experiments.patch_hunks import diff_files, exclusion_reason, read_snapshot

from app.scanners.sources import FetchedArchive


def archive_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for path, data in files.items():
            item = tarfile.TarInfo(f"package/{path}")
            item.size = len(data)
            bundle.addfile(item, io.BytesIO(data))
    return buffer.getvalue()


class ManifestTests(unittest.TestCase):
    def test_v01_pair_counts_and_group_counts_by_language(self):
        manifests, report = build_manifests()
        self.assertEqual(
            report["manifest_counts"], {"development": 24, "held_out": 16, "reserve": 11}
        )
        self.assertEqual(report["group_counts"], {"development": 23, "held_out": 15, "reserve": 11})
        self.assertEqual(report["excluded_count"], 32)
        self.assertEqual(
            Counter((m["language"], m["split"]) for m in manifests),
            Counter(
                {
                    ("javascript", "development"): 14,
                    ("javascript", "held_out"): 9,
                    ("javascript", "reserve"): 11,
                    ("python", "development"): 10,
                    ("python", "held_out"): 7,
                }
            ),
        )
        split = json.loads(SPLIT.read_text())
        actual_groups = Counter(
            (m["language"], m["split"]) for m in {m["group_id"]: m for m in manifests}.values()
        )
        expected_groups = Counter(
            {
                (language, assignment): count
                for language, counts in split["summary_by_language"].items()
                for assignment, count in counts.items()
                if assignment != "excluded"
            }
        )
        self.assertEqual(actual_groups, expected_groups)
        ids = {m["pair_id"] for m in manifests}
        for pair in [
            "pyvul-django-django-e1e81aa1c442",
            "pyvul-PaddlePaddle-Paddle-5ed9478fdef9",
            "pyvul-mlflow-mlflow-a98a341a7222",
            "pyvul-mlflow-mlflow-802911381717",
        ]:
            self.assertNotIn(pair, ids)
        self.assertEqual(
            sum(
                item["inventory_split_v0"] in {"development", "held_out"}
                and item["group_assignment"] == "excluded"
                for item in report["excluded"]
            ),
            16,
        )
        self.assertEqual(
            sum(
                item["group_assignment"] in {"development", "held_out"}
                for item in report["excluded"]
            ),
            3,
        )

    def test_inventory_split_column_is_not_an_assignment_input(self):
        expected, _ = build_manifests()
        with INVENTORY.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        for row in rows:
            row["split"] = "held_out"
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "inventory.csv"
            with inventory.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            actual, _ = build_manifests(inventory)
        self.assertEqual(actual, expected)

    def test_committed_manifests_validate_and_match_generator(self):
        manifests, report = build_manifests()
        directory = ROOT / "experiments/pairs"
        self.assertEqual(json.loads((directory / "index.json").read_text(encoding="utf-8")), report)
        for manifest in manifests:
            self.assertEqual(
                json.loads((directory / f"{manifest['pair_id']}.json").read_text(encoding="utf-8")),
                manifest,
            )
        self.assertEqual(len(list(directory.glob("secbench-*.json"))), 34)
        self.assertEqual(len(list(directory.glob("pyvul-*.json"))), 17)
        self.assertIn("sink_hint", json.loads(SCHEMA.read_text())["properties"])


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


class PatchTests(unittest.TestCase):
    def test_modified_lines_exclude_context_and_insertions(self):
        result = diff_files(
            {"a.py": b"one\ntwo\nthree\nfour\n"}, {"a.py": b"one\nchanged\ninserted\nthree\nfour\n"}
        )
        changes = result["files"][0]["hunks"][0]["changes"]
        self.assertEqual([line for change in changes for line in change["old_lines"]], [2])

    def test_exact_content_renames_are_detected_without_guessing_ambiguous_ones(self):
        result = diff_files({"old.py": b"identical"}, {"new.py": b"identical"})
        self.assertEqual(result["renames"][0]["old_path"], "old.py")
        self.assertEqual(result["files"], [])
        ambiguous = diff_files({"one.py": b"same", "two.py": b"same"}, {"new.py": b"same"})
        self.assertEqual(ambiguous["renames"], [])
        self.assertEqual(len(ambiguous["rename_ambiguities"]), 1)
        self.assertEqual(len(ambiguous["files"]), 3)

    def test_skipped_files_are_auditable_and_binary_changes_are_preserved_as_skips(self):
        data = archive_bytes(
            {
                "src/app.py": b"code",
                "tests/a.py": b"test",
                "docs/guide.txt": b"doc",
                "README.md": b"doc",
                "package-lock.json": b"lock",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.tgz"
            path.write_bytes(data)
            files, ignored = read_snapshot(path)
        self.assertEqual(set(files), {"src/app.py"})
        self.assertEqual(len(ignored), 4)
        self.assertEqual(exclusion_reason("src/app.test.js"), "test_file")
        result = diff_files({"image.png": b"\x00old"}, {"image.png": b"\x00new"})
        self.assertEqual(result["skipped_changes"][0]["reason"], "binary_or_non_utf8")

    def test_hostile_archives_are_rejected_even_under_skipped_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.tgz"
            path.write_bytes(archive_bytes({"docs/../../escape": b"bad"}))
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                read_snapshot(path)


class KnownLocationTests(unittest.TestCase):
    def manifest(self):
        return {
            "sink_hint": "a.js:2:1",
            "reference_provenance": ["dataset:fixed-commit"],
            "os_command_execution_basis": "published hint",
            "fix_commit": "a" * 40,
        }

    def test_javascript_parser_resolves_aliases_and_ignores_shadowed_or_fake_calls(self):
        source = (
            "const {exec: run} = require('node:child_process');\nrun(input);\n"
            "function f(run) { run(other); }\nconst text = 'run(cmd)';\n// run(fake);\n"
        )
        output = locate_javascript("a.js", source)
        self.assertEqual(len(output["sinks"]), 1)
        self.assertEqual(output["sinks"][0]["sink_kind"], "child_process.exec")
        locations, unresolved, _ = resolve_secbench(self.manifest(), {"a.js": source.encode()})
        self.assertEqual(len(locations), 1)
        self.assertEqual(unresolved, [])

    def test_javascript_hint_mismatch_or_callback_location_remains_unresolved(self):
        source = (
            "const exec = require('child_process').exec;\n"
            "exec(cmd, () => {\n  const value = 1;\n});\n"
        )
        manifest = self.manifest()
        manifest["sink_hint"] = "a.js:3:3"
        locations, unresolved, _ = resolve_secbench(manifest, {"a.js": source.encode()})
        self.assertEqual(locations, [])
        self.assertEqual(unresolved[0]["status"], "known_location_unresolved")

    def test_pyvul_uses_changed_lines_and_exact_function_labels(self):
        old = "import os\ndef first():\n    os.system(a)\ndef second():\n    os.system(b)\n"
        fixed = old.replace("system(a)", "system(c)").replace("system(b)", "system(d)")
        hunks = diff_files({"a.py": old.encode()}, {"a.py": fixed.encode()})
        segment = "def first():\n    os.system(a)"
        labels = [
            {
                "function_name": "first",
                "normalized_code_before_sha256": hashlib.sha256(
                    textwrap.dedent(segment).strip().encode()
                ).hexdigest(),
            }
        ]
        locations, unresolved, metadata = resolve_pyvul(
            self.manifest(), {"a.py": old.encode()}, hunks, labels=labels
        )
        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0]["span"]["startLine"], 3)
        self.assertEqual(unresolved, [])
        self.assertEqual(len(metadata["excluded_by_function_labels"]), 1)

    def test_unchanged_sink_in_patch_context_is_not_a_known_location(self):
        old = b"import os\nvalue = 1\nos.system(cmd)\n"
        hunks = diff_files({"a.py": old}, {"a.py": old.replace(b"value = 1", b"value = 2")})
        locations, unresolved, _ = resolve_pyvul(self.manifest(), {"a.py": old}, hunks)
        self.assertEqual(locations, [])
        self.assertEqual(unresolved[0]["status"], "known_location_unresolved")

    def test_parse_failure_is_counted_instead_of_dropped(self):
        old = b"def broken(\n"
        hunks = diff_files({"a.py": old}, {"a.py": b"def valid(): pass\n"})
        locations, unresolved, _ = resolve_pyvul(self.manifest(), {"a.py": old}, hunks)
        self.assertEqual(locations, [])
        self.assertTrue(any("could not parse" in item["reason"] for item in unresolved))

    def test_recorded_three_development_results_have_provenance(self):
        pairs = {
            "pyvul-dwisiswant0-apkleaks-a966e781499f": ("apkleaks/apkleaks.py", 88, "os.system"),
            "secbench-diskusage-ng-0.2.6": ("lib/posix.js", 11, "child_process.exec"),
            "secbench-dns-sync-0.1.0": ("lib/dns-sync.js", 21, "shelljs.exec"),
        }
        for pair_id, (path, line, kind) in pairs.items():
            directory = ROOT / "experiments/pairs" / pair_id
            result = json.loads((directory / "known-locations.json").read_text())
            self.assertEqual(result["status"], "resolved")
            self.assertEqual(result["scanner_invocations"], 0)
            self.assertEqual(result["resolved_location_count"], 1)
            self.assertEqual(result["unresolved_case_count"], 0)
            self.assertEqual(result["patch_hunks_sha256"], sha256(directory / "patch-hunks.json"))
            location = result["locations"][0]
            self.assertEqual(
                (location["path"], location["span"]["startLine"], location["sink_kind"]),
                (path, line, kind),
            )
            self.assertTrue(location["provenance"]["references"])


if __name__ == "__main__":
    unittest.main()
