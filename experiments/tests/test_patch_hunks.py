"""Focused regressions for PatchTests."""

from __future__ import annotations

# Direct unittest discovery bootstraps the repository and shared backend imports.
# ruff: noqa: E402
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
import tempfile

from experiments.patch_hunks import diff_files, exclusion_reason, read_snapshot
from experiments.tests.archive_fixtures import archive_bytes


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


if __name__ == "__main__":
    unittest.main()
