"""Safety and lossless-ingestion checks; no scanners or network required."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from experiments.run_pilot import sarif_findings, unpack


class RunnerTests(unittest.TestCase):
    def archive(self, root, name, kind=None):
        p = root / "input.tgz"
        with tarfile.open(p, "w:gz") as bundle:
            entry = tarfile.TarInfo(name)
            if kind:
                entry.type, entry.linkname = kind, "/etc/passwd"
                bundle.addfile(entry)
            else:
                data = b"source text"
                entry.size = len(data)
                bundle.addfile(entry, io.BytesIO(data))
        return p

    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(ValueError):
                unpack(self.archive(root, "package/../../escape"), root / "out", "package")
            self.assertFalse((root / "escape").exists())

    def test_rejects_links(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with self.assertRaises(ValueError):
                    unpack(self.archive(root, "package/link", kind), root / "out", "package")

    def test_extracts_regular_file_without_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = unpack(self.archive(root, "package/install.sh"), root / "out", "package")
            self.assertEqual((source / "install.sh").read_text(), "source text")
            self.assertFalse((source / "install.sh").stat().st_mode & 0o111)

    def test_missing_location_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.sarif"
            path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "rules": [
                                            {
                                                "id": "r",
                                                "properties": {"tags": ["external/cwe/cwe-078"]},
                                            }
                                        ]
                                    }
                                },
                                "results": [
                                    {"ruleIndex": 0, "message": {"text": "no location"}},
                                    {
                                        "ruleId": "r",
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "a.js"},
                                                    "region": {"startLine": 3},
                                                }
                                            }
                                        ],
                                    },
                                ],
                            }
                        ],
                    }
                )
            )
            rows, complete = sarif_findings(path, "semgrep", "snapshot")
            self.assertTrue(complete)
            self.assertEqual(len(rows), 2)
            self.assertIsNone(rows[0]["reported_path"])
            self.assertEqual(rows[0]["rule_id"], "r")
            self.assertEqual(rows[0]["mapping_status"], "unresolved")
            self.assertEqual(rows[1]["reported_path"], "a.js")

    def test_failed_invocation_is_not_clean_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.sarif"
            path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [{"invocations": [{"executionSuccessful": False}], "results": []}],
                    }
                )
            )
            rows, complete = sarif_findings(path, "codeql", "snapshot")
            self.assertEqual(rows, [])
            self.assertFalse(complete)


if __name__ == "__main__":
    unittest.main()
