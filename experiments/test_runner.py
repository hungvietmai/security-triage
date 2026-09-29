"""Safety and lossless-ingestion checks; no scanners or network required."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments import run_pilot
from experiments.run_pilot import ROOT, digest, sarif_findings, stage_rule, unpack


class RunnerTests(unittest.TestCase):
    def test_missing_sarif_preserves_process_diagnostics(self):
        for process_status, exit_code in (("failed", 2), ("timeout", None)):
            with (
                self.subTest(process_status=process_status),
                tempfile.TemporaryDirectory() as folder,
            ):
                root = Path(folder)
                archive = root / "package.tgz"
                with tarfile.open(archive, "w:gz") as bundle:
                    data = b'{"name":"fixture","version":"1.0.0"}'
                    entry = tarfile.TarInfo("package/package.json")
                    entry.size = len(data)
                    bundle.addfile(entry, io.BytesIO(data))
                case = root / "case.json"
                case.write_text(
                    json.dumps(
                        {
                            "case_id": "fixture",
                            "split": "development",
                            "source_kind": "npm_tarball",
                            "language": "javascript",
                            "artifact_sha256": digest(archive),
                            "archive_root": "package",
                            "package_name": "fixture",
                            "package_version": "1.0.0",
                        }
                    )
                )
                config = ROOT / "experiments/configs/development-semgrep-upstream.json"
                output = root / "run"
                args = [
                    "run_pilot",
                    "--case",
                    str(case),
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                    "--configuration-commit",
                    "a" * 40,
                    "--source-archive",
                    str(archive),
                ]
                record = {
                    "argv": ["scanner", "scan"],
                    "status": process_status,
                    "exit_code": exit_code,
                    "seconds": 1.25,
                }
                with (
                    patch("sys.argv", args),
                    patch.object(run_pilot, "tool_version"),
                    patch.object(run_pilot, "invoke", return_value=record),
                    patch("builtins.print"),
                ):
                    self.assertEqual(run_pilot.main(), 2)
                report = json.loads((output / "run.json").read_text())
                failure = report["steps"]["semgrep"]
                self.assertEqual(report["status"], "partial")
                self.assertEqual(failure["status"], process_status)
                self.assertEqual(failure["exit_code"], exit_code)
                self.assertEqual(failure["argv"], ["scanner", "scan"])
                self.assertEqual(failure["seconds"], 1.25)
                self.assertIn("no SARIF", failure["error"])
                self.assertNotIn("raw_findings", failure)

    def test_local_rule_is_verified_before_copy(self):
        rule = ROOT / "experiments/rules/detect-child-process-upstream.yaml"
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "rule.yaml"
            spec = {"path": str(rule.relative_to(ROOT)), "sha256": digest(rule)}
            stage_rule(spec, target)
            self.assertEqual(target.read_bytes(), rule.read_bytes())
            target.unlink()
            spec["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                stage_rule(spec, target)
            self.assertFalse(target.exists())

    def test_local_rule_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "rule.yaml"
            with self.assertRaisesRegex(ValueError, "inside repository"):
                stage_rule({"path": "../outside.yaml", "sha256": "0" * 64}, target)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                stage_rule({"path": "rule.yaml", "url": "https://example.org"}, target)

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
                unpack(
                    self.archive(root, "package/../../escape"), root / "out", "package"
                )
            self.assertFalse((root / "escape").exists())

    def test_rejects_links(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with self.assertRaises(ValueError):
                    unpack(
                        self.archive(root, "package/link", kind),
                        root / "out",
                        "package",
                    )

    def test_extracts_regular_file_without_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = unpack(
                self.archive(root, "package/install.sh"), root / "out", "package"
            )
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
                                                "properties": {
                                                    "tags": ["external/cwe/cwe-078"]
                                                },
                                            }
                                        ]
                                    }
                                },
                                "results": [
                                    {
                                        "ruleIndex": 0,
                                        "message": {"text": "no location"},
                                    },
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
                        "runs": [
                            {
                                "invocations": [{"executionSuccessful": False}],
                                "results": [],
                            }
                        ],
                    }
                )
            )
            rows, complete = sarif_findings(path, "codeql", "snapshot")
            self.assertEqual(rows, [])
            self.assertFalse(complete)

    def test_informational_notifications_do_not_make_scan_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.sarif"
            path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "invocations": [
                                    {
                                        "executionSuccessful": True,
                                        "toolExecutionNotifications": [
                                            {
                                                "level": "none",
                                                "message": {"text": "coverage"},
                                            }
                                        ],
                                    }
                                ],
                                "results": [],
                            }
                        ],
                    }
                )
            )
            _, complete = sarif_findings(path, "codeql", "snapshot")
            self.assertTrue(complete)


if __name__ == "__main__":
    unittest.main()
