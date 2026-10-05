"""Thin-CLI gates and provenance checks; no scanners or network required."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.scanners.acquisition import (
    MAX_FILES,
    MAX_UNPACKED,
    AcquiredSource,
    unpack,
    verify_source_identity,
)
from app.scanners.pipeline import PipelineResult
from app.scanners.sarif import sarif_findings
from app.scanners.semgrep import stage_rule
from experiments import run_batch, run_pilot
from experiments.run_pilot import ROOT, digest, runner_files_sha256


class RunnerTests(unittest.TestCase):
    def test_run_batch_compatibility_exports_remain_available(self):
        self.assertIs(run_batch.ROOT, ROOT)
        self.assertTrue(callable(run_batch.digest))
        self.assertTrue(callable(run_batch.write_json))

    def test_runner_files_hash_cli_and_every_scanner_module(self):
        hashes = runner_files_sha256()
        expected = {
            "experiments/run_pilot.py",
            *{
                str(path.relative_to(ROOT))
                for path in (ROOT / "backend/app/scanners").glob("*.py")
            },
        }
        self.assertEqual(set(hashes), expected)
        for relative, expected_hash in hashes.items():
            self.assertEqual(expected_hash, digest(ROOT / relative))
        self.assertNotIn("runner_sha256", hashes)

    def test_github_identity_is_pinned_and_verified_without_package_json(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("raise RuntimeError('never execute')\n")
            commit = "a" * 40
            case = {
                "source_kind": "github_tarball",
                "repository": "org/fixture",
                "source_commit": commit,
                "archive_root": "fixture-" + commit,
                "artifact_url": "https://codeload.github.com/org/fixture/tar.gz/" + commit,
                "identity_files_sha256": {"app.py": digest(root / "app.py")},
            }
            verify_source_identity(case, root)
            for field, value in (
                ("source_commit", "main"),
                ("artifact_url", "https://codeload.github.com/org/fixture/tar.gz/main"),
                ("archive_root", "fixture-main"),
                ("identity_files_sha256", {"app.py": "0" * 64}),
                ("identity_files_sha256", {"../outside": "0" * 64}),
                ("identity_files_sha256", {}),
            ):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    verify_source_identity({**case, field: value}, root)

    def test_python_rejects_javascript_configuration_before_scanning(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case = root / "case.json"
            case.write_text(
                json.dumps(
                    {
                        "split": "development",
                        "source_kind": "github_tarball",
                        "language": "python",
                    }
                )
            )
            config = ROOT / "experiments/configs/development-batch-01-upstream.json"
            output = root / "out"
            argv = [
                "run_pilot",
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]
            with patch("sys.argv", argv), patch("sys.stderr"), self.assertRaises(SystemExit):
                run_pilot.main()
            self.assertFalse(output.exists())

    def test_rejects_invalid_configuration_commit_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case = ROOT / "experiments/cases/secbench-curling-0.2.0.json"
            config = ROOT / "experiments/configs/development-smoke-javascript.json"
            output = root / "out"
            argv = [
                "run_pilot",
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "not-a-commit",
            ]
            with patch("sys.argv", argv), patch("sys.stderr"), self.assertRaises(SystemExit):
                run_pilot.main()
            self.assertFalse(output.exists())

    def test_rejects_held_out_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = json.loads(
                (ROOT / "experiments/cases/secbench-curling-0.2.0.json").read_text()
            )
            source["split"] = "held_out"
            case = root / "case.json"
            case.write_text(json.dumps(source))
            config = ROOT / "experiments/configs/development-smoke-javascript.json"
            output = root / "out"
            argv = [
                "run_pilot",
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]
            with patch("sys.argv", argv), patch("sys.stderr"), self.assertRaises(SystemExit):
                run_pilot.main()
            self.assertFalse(output.exists())

    def test_retained_manifest_bytes_and_runner_file_provenance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source_case = {
                "case_id": "fixture",
                "split": "development",
                "source_kind": "npm_tarball",
                "language": "javascript",
            }
            source_config = {
                "scanners": [],
                "config_id": "fixture",
                "purpose": "test",
                "protocol_commit": "a" * 40,
            }
            case = root / "case.json"
            config = root / "config.json"
            output = root / "out"
            case_bytes = (
                json.dumps(source_case, separators=(",", ":")).encode() + b"\r\n \r\n"
            )
            config_bytes = json.dumps(source_config, indent=4).encode() + b"\n\n"
            case.write_bytes(case_bytes)
            config.write_bytes(config_bytes)
            argv = [
                "run_pilot",
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]
            with patch("sys.argv", argv), patch("builtins.print"):
                self.assertEqual(run_pilot.main(), 2)
            report = json.loads((output / "run.json").read_text())
            self.assertEqual((output / "case.json").read_bytes(), case_bytes)
            self.assertEqual((output / "config.json").read_bytes(), config_bytes)
            self.assertEqual(report["case_manifest_sha256"], digest(output / "case.json"))
            self.assertEqual(report["configuration_sha256"], digest(output / "config.json"))
            self.assertEqual(report["runner_files_sha256"], runner_files_sha256())
            self.assertNotIn("runner_sha256", report)

    def test_cli_delegates_and_writes_all_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case_data = json.loads(
                (ROOT / "experiments/cases/secbench-curling-0.2.0.json").read_text()
            )
            case = root / "case.json"
            case.write_text(json.dumps(case_data))
            config = ROOT / "experiments/configs/development-smoke-javascript.json"
            output = root / "out"
            source = root / "source"
            source.mkdir()
            acquired = AcquiredSource(
                source_path=source,
                archive_path=output / "source.tgz",
                snapshot_sha256="d" * 64,
                source_files=["index.js"],
                transport="verified_local_archive",
                seconds=0.25,
            )
            finding = {
                "raw_id": "codeql:0:0",
                "tool": "codeql",
                "snapshot_sha256": "d" * 64,
                "rule_id": "js/command-line-injection",
                "reported_path": "index.js",
                "reported_region": {"startLine": 1},
                "reported_cwes": ["CWE-78"],
                "message": "candidate",
                "sink_identity": None,
                "mapping_status": "unresolved",
                "technical_verdict": "unresolved",
                "scope_verdict": "unresolved",
                "raw_result": {},
            }
            result = PipelineResult(
                status="completed",
                steps={"codeql": {"status": "completed", "raw_findings": 1}},
                findings=[finding],
                codeql_query_files={"query.ql": "e" * 64},
                codeql_pack_manifest="name: test\n",
            )
            argv = [
                "run_pilot",
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]
            with (
                patch("sys.argv", argv),
                patch.object(run_pilot, "acquire_source", return_value=acquired) as acquire,
                patch.object(run_pilot, "run_pipeline", return_value=result) as pipeline,
                patch("builtins.print"),
            ):
                self.assertEqual(run_pilot.main(), 0)

            acquire.assert_called_once()
            pipeline.assert_called_once()
            report = json.loads((output / "run.json").read_text())
            findings = json.loads((output / "findings.json").read_text())
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["raw_findings"], 1)
            self.assertEqual(report["snapshot_sha256"], "d" * 64)
            self.assertEqual(report["codeql_query_files"], {"query.ql": "e" * 64})
            self.assertEqual(findings, [finding])
            self.assertTrue((output / "findings.csv").is_file())

    def test_local_rule_is_verified_before_copy(self):
        rule = ROOT / "experiments/rules/detect-child-process-upstream.yaml"
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "rule.yaml"
            spec = {"path": str(rule.relative_to(ROOT)), "sha256": digest(rule)}
            stage_rule(spec, target, repository_root=ROOT)
            self.assertEqual(target.read_bytes(), rule.read_bytes())
            target.unlink()
            spec["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                stage_rule(spec, target, repository_root=ROOT)
            self.assertFalse(target.exists())

    def archive(self, root, name, kind=None):
        path = root / "input.tgz"
        with tarfile.open(path, "w:gz") as bundle:
            entry = tarfile.TarInfo(name)
            if kind:
                entry.type, entry.linkname = kind, "/etc/passwd"
                bundle.addfile(entry)
            else:
                data = b"source text"
                entry.size = len(data)
                bundle.addfile(entry, io.BytesIO(data))
        return path

    def test_rejects_parent_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(ValueError):
                unpack(
                    self.archive(root, "package/../../escape"),
                    root / "out",
                    "package",
                    max_unpacked_bytes=MAX_UNPACKED,
                    max_files=MAX_FILES,
                )
            self.assertFalse((root / "escape").exists())
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with self.assertRaises(ValueError):
                    unpack(
                        self.archive(root, "package/link", kind),
                        root / "out",
                        "package",
                        max_unpacked_bytes=MAX_UNPACKED,
                        max_files=MAX_FILES,
                    )

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
            self.assertEqual(rows[1]["reported_path"], "a.js")


if __name__ == "__main__":
    unittest.main()
