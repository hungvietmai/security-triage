"""Thin-CLI gates and provenance checks; no scanners or network required."""

import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
for _IMPORT_ROOT in (_ROOT, _BACKEND):
    if str(_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_IMPORT_ROOT))

from app.scanners.acquisition import (
    MAX_ARCHIVE,
    MAX_FILES,
    MAX_UNPACKED,
    AcquiredSource,
    unpack,
    verify_source_identity,
)
from app.scanners.codeql import query_pack_for_language
from app.scanners.pipeline import PipelineResult
from app.scanners.sarif import sarif_findings
from app.scanners.semgrep import stage_rule

from experiments import run_batch, run_pilot
from experiments.run_pilot import (
    ROOT,
    _assert_finding_conservation,
    digest,
    runner_files_sha256,
)


class RunnerTests(unittest.TestCase):
    def test_run_batch_compatibility_exports_remain_available(self):
        self.assertIs(run_batch.ROOT, ROOT)
        self.assertTrue(callable(run_batch.digest))
        self.assertTrue(callable(run_batch.write_json))

    def test_runner_files_hash_cli_and_every_scanner_module(self):
        hashes = runner_files_sha256()
        expected = {
            "experiments/run_pilot.py",
            "experiments/locators/sink-locator-v0-javascript.yaml",
            "experiments/policy/priority-v0.1.yaml",
            "experiments/policy/PRIORITY_V0_1.md",
            "experiments/mappings/rule-claims-v2.json",
            *{
                str(path.relative_to(ROOT))
                for path in (ROOT / "backend/app/scanners").glob("*.py")
            },
            *{
                str(path.relative_to(ROOT))
                for path in (ROOT / "backend/app/triage").glob("*.py")
            },
        }
        self.assertEqual(set(hashes), expected)
        for relative, expected_hash in hashes.items():
            self.assertEqual(expected_hash, digest(ROOT / relative))
        self.assertNotIn("runner_sha256", hashes)

    def test_finding_conservation_accepts_one_cross_tool_unit(self):
        findings = [
            {"raw_id": "codeql:0:0"},
            {"raw_id": "semgrep:0:0"},
        ]
        units = [
            {
                "raw_finding_ids": ["codeql:0:0", "semgrep:0:0"],
                "tools": ["codeql", "semgrep"],
            }
        ]
        _assert_finding_conservation(findings, units)

    def test_finding_conservation_rejects_loss_or_duplication(self):
        findings = [
            {"raw_id": "codeql:0:0"},
            {"raw_id": "semgrep:0:0"},
        ]
        bad_units = [
            [{"raw_finding_ids": ["codeql:0:0"]}],
            [
                {
                    "raw_finding_ids": [
                        "codeql:0:0",
                        "semgrep:0:0",
                        "semgrep:0:0",
                    ]
                }
            ],
        ]
        for units in bad_units:
            with (
                self.subTest(units=units),
                self.assertRaisesRegex(RuntimeError, "finding conservation failed"),
            ):
                _assert_finding_conservation(findings, units)

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
                "artifact_url": "https://codeload.github.com/org/fixture/tar.gz/"
                + commit,
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
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    verify_source_identity({**case, field: value}, root)

    def test_language_selects_its_own_query_pack(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            javascript = root / "javascript"
            python = root / "python"
            javascript.mkdir()
            python.mkdir()
            self.assertEqual(
                query_pack_for_language(
                    "javascript",
                    javascript_query_pack=javascript,
                    python_query_pack=python,
                ),
                javascript.resolve(),
            )
            self.assertEqual(
                query_pack_for_language(
                    "python",
                    javascript_query_pack=javascript,
                    python_query_pack=python,
                ),
                python.resolve(),
            )
            self.assertNotEqual(javascript.resolve(), python.resolve())

    def test_failed_pipeline_is_not_clean_scan(self):
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
                snapshot_sha256="f" * 64,
                source_files=["index.js"],
                transport="verified_local_archive",
                seconds=0.1,
            )
            failed = PipelineResult(
                status="failed",
                steps={"codeql": {"status": "failed", "error": "fixture failure"}},
                findings=[],
                codeql_query_files=None,
                codeql_pack_manifest=None,
            )
            argv = [
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "c" * 40,
            ]

            def fake_acquire(case_value, output_value, *, source_archive, limits):
                return acquired

            def fake_pipeline(**kwargs):
                return failed

            self.assertEqual(
                run_pilot.main(
                    argv,
                    acquire_source_fn=fake_acquire,
                    run_pipeline_fn=fake_pipeline,
                    print_fn=lambda _: None,
                ),
                2,
            )
            report = json.loads((output / "run.json").read_text())
            findings = json.loads((output / "findings.json").read_text())
            units = json.loads((output / "units.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["raw_findings"], 0)
            self.assertEqual(report["steps"]["codeql"]["status"], "failed")
            self.assertEqual(report["steps"]["codeql"]["error"], "fixture failure")
            self.assertEqual(findings, [])
            self.assertEqual(units, [])

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
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]
            with self.assertRaises(SystemExit):
                run_pilot.main(argv, print_fn=lambda _: None)
            self.assertFalse(output.exists())

    def test_rejects_invalid_configuration_commit_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case = ROOT / "experiments/cases/secbench-curling-0.2.0.json"
            config = ROOT / "experiments/configs/development-smoke-javascript.json"
            output = root / "out"
            argv = [
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "not-a-commit",
            ]
            with self.assertRaises(SystemExit):
                run_pilot.main(argv, print_fn=lambda _: None)
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
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]
            with self.assertRaises(SystemExit):
                run_pilot.main(argv, print_fn=lambda _: None)
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
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
            ]

            def fail_acquisition(*args, **kwargs):
                raise ValueError("fixture acquisition stop")

            self.assertEqual(
                run_pilot.main(
                    argv,
                    acquire_source_fn=fail_acquisition,
                    print_fn=lambda _: None,
                ),
                2,
            )
            report = json.loads((output / "run.json").read_text())
            self.assertEqual((output / "case.json").read_bytes(), case_bytes)
            self.assertEqual((output / "config.json").read_bytes(), config_bytes)
            self.assertEqual(
                report["case_manifest_sha256"], digest(output / "case.json")
            )
            self.assertEqual(
                report["configuration_sha256"], digest(output / "config.json")
            )
            self.assertEqual(report["runner_files_sha256"], runner_files_sha256())
            self.assertNotIn("runner_sha256", report)
            self.assertEqual(report["error"], "fixture acquisition stop")
            self.assertEqual(json.loads((output / "units.json").read_text()), [])

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
                "--case",
                str(case),
                "--config",
                str(config),
                "--output",
                str(output),
                "--configuration-commit",
                "b" * 40,
                "--semgrep",
                "/tools/semgrep",
                "--codeql",
                "/tools/codeql",
                "--javascript-query-pack",
                str(root / "js-pack"),
            ]
            acquisition_calls = []
            pipeline_calls = []
            locator_calls = []
            reconcile_calls = []
            printed = []
            unit = {
                "unit_id": "u" * 64,
                "snapshot_sha256": "d" * 64,
                "path": "index.js",
                "sink_span": {
                    "startLine": 1,
                    "startColumn": 1,
                    "endLine": 1,
                    "endColumn": 10,
                },
                "reported_region": None,
                "argument_role": "shell_command",
                "sink_kind": "child_process.exec",
                "callee": "exec",
                "mapping_status": "mapped",
                "raw_finding_ids": ["codeql:0:0"],
                "tools": ["codeql"],
                "mappings": [
                    {
                        "raw_id": "codeql:0:0",
                        "tool": "codeql",
                        "mapping_status": "mapped",
                        "mapping_method": "explicit_link",
                    }
                ],
            }

            def fake_acquire(case_value, output_value, *, source_archive, limits):
                acquisition_calls.append(
                    {
                        "case": case_value,
                        "output": output_value,
                        "source_archive": source_archive,
                        "limits": limits,
                    }
                )
                return acquired

            def fake_pipeline(**kwargs):
                pipeline_calls.append(kwargs)
                return result

            def fake_locator(**kwargs):
                locator_calls.append(kwargs)
                return (
                    [],
                    {"index.js": "exec(command);\n"},
                    {"status": "completed", "raw_findings": 0},
                )

            def fake_reconcile(findings_value, sinks_value, sources_value):
                reconcile_calls.append((findings_value, sinks_value, sources_value))
                return [unit]

            self.assertEqual(
                run_pilot.main(
                    argv,
                    acquire_source_fn=fake_acquire,
                    run_pipeline_fn=fake_pipeline,
                    locate_sinks_fn=fake_locator,
                    reconcile_fn=fake_reconcile,
                    print_fn=printed.append,
                ),
                0,
            )

            self.assertEqual(len(acquisition_calls), 1)
            self.assertEqual(len(pipeline_calls), 1)
            self.assertEqual(len(locator_calls), 1)
            self.assertEqual(len(reconcile_calls), 1)
            acquire_call = acquisition_calls[0]
            pipeline_call = pipeline_calls[0]
            locator_call = locator_calls[0]
            self.assertEqual(acquire_call["case"], case_data)
            self.assertEqual(acquire_call["output"], output.resolve())
            self.assertIsNone(acquire_call["source_archive"])
            self.assertEqual(acquire_call["limits"].max_archive_bytes, MAX_ARCHIVE)
            self.assertEqual(acquire_call["limits"].max_unpacked_bytes, MAX_UNPACKED)
            self.assertEqual(acquire_call["limits"].max_files, MAX_FILES)
            self.assertEqual(pipeline_call["source"], source)
            self.assertEqual(pipeline_call["snapshot_sha256"], "d" * 64)
            self.assertEqual(pipeline_call["repository_root"], ROOT)
            self.assertEqual(pipeline_call["semgrep_binary"], "/tools/semgrep")
            self.assertEqual(pipeline_call["codeql_binary"], "/tools/codeql")
            self.assertEqual(
                pipeline_call["javascript_query_pack"],
                root / "js-pack",
            )
            self.assertEqual(pipeline_call["codeql_ram_mb"], 2048)
            self.assertEqual(locator_call["language"], "javascript")
            self.assertEqual(locator_call["source"], source)
            self.assertEqual(locator_call["source_files"], ["index.js"])
            self.assertEqual(locator_call["semgrep_binary"], "/tools/semgrep")
            self.assertEqual(reconcile_calls[0][0], [finding])
            self.assertEqual(reconcile_calls[0][1], [])
            self.assertEqual(reconcile_calls[0][2], {"index.js": "exec(command);\n"})
            self.assertEqual(len(printed), 1)

            report = json.loads((output / "run.json").read_text())
            findings = json.loads((output / "findings.json").read_text())
            units = json.loads((output / "units.json").read_text())
            assessments = json.loads((output / "assessments.json").read_text())
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["raw_findings"], 1)
            self.assertEqual(report["snapshot_sha256"], "d" * 64)
            self.assertEqual(report["codeql_query_files"], {"query.ql": "e" * 64})
            self.assertEqual(findings, [finding])
            self.assertEqual(units, [unit])
            self.assertEqual(len(assessments), 1)
            self.assertEqual(assessments[0]["priority"], "U")
            self.assertEqual(report["sink_count"], 0)
            self.assertEqual(report["unit_count"], 1)
            self.assertEqual(report["mapping_version"], "reconcile-v0.1")
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
