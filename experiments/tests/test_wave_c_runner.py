"""Runner workflows with synthetic source and stubbed external CodeQL/Git/HTTP boundaries."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
WAVE = ROOT / "experiments/wave-c"
sys.path.insert(0, str(WAVE))
SPEC = importlib.util.spec_from_file_location("wave_c_runner", WAVE / "run.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class WaveCRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        archive = self.root / "synthetic.tgz"
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo("synthetic/app.py")
            data = b"raise RuntimeError('synthetic input must not execute')\n"
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
        self.source = {
            "rank": 1,
            "repository": "synthetic/repo",
            "commit": "a" * 40,
            "archive_root": "synthetic",
            "objects": {
                "archive": {
                    "path": archive.name,
                    "sha256": RUNNER.file_digest(archive),
                    "size_bytes": archive.stat().st_size,
                }
            },
            "archive_inventory": {"python_files": ["app.py"]},
        }
        self.toolchain = {
            "cli": "codeql",
            "cache": "cache",
            "packs": {"v02": "v02", "v03": "v03", "diagnostics": "diagnostics"},
        }
        self.called = []
        self.fail_task = None

    def execute(self, argv, directory, name, timeout, commands):
        self.called.append(name)
        commands.append({"argv": argv, "status": "ok", "timeout": timeout})
        if name == self.fail_task:
            raise RUNNER.CommandFailure("synthetic CodeQL failure")
        if name in RUNNER.MODES:
            (directory / f"{name}.sarif").write_text(
                json.dumps({"version": "2.1.0", "runs": [{"results": []}]}), encoding="utf-8"
            )
        elif name in RUNNER.DIAGNOSTICS:
            bqrs = directory / "database/results/synthetic" / (RUNNER.DIAGNOSTICS[name] + ".bqrs")
            bqrs.parent.mkdir(parents=True, exist_ok=True)
            bqrs.write_bytes(b"synthetic external CLI output")
        elif name.startswith("decode_"):
            key = name.removeprefix("decode_")
            path = Path(
                next(a.removeprefix("--output=") for a in argv if a.startswith("--output="))
            )
            fields = {
                "contracts": ["file", "line", "col", "kind", "root", "detail"],
                "evidence": ["file", "line", "col", "root", "basis", "source", "level"],
                "resources": ["file", "name", "root", "detail"],
                "summaries": ["kind", "file", "line", "scope", "detail"],
                "extracted": ["file"],
            }[key]
            with path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(fields)
                if key == "extracted":
                    writer.writerow(["app.py"])

    def run_snapshot(self, directory="run", deadline=None):
        return RUNNER.run_snapshot(
            self.root,
            self.source,
            self.toolchain,
            self.root / directory,
            deadline if deadline is not None else time.monotonic() + 100,
            execute=self.execute,
        )

    def test_complete_zero_alert_retains_all_outputs_and_extraction_coverage(self):
        result = self.run_snapshot()
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["zero_alert"])
        self.assertEqual(result["extraction"]["missing_python"], [])
        self.assertEqual(set(result["files"]), set(RUNNER.MODES) | set(RUNNER.DIAGNOSTICS))
        self.assertTrue(all((self.root / name).is_file() for name in result["files"].values()))
        plan = RUNNER.commands_for(self.root, self.source, self.toolchain, self.root / "planned")
        for task in plan[1:]:
            self.assertIn("--rerun", task["argv"])
            self.assertIn("--threads=2", task["argv"])
            self.assertIn("--ram=5000", task["argv"])
        self.assertNotIn("--command", plan[0]["argv"])

    def test_failure_and_budget_do_not_become_empty_successful_scans(self):
        self.fail_task = "all"
        failed = self.run_snapshot()
        self.assertEqual(failed["status"], "run_failed")
        self.assertNotIn("zero_alert", failed)
        self.assertNotIn("v03", self.called)
        self.called.clear()
        exhausted = self.run_snapshot("budget", time.monotonic() - 1)
        self.assertEqual(exhausted["status"], "budget_exhausted")
        self.assertEqual(self.called, [])
        self.assertTrue((self.root / "budget/snapshot.json").exists())

    def test_partial_extraction_is_preserved_as_incomplete(self):
        self.source["archive_inventory"]["python_files"].append("not-extracted.py")
        result = self.run_snapshot()
        self.assertEqual(result["status"], "incomplete_extraction")
        self.assertEqual(result["extraction"]["missing_python"], ["not-extracted.py"])
        self.assertTrue(result["files"])

    def test_process_timeout_preserves_command_and_stream_logs(self):
        directory = self.root / "timeout"
        directory.mkdir()
        commands = []
        with self.assertRaises(RUNNER.CommandFailure):
            RUNNER.invoke(
                [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(10)"],
                directory,
                "timed",
                0.2,
                commands,
            )
        recorded = json.loads((directory / "commands.json").read_bytes())[0]
        self.assertEqual(recorded["status"], "timed_out")
        self.assertIn("started", (directory / "timed.stdout.log").read_text())

    def test_missing_executable_preserves_launch_failure_record(self):
        directory = self.root / "launch-failure"
        directory.mkdir()
        with self.assertRaises(RUNNER.CommandFailure):
            RUNNER.invoke([str(self.root / "not-an-executable")], directory, "missing", 1, [])
        recorded = json.loads((directory / "commands.json").read_bytes())[0]
        self.assertEqual(recorded["status"], "launch_failed")
        self.assertTrue((directory / "missing.stderr.log").exists())

    def test_publication_requires_matching_service_evidence_and_git_bytes(self):
        method = self.root / "method.txt"
        method.write_bytes(b"synthetic frozen method\n")
        manifest = self.root / "execution.sha256"
        manifest.write_text(RUNNER.file_digest(method) + "  method.txt\n", encoding="utf-8")
        publication = {
            "commit": "b" * 40,
            "repository": "synthetic/research",
            "workflow_run_id": 123,
            "execution_manifest_sha256": RUNNER.file_digest(manifest),
        }
        evidence = {
            "head_sha": "b" * 40,
            "created_at": "synthetic-service-time",
            "html_url": "https://github.com/synthetic/research/actions/runs/123",
        }
        calls = []

        def git_show(argv, **kwargs):
            calls.append(argv)
            name = argv[-1].split(":", 1)[1]
            return SimpleNamespace(returncode=0, stdout=(self.root / name).read_bytes())

        with patch.object(RUNNER.subprocess, "run", side_effect=git_show):
            valid = RUNNER.verify_publication(
                self.root,
                publication,
                "execution.sha256",
                fetch=lambda url, size: json.dumps(evidence).encode(),
            )
            self.assertEqual(valid["service_created_at"], "synthetic-service-time")
            self.assertEqual(len(calls), 2)
            evidence["head_sha"] = "c" * 40
            with self.assertRaisesRegex(ValueError, "does not prove"):
                RUNNER.verify_publication(
                    self.root,
                    publication,
                    "execution.sha256",
                    fetch=lambda url, size: json.dumps(evidence).encode(),
                )

        evidence["head_sha"] = "b" * 40
        with patch.object(
            RUNNER.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=b"wrong tree"),
        ):
            with self.assertRaisesRegex(ValueError, "frozen bytes"):
                RUNNER.verify_publication(
                    self.root,
                    publication,
                    "execution.sha256",
                    fetch=lambda url, size: json.dumps(evidence).encode(),
                )

    def test_empty_execution_manifest_cannot_authorize_scanning(self):
        manifest = self.root / "empty.sha256"
        manifest.write_bytes(b"")
        publication = {
            "commit": "b" * 40,
            "repository": "synthetic/research",
            "workflow_run_id": 123,
            "execution_manifest_sha256": RUNNER.file_digest(manifest),
        }
        evidence = {"head_sha": "b" * 40, "created_at": "synthetic-service-time"}
        with patch.object(RUNNER.subprocess, "run") as git:
            with self.assertRaisesRegex(ValueError, "Empty execution manifest"):
                RUNNER.verify_publication(
                    self.root,
                    publication,
                    "empty.sha256",
                    fetch=lambda url, size: json.dumps(evidence).encode(),
                )
            git.assert_not_called()


if __name__ == "__main__":
    unittest.main()
