"""Synthetic SARIF/diagnostic-to-review workflows; no scanner or research pair is used."""

from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WAVE = ROOT / "experiments/wave-c"
sys.path.insert(0, str(WAVE))
SPEC = importlib.util.spec_from_file_location("wave_c_evaluation", WAVE / "evaluate.py")
EVALUATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATOR)


class WaveCEvaluationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = {}
        for mode, lines in {
            "none": [10, 20, 30, 40],
            "all": [10, 20, 30],
            "v03": [20, 30],
            "v03s": [20],
        }.items():
            self.sarif(mode, lines)
        self.table(
            "contracts",
            ["file", "line", "col", "kind", "root", "detail"],
            [
                ["app.py", 10, 1, "allowed", "/srv/store", "local"],
                ["app.py", 10, 1, "contained", "/srv/store", "canonical"],
                ["app.py", 30, 1, "allowed", "$TMPDIR/store", "resource"],
                ["app.py", 30, 1, "contained", "$TMPDIR/store", "lexical (A-SYM)"],
            ],
        )
        self.table(
            "evidence",
            ["file", "line", "col", "root", "basis", "source", "level"],
            [
                ["app.py", 10, 1, "/srv/store", "canonical", "local", "proved"],
                ["app.py", 30, 1, "$TMPDIR/store", "lexical (A-SYM)", "resource", "scoped"],
            ],
        )

    def sarif(self, mode, lines):
        path = self.root / f"{mode}.sarif"
        results = [
            {
                "ruleId": f"st/cwe-22/{mode}",
                "message": {"text": "flow from source"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": line, "startColumn": 1},
                        }
                    }
                ],
                "relatedLocations": [
                    {
                        "id": 1,
                        "message": {"text": "source"},
                        "physicalLocation": {
                            "artifactLocation": {"uri": "routes.py"},
                            "region": {"startLine": 1, "startColumn": 1},
                        },
                    }
                ],
            }
            for line in lines
        ]
        path.write_text(
            json.dumps({"version": "2.1.0", "runs": [{"results": results}]}), encoding="utf-8"
        )
        self.paths[mode] = path

    def table(self, name, fields, rows):
        path = self.root / f"{name}.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(fields)
            writer.writerows(rows)
        self.paths[name] = path

    def evaluate(self, labels=None):
        return EVALUATOR.snapshot("synthetic/repo", "a" * 40, self.paths, labels)

    def reviewed(self, line, technical="false_positive"):
        identity = EVALUATOR.unit_id("synthetic/repo", "a" * 40, ("app.py", line, 1))
        return identity, {
            "unit_id": identity,
            "technical_label": technical,
            "scope": "production",
            "root_cause_id": f"synthetic-{line}",
            "review_status": "owner_reviewed",
            "reviewer": "synthetic-fixture-reviewer",
            "reviewed_at": "synthetic-date",
            "all_reported_flows_reviewed": True,
            "assumptions": {
                a: {"status": "supported", "evidence": "synthetic boundary evidence"}
                for a in (*EVALUATOR.SCOPED_ASSUMPTIONS, "A-SYM")
            },
        }

    def test_raw_suppression_does_not_invent_labels_or_scope_approval(self):
        result = self.evaluate()
        self.assertEqual(result["status"], "review_pending")
        self.assertEqual(result["counts"], {"none": 4, "all": 3, "v03": 2, "v03s": 1})
        self.assertEqual(result["modes"]["v03s"]["raw_suppressed"], 2)
        self.assertEqual(result["modes"]["v03s"]["accepted_suppression"], 0)
        self.assertEqual(result["modes"]["v03"]["contract_sinks"], 1)
        self.assertEqual(result["modes"]["v03s"]["contract_sinks"], 2)
        self.assertTrue(
            all(
                row["reviewer"] is None and row["technical_label"] is None
                for row in result["label_template"]
            )
        )
        packet = json.dumps(result["review_packet"])
        for hidden in ("raw_suppressed", "st/cwe-22", "technical_label", "operational_decision"):
            self.assertNotIn(hidden, packet)
        self.assertIn("reported_sources", packet)

    def test_final_review_acceptance_and_contradicted_or_missing_assumptions(self):
        labels = dict(self.reviewed(line) for line in (10, 30))
        result = self.evaluate(labels)
        self.assertEqual(result["modes"]["v03s"]["accepted_suppression"], 2)
        row_id, row = self.reviewed(30)
        row["assumptions"]["S-TEST"]["status"] = "contradicted"
        labels[row_id] = row
        rejected = self.evaluate(labels)
        self.assertEqual(rejected["status"], "failed_acceptance")
        self.assertEqual(rejected["modes"]["v03s"]["raw_suppressed"], 2)
        self.assertEqual(rejected["modes"]["v03s"]["decision_counts"]["scope_rejected"], 1)
        row["assumptions"]["S-TEST"] = {"status": "supported", "evidence": None}
        pending = self.evaluate(labels)
        self.assertEqual(pending["modes"]["v03s"]["decision_counts"]["scope_unknown"], 1)

    def test_tp_unknown_and_subset_violation_fail_acceptance(self):
        for label in ("true_positive", "true_positive_conditional", "unknown"):
            with self.subTest(label=label):
                self.assertEqual(
                    self.evaluate(dict([self.reviewed(30, label)]))["status"], "failed_acceptance"
                )
        self.sarif("v03s", [20, 99])
        self.assertTrue(self.evaluate()["subset_violations"])
        self.assertEqual(self.evaluate()["status"], "failed_acceptance")

    def test_zero_alert_is_explicit_and_missing_outputs_are_not_zero(self):
        for mode in EVALUATOR.MODES:
            self.sarif(mode, [])
        result = self.evaluate()
        self.assertEqual(result["counts"], dict.fromkeys(EVALUATOR.MODES, 0))
        self.assertIsNone(result["modes"]["v03s"]["contract_coverage"])
        self.paths["none"].unlink()
        with self.assertRaises(FileNotFoundError):
            self.evaluate()

    def test_ambiguous_sink_mapping_is_rejected_and_all_sarif_runs_are_read(self):
        document = json.loads(self.paths["none"].read_bytes())
        document["runs"].append(document["runs"][0])
        self.paths["none"].write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(self.evaluate()["counts"]["none"], 4)
        del document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
            "startColumn"
        ]
        self.paths["none"].write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(KeyError):
            self.evaluate()

    def test_cli_persists_report_packet_template_and_detects_corrupt_artifacts(self):
        files = {key: path.name for key, path in self.paths.items()}
        run = {
            "records": [
                {
                    "rank": 1,
                    "repository": "synthetic/repo",
                    "commit": "a" * 40,
                    "status": "completed",
                    "files": files,
                    "file_hashes": {
                        key: EVALUATOR.file_digest(path) for key, path in self.paths.items()
                    },
                }
            ]
        }
        (self.root / "run.json").write_text(json.dumps(run), encoding="utf-8")
        command = [
            sys.executable,
            str(WAVE / "evaluate.py"),
            "--root",
            str(self.root),
            "--run",
            "run.json",
            "--output",
            "report",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "report/review_packet.json").is_file())
        self.assertEqual(
            len(json.loads((self.root / "report/labels.template.json").read_bytes())), 4
        )
        report = json.loads((self.root / "report/report.json").read_bytes())
        self.assertEqual(report["aggregate"]["complete_counts"]["none"], 4)
        self.assertEqual(report["aggregate"]["complete_repositories"], 1)
        run["records"][0]["status"] = "incomplete_extraction"
        (self.root / "run.json").write_text(json.dumps(run), encoding="utf-8")
        command[-1] = "incomplete-report"
        partial = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(partial.returncode, 0, partial.stderr)
        aggregate = json.loads((self.root / "incomplete-report/report.json").read_bytes())[
            "aggregate"
        ]
        self.assertEqual(aggregate["complete_repositories"], 0)
        self.assertEqual(aggregate["incomplete_extraction_repositories"], 1)
        self.assertEqual(aggregate["complete_counts"]["none"], 0)
        self.paths["all"].write_bytes(b"corrupted")
        command[-1] = "bad-report"
        bad = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("hash mismatch", bad.stderr)
        self.assertFalse((self.root / "bad-report").exists())


if __name__ == "__main__":
    unittest.main()
