"""Regression checks for retaining audit/unknown alerts and respecting provenance."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from experiments.annotate_claims import DEFAULT_MAPPING, annotate, build, canonical_cwes
from experiments.run_pilot import ROOT, digest


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.mapping = json.loads(DEFAULT_MAPPING.read_text())
        self.config = json.loads(
            (
                ROOT / "experiments/configs/development-batch-01-upstream.json"
            ).read_text()
        )

    def finding(self, rid: str | None = "path.spawn-shell-true", tool="semgrep"):
        return {
            "raw_id": "raw:0",
            "tool": tool,
            "rule_id": rid,
            "reported_path": None,
            "reported_region": {},
            "reported_cwes": ["cwe-078"],
            "technical_verdict": "unresolved",
            "scope_verdict": "unresolved",
            "raw_result": {"message": {"text": "original"}, "locations": []},
        }

    def test_audit_alert_and_missing_location_survive_without_truth_inference(self):
        raw = self.finding()
        saved = copy.deepcopy(raw)
        result = annotate([raw], self.config, self.mapping)
        self.assertEqual(raw, saved)
        self.assertEqual(len(result), 1)
        self.assertEqual({k: result[0][k] for k in raw}, raw)
        semantics = result[0]["rule_semantics"]
        self.assertEqual(semantics["claim_kind"], "shell_usage_audit")
        self.assertEqual(semantics["candidate_status"], "cwe78_candidate")
        self.assertFalse(semantics["automatic_suppression"])

    def test_unknown_and_near_matching_rule_remain_unresolved(self):
        for rid in ("new-rule", "otherdetect-child-process", None):
            row = annotate([self.finding(rid)], self.config, self.mapping)[0]
            self.assertEqual(
                row["rule_semantics"]["candidate_status"], "classification_unresolved"
            )
            self.assertEqual(row["technical_verdict"], "unresolved")
        row = annotate(
            [self.finding("path.spawn-shell-true", "codeql")], self.config, self.mapping
        )[0]
        self.assertEqual(row["rule_semantics"]["status"], "unmapped")

    def test_changed_rule_or_tool_version_does_not_reuse_mapping(self):
        for kind in ("hash", "version"):
            config = copy.deepcopy(self.config)
            if kind == "hash":
                config["semgrep_rules"][2]["sha256"] = "0" * 64
            else:
                config["semgrep_version"] = "different"
            row = annotate([self.finding()], config, self.mapping)[0]
            self.assertEqual(row["rule_semantics"]["status"], "unmapped")

    def test_cwe_normalization_keeps_multiple_classes_without_reclassification(self):
        self.assertEqual(
            canonical_cwes(["cwe-078", "CWE-78", "CWE-088"]), ["CWE-78", "CWE-88"]
        )
        raw = self.finding("js/shell-command-constructed-from-input", "codeql")
        raw["reported_cwes"] = ["cwe-078", "cwe-088"]
        row = annotate([raw], self.config, self.mapping)[0]
        self.assertEqual(row["reported_cwes"], raw["reported_cwes"])
        self.assertEqual(
            row["rule_semantics"]["mapped_rule_cwes"], ["CWE-78", "CWE-88"]
        )
        self.assertEqual(
            row["rule_semantics"]["cwe_links"]["CWE-78"],
            "https://cwe.mitre.org/data/definitions/78.html",
        )
        self.assertNotIn("adjudicated_cwes", row)

    def test_recorded_sarif_is_verified_and_failures_are_not_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config.json").write_text(json.dumps(self.config))
            sarif = root / "semgrep.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "results": [
                                    {
                                        "ruleId": "path.spawn-shell-true",
                                        "message": {"text": "audit"},
                                    }
                                ]
                            }
                        ],
                    }
                )
            )
            report = {
                "status": "partial",
                "configuration_sha256": digest(root / "config.json"),
                "snapshot_sha256": "a" * 64,
                "steps": {
                    "semgrep": {"status": "completed", "sarif_sha256": digest(sarif)},
                    "codeql": {"status": "failed"},
                },
            }
            (root / "run.json").write_text(json.dumps(report))
            result = build(root, self.mapping)
            self.assertEqual(result["raw_count"], 1)
            self.assertEqual(result["annotated_count"], 1)
            self.assertIsNone(result["scanner_runs"]["codeql"]["raw_findings"])
            sarif.write_text(sarif.read_text() + " ")
            with self.assertRaisesRegex(ValueError, "SARIF digest"):
                build(root, self.mapping)

    def test_missing_sarif_on_completed_run_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config.json").write_text(json.dumps(self.config))
            report = {
                "configuration_sha256": digest(root / "config.json"),
                "snapshot_sha256": "a" * 64,
                "steps": {"semgrep": {"status": "completed"}},
            }
            (root / "run.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "missing SARIF"):
                build(root, self.mapping)
            report["configuration_sha256"] = "0" * 64
            (root / "run.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "Configuration digest"):
                build(root, self.mapping)


if __name__ == "__main__":
    unittest.main()
