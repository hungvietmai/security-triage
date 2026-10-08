"""Regression checks for evidence integrity, sink identity and fallback retention."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from experiments.build_review import build_packet, load_evidence, propose, sha

EVIDENCE = Path(__file__).resolve().parents[1] / "reports/curling-0.2.0/execution-evidence.json"


class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = load_evidence(EVIDENCE, "002")
        cls.packet = build_packet(cls.files, sha(EVIDENCE.read_bytes()), "002")

    def row(self):
        result = json.loads(self.files["codeql.sarif"])["runs"][0]["results"][0]
        return {
            "tool": "codeql",
            "rule_id": result["ruleId"],
            "snapshot_sha256": "a" * 64,
            "message": result["message"]["text"],
            "raw_result": result,
        }

    def sources(self):
        from experiments.build_review import source_texts

        return source_texts(self.files["source.tgz"], "package")

    def test_real_case_keeps_six_raw_records_and_proposes_one_sink(self):
        packet = self.packet
        self.assertEqual(len(packet["raw_findings"]), 6)
        self.assertEqual(len(packet["candidate_groups"]), 1)
        self.assertEqual(
            len({r["fallback_unit_id"] for r in packet["raw_findings"]}), 6
        )
        self.assertEqual(packet["summary"]["accepted_sink_assignments"], 0)
        self.assertIsNone(packet["metrics"])
        self.assertTrue(
            all(
                label["technical_verdict"] == "unresolved"
                for label in packet["labels"].values()
            )
        )

    def test_cwe_reclassification_does_not_change_sink_identity(self):
        row = self.row()
        row["reported_cwes"] = ["CWE-78"]
        first, _ = propose(row, self.sources())
        row["reported_cwes"] = ["CWE-88"]
        second, _ = propose(row, self.sources())
        self.assertEqual(first[0]["unit_id"], second[0]["unit_id"])

    def test_reference_id_is_not_hard_coded(self):
        row = self.row()
        row["message"] = row["message"].replace(
            "[shell command](2)", "[shell command](97)"
        )
        for related in row["raw_result"]["relatedLocations"]:
            if related.get("id") == 2:
                related["id"] = 97
        candidates, _ = propose(row, self.sources())
        self.assertEqual(candidates[0]["evidence"]["related_location_id"], 97)

    def test_ambiguous_related_id_and_unsafe_path_are_not_mapped(self):
        row = self.row()
        sink = next(
            loc for loc in row["raw_result"]["relatedLocations"] if loc["id"] == 2
        )
        row["raw_result"]["relatedLocations"].append(copy.deepcopy(sink))
        self.assertEqual(propose(row, self.sources())[0], [])
        row = self.row()
        sink = next(
            loc for loc in row["raw_result"]["relatedLocations"] if loc["id"] == 2
        )
        sink["physicalLocation"]["artifactLocation"]["uri"] = "../lib/curl-transport.js"
        self.assertEqual(propose(row, self.sources())[0], [])

    def test_missing_location_and_unsupported_rule_keep_fallbacks(self):
        files = dict(self.files)
        data = json.loads(files["codeql.sarif"])
        data["runs"][0]["results"] = [
            {"ruleId": "unsupported", "message": {"text": "alert"}}
        ]
        files["codeql.sarif"] = json.dumps(data).encode()
        run = json.loads(files["run.json"])
        run["steps"]["codeql"]["sarif_sha256"] = sha(files["codeql.sarif"])
        files["run.json"] = json.dumps(run).encode()
        packet = build_packet(files, "fixture", "002")
        self.assertEqual(packet["summary"]["fallback_records_retained"], 1)
        row = packet["raw_findings"][0]
        self.assertEqual(row["candidates"], [])
        self.assertIsNone(row["reported_path"])
        self.assertIn(row["fallback_unit_id"], packet["labels"])

    def test_evidence_tampering_is_rejected(self):
        data = json.loads(EVIDENCE.read_text())
        data["decoded_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "evidence.json"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                load_evidence(path, "002")
        files = dict(self.files)
        files["source.tgz"] += b"tampered"
        with self.assertRaisesRegex(ValueError, "Source identity mismatch"):
            build_packet(files, "fixture", "002")


if __name__ == "__main__":
    unittest.main()
