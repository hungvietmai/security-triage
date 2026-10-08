"""Focused regressions for ManifestTests."""

from __future__ import annotations

# Direct unittest discovery bootstraps the repository and shared backend imports.
# ruff: noqa: E402
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
import csv
import json
import tempfile
from collections import Counter

from experiments.make_pair_manifests import INVENTORY, SCHEMA, SPLIT, build_manifests


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


if __name__ == "__main__":
    unittest.main()
