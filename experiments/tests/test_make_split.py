from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments"))

import make_split  # noqa: E402


class SplitGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = ROOT / "experiments/inventory/pair-inventory.csv"
        cls.frozen = ROOT / "experiments/inventory/split_v0.json"
        cls.rows = make_split.load_rows(cls.inventory)
        cls.base = json.loads(cls.frozen.read_text(encoding="utf-8"))

    def test_regenerated_base_matches_frozen_split_v0(self):
        regenerated = make_split.build_base_split(self.rows)
        self.assertEqual(
            make_split.normalized(regenerated),
            make_split.normalized(self.base),
        )

    def test_generation_is_idempotent_even_after_split_values_exist(self):
        first = make_split.build_base_split(self.rows)
        assignments = {g["group_id"]: g["assignment"] for g in first["groups"]}
        mutated = copy.deepcopy(self.rows)
        for row in mutated:
            row["split"] = assignments[row["group_id"]]
        second = make_split.build_base_split(mutated)
        self.assertEqual(
            make_split.normalized(first),
            make_split.normalized(second),
        )

    def test_scope_derivation_preserves_frozen_hash_and_assignment(self):
        derived = make_split.derive_v01(self.base, self.rows)
        base_by_id = {g["group_id"]: g for g in self.base["groups"]}
        derived_by_id = {g["group_id"]: g for g in derived["groups"]}

        self.assertEqual(set(base_by_id), set(derived_by_id))
        for gid, base_group in base_by_id.items():
            d = derived_by_id[gid]
            self.assertEqual(d["hash_sha256"], base_group["hash_sha256"])
            self.assertEqual(d["frozen_assignment"], base_group["assignment"])
            self.assertIsNone(d["replacement_group_id"])

        frozen_held = {g["group_id"] for g in self.base["groups"] if g["assignment"] == "held_out"}
        derived_held = {g["group_id"] for g in derived["groups"] if g["assignment"] == "held_out"}
        self.assertTrue(derived_held.issubset(frozen_held))
        self.assertFalse(derived["selection_redrawn"])
        self.assertFalse(derived["replacement_performed"])

    def test_expected_scope_filtered_counts(self):
        derived = make_split.derive_v01(self.base, self.rows)
        self.assertEqual(
            derived["summary_by_language"],
            {
                "javascript": {
                    "development": 14,
                    "excluded": 13,
                    "held_out": 9,
                    "reserve": 11,
                },
                "python": {
                    "development": 9,
                    "excluded": 12,
                    "held_out": 6,
                },
            },
        )
        self.assertEqual(len(derived["removed_or_reserved_from_frozen_held_out"]), 5)

        by_cwe = derived["held_out_groups_by_language_and_cwe"]
        self.assertEqual(len(by_cwe["javascript"]["CWE-77"]), 4)
        self.assertEqual(len(by_cwe["javascript"]["CWE-78"]), 5)
        self.assertEqual(len(by_cwe["python"]["CWE-77"]), 1)
        self.assertEqual(len(by_cwe["python"]["CWE-78"]), 4)
        self.assertEqual(len(by_cwe["python"]["CWE-88"]), 1)


if __name__ == "__main__":
    unittest.main()
