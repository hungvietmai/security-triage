"""Amendment 05: split-v0.2 reassigns only the JavaScript reserve and is reproducible."""

from __future__ import annotations

# ruff: noqa: E402
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import json

from experiments import make_split_v0_2


class SplitV02Tests(unittest.TestCase):
    def setUp(self):
        self.before = json.loads(make_split_v0_2.SOURCE.read_text(encoding="utf-8"))
        self.after = json.loads(make_split_v0_2.TARGET.read_text(encoding="utf-8"))

    def test_committed_split_matches_its_derivation(self):
        self.assertEqual(make_split_v0_2.main(["--check"]), 0)

    def test_only_reserve_groups_change_and_held_out_is_untouched(self):
        before = {g["group_id"]: g for g in self.before["groups"]}
        after = {g["group_id"]: g for g in self.after["groups"]}
        self.assertEqual(set(before), set(after))
        changed = {gid for gid in before if before[gid] != after[gid]}
        reserve = {gid for gid, g in before.items() if g["assignment"] == "reserve"}
        self.assertEqual(changed, reserve)
        self.assertEqual(len(reserve), 11)
        for gid in reserve:
            self.assertEqual(before[gid]["language"], "javascript")
            self.assertEqual(after[gid]["assignment"], "development")
            self.assertEqual(after[gid]["previous_assignment"], "reserve")
        for key in ("held_out_rule", "frozen_strata", "held_out_groups_by_language_and_cwe"):
            self.assertEqual(self.before[key], self.after[key])
        self.assertFalse(self.after["selection_redrawn"])
        self.assertFalse(self.after["replacement_performed"])
        self.assertEqual(
            self.after["summary_by_language"]["javascript"],
            {"development": 25, "excluded": 13, "held_out": 9},
        )


if __name__ == "__main__":
    unittest.main()
