"""Fail-closed verification of the authored guard-query diagnostic oracle."""

import unittest

from experiments.diagnostics.run_constant_guard import check_fixtures


class GuardEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.expectations = {"cases": [
            {"function": "constant", "guard_line": 5,
             "expected_evidence": [208, ">", 200, True]},
            {"function": "dynamic", "guard_line": 15, "expected_evidence": None},
        ]}
        self.row = {"file": "cases.py", "function_name": "constant", "guard_line": 5,
                    "left_value": 208, "comparison_operator": ">", "right_value": 200,
                    "condition_value": True, "selected_branch": "then"}

    def test_spurious_evidence_on_dynamic_case_is_rejected(self):
        result = check_fixtures([self.row], self.expectations)
        self.assertFalse(result["sink_safety_asserted"])
        extra = {**self.row, "function_name": "dynamic", "guard_line": 15}
        with self.assertRaisesRegex(ValueError, "differs"):
            check_fixtures([self.row, extra], self.expectations)

    def test_missing_or_wrong_branch_evidence_is_rejected(self):
        for rows in ([], [{**self.row, "selected_branch": "else"}],
                     [{**self.row, "condition_value": False}], [self.row, self.row]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                check_fixtures(rows, self.expectations)


if __name__ == "__main__":
    unittest.main()
