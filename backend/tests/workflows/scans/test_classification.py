"""Classification of raw findings: reported CWEs, mapped CWEs and the analysis family."""

import copy
import json
from typing import Any

import pytest

from app.core.config import get_settings
from app.scanners.profile import load_profile
from app.workflows.scans.classification import (
    RuleClaim,
    classify_findings,
    pinned_rules_claim,
    rule_claims_claim,
)


def _finding(raw_id: str, rule_id: str, cwes: list[str] | None = None) -> dict[str, Any]:
    return {
        "raw_id": raw_id,
        "tool": raw_id.split(":")[0],
        "rule_id": rule_id,
        "reported_cwes": ["cwe-078"] if cwes is None else cwes,
        "raw_result": {"ruleId": rule_id},
    }


def _claim(rules: dict[str, RuleClaim]):
    return lambda finding: rules.get(finding["rule_id"])


COMMAND: RuleClaim = {"verified": True, "mapped_cwes": ["CWE-78", "CWE-88"], "basis": "claims:a"}
PATH: RuleClaim = {"verified": True, "mapped_cwes": ["CWE-22"], "basis": "claims:b"}
UNVERIFIED: RuleClaim = {"verified": False, "mapped_cwes": [], "basis": "claims:a"}


def _classify(findings, pass_members, claims):
    return classify_findings(
        findings,
        pass_of={finding["raw_id"]: finding["tool"] for finding in findings},
        pass_members=pass_members,
        claims=claims,
    )


def test_a_pass_that_serves_one_member_assigns_its_family_and_keeps_every_label():
    finding = _finding("codeql:0:0", "py/command-line-injection")
    before = copy.deepcopy(finding)

    (record,) = _classify(
        [finding],
        {"codeql": ["command-injection"]},
        {"command-injection": _claim({"py/command-line-injection": COMMAND})},
    )

    assert record["analysis_family"] == "command-injection"
    assert (record["family_status"], record["family_basis"]) == ("resolved", "pass_provenance")
    # One rule, several CWEs: the mapping is a list, never a single forced CWE.
    assert record["mapped_cwes"] == ["CWE-78", "CWE-88"]
    assert record["mapped_cwes_basis"] == "claims:a"
    # The tool's own label is copied as written, not normalized to "CWE-78".
    assert record["reported_cwes"] == ["cwe-078"]
    assert finding == before


def test_a_rule_the_only_member_does_not_name_keeps_its_family_but_gets_no_mapping():
    (record,) = _classify(
        [_finding("semgrep:0:0", "tmp.unknown-rule", ["CWE-78"])],
        {"semgrep": ["command-injection"]},
        {"command-injection": _claim({})},
    )

    assert record["analysis_family"] == "command-injection"
    assert record["mapped_cwes"] == [] and record["mapped_cwes_basis"] is None
    assert record["reported_cwes"] == ["CWE-78"]


@pytest.mark.parametrize(
    ("rules_a", "rules_b", "family", "basis", "reason", "candidates"),
    [
        ({"r": COMMAND}, {}, "command-injection", "pinned_rule_set", None, ["command-injection"]),
        ({}, {"r": PATH}, "path-traversal", "pinned_rule_set", None, ["path-traversal"]),
        ({}, {}, None, None, "rule_not_claimed", []),
        ({"r": UNVERIFIED}, {}, None, None, "definition_unverified", ["command-injection"]),
        (
            {"r": COMMAND},
            {"r": PATH},
            None,
            None,
            "ambiguous_family",
            ["command-injection", "path-traversal"],
        ),
        # A verified claim wins over a member that only names the rule without a definition.
        (
            {"r": UNVERIFIED},
            {"r": PATH},
            "path-traversal",
            "pinned_rule_set",
            None,
            ["command-injection", "path-traversal"],
        ),
    ],
)
def test_a_pass_that_serves_two_members_needs_exactly_one_verified_claim(
    rules_a, rules_b, family, basis, reason, candidates
):
    (record,) = _classify(
        [_finding("semgrep:0:0", "r")],
        {"semgrep": ["command-injection", "path-traversal"]},
        {"command-injection": _claim(rules_a), "path-traversal": _claim(rules_b)},
    )

    assert record["analysis_family"] == family
    assert record["family_basis"] == basis
    assert record["unresolved_reason"] == reason
    assert record["family_status"] == ("resolved" if family else "unresolved")
    assert record["candidate_families"] == candidates
    # An unresolved finding loses nothing it came with, and gains no invented mapping.
    assert record["reported_cwes"] == ["cwe-078"]
    if family is None:
        assert record["mapped_cwes"] == []


def test_a_finding_of_a_pass_nobody_configured_is_unresolved():
    (record,) = _classify([_finding("other:0:0", "r")], {}, {})
    assert (record["analysis_family"], record["unresolved_reason"]) == (None, "rule_not_claimed")


def test_finding_ids_must_be_unique():
    findings = [_finding("semgrep:0:0", "a"), _finding("semgrep:0:0", "b")]
    with pytest.raises(ValueError, match="unique"):
        _classify(findings, {"semgrep": ["command-injection"]}, {})


def test_pinned_rule_claims_give_every_mapped_cwe_and_match_semgrep_by_suffix():
    settings = get_settings()
    profile = load_profile(settings.triage_root, settings.scan_profiles["command-injection-v0.3"])
    claim = rule_claims_claim(profile.rule_claims, "python")

    codeql = claim(_finding("codeql:0:0", "py/shell-command-constructed-from-input"))
    assert codeql == {
        "verified": True,
        "mapped_cwes": ["CWE-78", "CWE-88", "CWE-73"],
        "basis": "rule_claims:rule-claims-v3",
    }
    semgrep = claim(_finding("semgrep:0:0", "tmp.rule-0.dangerous-system-call"))
    assert semgrep is not None and semgrep["mapped_cwes"] == ["CWE-78"]
    assert claim(_finding("bandit:0:0", "B605")) is not None
    # Another language's rule, another tool's rule and an unknown rule are not claimed.
    assert claim(_finding("codeql:0:0", "js/command-line-injection")) is None
    assert claim(_finding("eslint:0:0", "dangerous-system-call")) is None
    assert claim(_finding("semgrep:0:0", "tmp.not-a-pinned-rule")) is None
    assert claim({"raw_id": "x", "tool": "semgrep", "rule_id": None}) is None


def test_variants_of_one_rule_that_disagree_on_its_cwes_are_not_a_verified_claim():
    mapping: dict[str, Any] = {
        "version": "test",
        "rules": [
            {"tool": "semgrep", "rule_id": "r", "language": "python", "mapped_cwes": ["CWE-78"]},
            {"tool": "semgrep", "rule_id": "r", "language": "python", "mapped_cwes": ["CWE-94"]},
        ],
    }
    assert rule_claims_claim(mapping, "python")(_finding("semgrep:0:0", "r")) == {
        "verified": False,
        "mapped_cwes": [],
        "basis": "rule_claims:test",
    }
    # Variants that agree (the pinned file has two of detect-child-process) stay verified.
    mapping["rules"][1]["mapped_cwes"] = ["CWE-78"]
    agreed = rule_claims_claim(json.loads(json.dumps(mapping)), "python")(
        _finding("semgrep:0:0", "r")
    )
    assert agreed is not None and agreed["verified"] and agreed["mapped_cwes"] == ["CWE-78"]


def test_rules_pinned_by_id_are_claimed_with_their_mapping():
    claim = pinned_rules_claim({"st/cwe-22/none": ["CWE-22"]}, basis="pinned_query_id:p")
    assert claim(_finding("codeql:0:0", "st/cwe-22/none")) == {
        "verified": True,
        "mapped_cwes": ["CWE-22"],
        "basis": "pinned_query_id:p",
    }
    assert claim(_finding("codeql:0:0", "st/cwe-22/other")) is None
