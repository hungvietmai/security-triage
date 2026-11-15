"""Classify each raw finding for a scan that serves several analysis families; no I/O.

Three facts about a finding are kept apart and none replaces another:

  reported_cwes    what the tool's rule metadata says, copied exactly as the scanner wrote it;
  mapped_cwes      the CWEs a pinned, hash-verified rule definition is mapped to. A rule can
                   map to several. Empty when no verified definition supports a mapping;
  analysis_family  the semantic group whose handler processes the finding, or None.

A family is assigned only when exactly one can be named:

  1. the tool pass that produced the finding ran the pinned rules of one member only
     ("pass_provenance"), or
  2. the pass served several members and exactly one of them declares the rule with a verified
     definition ("pinned_rule_set").

Otherwise the finding is "unresolved". It keeps every label, is handed to no family's handler
and is never filtered. The input findings are never modified.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, TypedDict

FamilyStatus = Literal["resolved", "unresolved"]
FamilyBasis = Literal["pass_provenance", "pinned_rule_set"]
UnresolvedReason = Literal["rule_not_claimed", "definition_unverified", "ambiguous_family"]


class RuleClaim(TypedDict):
    """What one member's pinned files say about a finding's rule."""

    # False: the member names the rule, but no single verified definition backs it.
    verified: bool
    mapped_cwes: list[str]
    basis: str


class Classification(TypedDict):
    raw_id: str
    tool: str
    tool_pass: str
    rule_id: str | None
    reported_cwes: list[str]
    mapped_cwes: list[str]
    mapped_cwes_basis: str | None
    analysis_family: str | None
    family_status: FamilyStatus
    family_basis: FamilyBasis | None
    unresolved_reason: UnresolvedReason | None
    # Families whose pinned files name the rule; more than one is why a family is ambiguous.
    candidate_families: list[str]


# A member's view of one finding: its claim on the rule, or None when it does not name it.
Claim = Callable[[Mapping[str, Any]], RuleClaim | None]


def classify_findings(
    findings: Sequence[Mapping[str, Any]],
    *,
    pass_of: Mapping[str, str],
    pass_members: Mapping[str, Sequence[str]],
    claims: Mapping[str, Claim],
) -> list[Classification]:
    """One classification per finding, in the order given.

    `pass_of` maps a finding's raw ID to the tool pass that produced it; `pass_members` names
    the families each pass ran rules for; `claims` holds each family's claim function.
    """
    ids = [finding.get("raw_id") for finding in findings]
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("Finding IDs must be nonempty and unique")
    return [
        _classify(finding, pass_of[finding["raw_id"]], pass_members, claims) for finding in findings
    ]


def _classify(
    finding: Mapping[str, Any],
    tool_pass: str,
    pass_members: Mapping[str, Sequence[str]],
    claims: Mapping[str, Claim],
) -> Classification:
    members = list(dict.fromkeys(pass_members.get(tool_pass, ())))
    claimed = {family: claims[family](finding) for family in members if family in claims}
    named = {family: claim for family, claim in claimed.items() if claim is not None}
    verified = {family: claim for family, claim in named.items() if claim["verified"]}

    family: str | None = None
    basis: FamilyBasis | None = None
    reason: UnresolvedReason | None = None
    if len(members) == 1:
        # The pass ran this member's pinned rules only, so the alert is this member's.
        family, basis = members[0], "pass_provenance"
    elif len(verified) == 1:
        family, basis = next(iter(verified)), "pinned_rule_set"
    elif len(verified) > 1:
        reason = "ambiguous_family"
    elif named:
        reason = "definition_unverified"
    else:
        reason = "rule_not_claimed"

    claim = verified.get(family) if family is not None else None
    reported = finding.get("reported_cwes")
    return {
        "raw_id": finding["raw_id"],
        "tool": str(finding.get("tool") or ""),
        "tool_pass": tool_pass,
        "rule_id": finding.get("rule_id"),
        # A copy, exactly as reported: no case folding, no zero stripping, no reordering.
        "reported_cwes": list(reported) if isinstance(reported, list) else [],
        "mapped_cwes": list(claim["mapped_cwes"]) if claim else [],
        "mapped_cwes_basis": claim["basis"] if claim else None,
        "analysis_family": family,
        "family_status": "resolved" if family is not None else "unresolved",
        "family_basis": basis,
        "unresolved_reason": reason,
        "candidate_families": sorted(named),
    }


def rule_claims_claim(mapping: Mapping[str, Any], language: str) -> Claim:
    """Claims of a pinned rule-claims file (profiles/*/rule-claims-*.json) for one language.

    A rule is matched the way `app.triage.claims.classify_claims` matches it: by tool and by
    exact rule ID, or for Semgrep by a dot-delimited suffix. The scanner adapters refuse to run
    a rule, query or tool configuration whose bytes differ from the pin, so an alert of a named
    rule comes from a pinned definition; when the file holds variants of one rule that disagree
    on its CWEs, no single definition can be named and the claim is unverified.
    """
    basis = f"rule_claims:{mapping['version']}"

    def claim(finding: Mapping[str, Any]) -> RuleClaim | None:
        tool, rule_id = finding.get("tool"), finding.get("rule_id")
        if not isinstance(tool, str) or not isinstance(rule_id, str):
            return None
        matches = [
            rule
            for rule in mapping["rules"]
            if rule["tool"] == tool
            and rule.get("language", language) == language
            and (
                rule_id == rule["rule_id"]
                or (tool == "semgrep" and rule_id.endswith("." + rule["rule_id"]))
            )
        ]
        if not matches:
            return None
        mapped = {tuple(rule.get("mapped_cwes", ())) for rule in matches}
        if len(mapped) != 1:
            return {"verified": False, "mapped_cwes": [], "basis": basis}
        return {"verified": True, "mapped_cwes": list(next(iter(mapped))), "basis": basis}

    return claim


def pinned_rules_claim(rules: Mapping[str, Sequence[str]], *, basis: str) -> Claim:
    """Claims of a member that pins its rules by ID: {rule ID: mapped CWEs}."""

    def claim(finding: Mapping[str, Any]) -> RuleClaim | None:
        rule_id = finding.get("rule_id")
        if not isinstance(rule_id, str) or rule_id not in rules:
            return None
        return {"verified": True, "mapped_cwes": list(rules[rule_id]), "basis": basis}

    return claim
