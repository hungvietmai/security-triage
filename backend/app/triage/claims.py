"""Pure hash-qualified claim classification; never mutate raw findings."""

from collections.abc import Mapping, Sequence
from functools import lru_cache
from typing import Any


def classify_claims(
    mapping: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    definitions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Definitions come from verified run bytes, never untrusted finding metadata."""
    ids = [f.get("raw_id") for f in findings]
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("Finding IDs must be nonempty and unique")

    # Definitions and mappings are fixed for this invocation; never reuse trust across runs.
    @lru_cache(maxsize=256)
    def resolved_rule(tool: str, rid: str) -> Mapping[str, Any] | None:
        candidates = []
        for rule in mapping["rules"]:
            if rule["tool"] != tool:
                continue
            if rid != rule["rule_id"] and not (
                rule["tool"] == "semgrep" and rid.endswith("." + rule["rule_id"])
            ):
                continue
            fields = list(mapping["identity_fields"])
            if rule["tool"] == "codeql":
                fields += list(mapping["codeql_additional_identity_fields"])
            observed = [d for d in definitions if all(d.get(k) == rule.get(k) for k in fields)]
            if len(observed) == 1:
                candidates.append(rule)
        return candidates[0] if len(candidates) == 1 else None

    results = []
    for finding in findings:
        rid = finding.get("rule_id")
        tool = finding.get("tool")
        rule = resolved_rule(tool, rid) if isinstance(tool, str) and isinstance(rid, str) else None
        results.append(
            {
                "raw_id": finding["raw_id"],
                "tool": finding["tool"],
                "rule_id": rid,
                "rule_claims_version": mapping["version"],
                "definition_verified": rule is not None,
                "definition_sha256": rule["definition_sha256"] if rule else None,
                "canonical_rule_id": rule["rule_id"] if rule else None,
                "candidate_status": "cwe78_candidate" if rule else "classification_unresolved",
                "claim_kind": rule["claim_kind"] if rule else "classification_unresolved",
                "claim_family": rule["claim_family"] if rule else "classification_unresolved",
                "audit_oriented": rule["audit_oriented"] if rule else False,
                "source_type": rule["source_type"] if rule else "unknown",
                "source_type_basis": "pinned_rule_definition" if rule else None,
            }
        )
    return results
