"""Evaluate the frozen ordered decision list without labels or I/O."""

from collections.abc import Mapping
from typing import Any

PREDICATES = frozenset(
    {
        "execution_candidate",
        "unresolved_unit",
        "flow_claim",
        "audit_claim",
        "strong_flow",
        "shell_semantics",
        "agreement",
        "verified_blocker",
        "important_unknown",
        "evidence_conflict",
    }
)
TIERS = frozenset({"P1", "P2", "P3", "P4", "U"})


def matches(condition: Any, signals: Mapping[str, bool]) -> bool:
    if isinstance(condition, str):
        if condition not in PREDICATES:
            raise ValueError("Unknown predicate: " + condition)
        return signals[condition]
    if not isinstance(condition, dict) or len(condition) != 1:
        raise ValueError("Invalid decision condition")
    key, value = next(iter(condition.items()))
    if key == "always" and value is True:
        return True
    if key == "not":
        return not matches(value, signals)
    if key in {"all", "any"} and isinstance(value, list) and value:
        values = [matches(child, signals) for child in value]
        return all(values) if key == "all" else any(values)
    raise ValueError("Invalid decision operator")


def apply_policy(evidence: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    signals = evidence["predicate_values"]
    if set(signals) != PREDICATES or any(type(v) is not bool for v in signals.values()):
        raise ValueError("Policy needs exactly ten boolean predicates")
    decisions = policy["decisions"]
    if not decisions or decisions[-1]["when"] != {"always": True}:
        raise ValueError("Ordered policy must end with an unconditional default")
    outcomes = [(row, matches(row["when"], signals)) for row in decisions]
    if len({r["id"] for r, _ in outcomes}) != len(outcomes):
        raise ValueError("Duplicate decision ID")
    if any(r["priority"] not in TIERS for r, _ in outcomes):
        raise ValueError("Unknown priority")
    row = next(r for r, matched in outcomes if matched)
    conditions = sorted(k for k, v in signals.items() if v)

    def clauses(condition: Any) -> list[str]:
        if isinstance(condition, str):
            return [condition] if signals[condition] else []
        if not matches(condition, signals):
            return []
        key, value = next(iter(condition.items()))
        if key == "not":
            return ["not " + str(value)]
        if key == "always":
            return ["default: no preceding rule matched"]
        return [str(condition)] + [c for child in value for c in clauses(child)]

    conditions = sorted(set(conditions + clauses(row["when"])))
    return {
        **evidence,
        "tier": row["priority"],
        "priority": row["priority"],
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "decision_id": row["id"],
        "matched_conditions": conditions,
        "reason": row["reason"].format(
            matched_conditions=", ".join(conditions),
            unknown_fields=evidence.get("unknown_fields", []),
            source_types=evidence.get("source_types", []),
            blocker_proof=evidence.get("blocker_proof"),
        ),
    }
