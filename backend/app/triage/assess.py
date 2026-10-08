"""Run-level triage shared by the experiment CLI and the scan worker; no I/O."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from app.triage.claims import classify_claims
from app.triage.evidence import EvidenceIndex
from app.triage.policy import apply_policy
from app.triage.types import SinkRecord

# Exact pinned query paths only: an unknown query must fail, not inherit a rule ID.
_CODEQL_RULES = {
    "Security/CWE-078/CommandInjection.ql": "command-line-injection",
    "Security/CWE-078/UnsafeShellCommandConstruction.ql": "shell-command-constructed-from-input",
}
_CODEQL_PREFIX = {"javascript": "js/", "python": "py/"}


def assert_finding_conservation(
    findings: Sequence[Mapping[str, Any]], units: Sequence[Mapping[str, Any]]
) -> None:
    """Require reconciliation to preserve every raw finding exactly once."""
    raw_ids = Counter(str(finding.get("raw_id") or "") for finding in findings)
    unit_ids = Counter(str(raw_id) for unit in units for raw_id in unit.get("raw_finding_ids", []))
    if raw_ids == unit_ids:
        return
    missing = sorted((raw_ids - unit_ids).elements())
    duplicated = sorted((unit_ids - raw_ids).elements())
    raise RuntimeError(
        f"Reconciliation finding conservation failed: missing={missing}, duplicated={duplicated}"
    )


def codeql_rule_id(language: str, query_path: str) -> str:
    rule = _CODEQL_RULES.get(query_path)
    prefix = _CODEQL_PREFIX.get(language)
    if rule is None or prefix is None:
        raise ValueError(f"Unmapped CodeQL query for {language}: {query_path}")
    return prefix + rule


def verified_definitions(
    *,
    language: str,
    semgrep_version: str,
    codeql_version: str,
    semgrep_rules: Sequence[Mapping[str, Any]],
    staged_rules: Sequence[tuple[str | None, object]],
    expected_query_sha256: Mapping[str, str],
    observed_query_sha256: Mapping[str, str] | None,
    query_pack_version: str | None,
) -> list[dict[str, str]]:
    """Rule definitions from bytes this run staged or verified, never finding metadata.

    `staged_rules[i]` is (SHA-256 of the staged copy of `semgrep_rules[i]` or None, its
    parsed YAML). Aliases sharing a rule ID stay distinct by hash.
    """
    definitions = []
    for rule, (staged_sha256, parsed) in zip(semgrep_rules, staged_rules, strict=True):
        defined = parsed.get("rules") if isinstance(parsed, dict) else None
        if staged_sha256 != rule["sha256"] or not isinstance(defined, list) or len(defined) != 1:
            continue
        rule_id = defined[0].get("id") if isinstance(defined[0], dict) else None
        if staged_sha256 is None or not isinstance(rule_id, str):
            continue
        definitions.append(
            {
                "tool": "semgrep",
                "language": language,
                "rule_id": rule_id,
                "tool_version": semgrep_version,
                "definition_sha256": staged_sha256,
            }
        )
    observed = observed_query_sha256 or {}
    if observed == expected_query_sha256 and query_pack_version:
        for query_path, sha256 in observed.items():
            definitions.append(
                {
                    "tool": "codeql",
                    "language": language,
                    "rule_id": codeql_rule_id(language, query_path),
                    "tool_version": codeql_version,
                    "definition_sha256": sha256,
                    "query_path": query_path,
                    "query_pack": f"codeql/{language}-queries@{query_pack_version}",
                }
            )
    return definitions


def assess_units(
    units: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    sinks: Sequence[SinkRecord],
    sources: Mapping[str, str],
    *,
    mapping: Mapping[str, Any],
    definitions: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    provenance: Mapping[str, str],
) -> list[dict[str, Any]]:
    """One assessment per unit, stamped with the hashes of the policy bytes that ran."""
    claims = classify_claims(mapping, findings, definitions)
    evidence = EvidenceIndex(findings, claims, sinks, sources)
    return [{**apply_policy(evidence.build(unit), policy), **provenance} for unit in units]
