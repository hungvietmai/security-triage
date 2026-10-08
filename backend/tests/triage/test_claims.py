"""Repeated claims reuse verified identities within a run, without carrying trust across runs."""

from typing import Any

from app.triage.claims import classify_claims


def _mapping():
    return {
        "version": "v1",
        "identity_fields": ["tool", "rule_id", "definition_sha256"],
        "codeql_additional_identity_fields": [],
        "rules": [
            {
                "tool": "semgrep",
                "rule_id": "example",
                "definition_sha256": "a" * 64,
                "claim_kind": "audit",
                "claim_family": "audit",
                "audit_oriented": True,
                "source_type": "unknown",
            }
        ],
    }


class CountingDefinition(dict[str, Any]):
    lookups = 0

    def get(self, *args: Any, **kwargs: Any) -> Any:
        self.lookups += 1
        return super().get(*args, **kwargs)


def test_repeated_findings_do_not_repeat_definition_verification():
    mapping = _mapping()
    definition = CountingDefinition(mapping["rules"][0])
    findings = [
        {"raw_id": f"semgrep:0:{index}", "tool": "semgrep", "rule_id": "staged.example"}
        for index in range(1000)
    ]
    claims = classify_claims(mapping, findings, [definition])
    assert all(claim["definition_verified"] for claim in claims)
    assert [claim["raw_id"] for claim in claims] == [finding["raw_id"] for finding in findings]
    assert definition.lookups <= len(mapping["identity_fields"])


def test_cached_classification_does_not_survive_changed_or_duplicate_definitions():
    mapping = _mapping()
    definition = mapping["rules"][0]
    finding = {"raw_id": "f", "tool": "semgrep", "rule_id": "example"}
    assert classify_claims(mapping, [finding], [definition])[0]["definition_verified"]
    changed = {**definition, "definition_sha256": "b" * 64}
    assert not classify_claims(mapping, [finding], [changed])[0]["definition_verified"]
    assert not classify_claims(mapping, [finding], [definition, definition])[0][
        "definition_verified"
    ]
    mapping["rules"][0] = changed
    assert not classify_claims(mapping, [finding], [definition])[0]["definition_verified"]
