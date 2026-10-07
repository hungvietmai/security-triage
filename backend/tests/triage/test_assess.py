import json
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from app.triage.assess import (
    assert_finding_conservation,
    assess_units,
    verified_definitions,
)
from app.triage.policy import validate_policy
from app.triage.reconcile import reconcile_findings
from app.triage.sinks_python import locate_python_sinks

ROOT = Path(__file__).resolve().parents[3]
MAPPING = json.loads((ROOT / "experiments/mappings/rule-claims-v2.json").read_bytes())
POLICY = validate_policy(
    yaml.safe_load((ROOT / "experiments/policy/priority-v0.1.yaml").read_bytes())
)
COMMAND_INJECTION = "Security/CWE-078/CommandInjection.ql"


def test_finding_conservation_accepts_one_cross_tool_unit():
    findings = [{"raw_id": "codeql:0:0"}, {"raw_id": "semgrep:0:0"}]
    assert_finding_conservation(findings, [{"raw_finding_ids": ["codeql:0:0", "semgrep:0:0"]}])


@pytest.mark.parametrize(
    "units",
    [
        [{"raw_finding_ids": ["codeql:0:0"]}],
        [{"raw_finding_ids": ["codeql:0:0", "semgrep:0:0", "semgrep:0:0"]}],
    ],
)
def test_finding_conservation_rejects_loss_or_duplication(units):
    findings = [{"raw_id": "codeql:0:0"}, {"raw_id": "semgrep:0:0"}]
    with pytest.raises(RuntimeError, match="finding conservation failed"):
        assert_finding_conservation(findings, units)


def _definitions(staged, observed):
    return verified_definitions(
        language="javascript",
        semgrep_version="1.0",
        codeql_version="2.0",
        semgrep_rules=[{"sha256": "a" * 64}] * len(staged),
        staged_rules=staged,
        expected_query_sha256={COMMAND_INJECTION: "c" * 64},
        observed_query_sha256=observed,
        query_pack_version="2.4.6",
    )


def test_verified_definitions_use_only_matching_staged_bytes():
    one_rule = {"rules": [{"id": "detect-child-process"}]}
    staged = [
        ("a" * 64, one_rule),
        ("b" * 64, one_rule),  # staged bytes differ from the pin
        (None, None),  # never staged
        ("a" * 64, {"rules": [{"id": "x"}, {"id": "y"}]}),
        ("a" * 64, {"rules": [{"id": 3}]}),
        ("a" * 64, {"rules": ["not a mapping"]}),
    ]
    definitions = _definitions(staged, {COMMAND_INJECTION: "c" * 64})
    assert definitions == [
        {
            "tool": "semgrep",
            "language": "javascript",
            "rule_id": "detect-child-process",
            "tool_version": "1.0",
            "definition_sha256": "a" * 64,
        },
        {
            "tool": "codeql",
            "language": "javascript",
            "rule_id": "js/command-line-injection",
            "tool_version": "2.0",
            "definition_sha256": "c" * 64,
            "query_path": COMMAND_INJECTION,
            "query_pack": "codeql/javascript-queries@2.4.6",
        },
    ]
    assert _definitions([], {COMMAND_INJECTION: "d" * 64}) == []
    assert _definitions([], None) == []


def test_assess_units_stamps_provenance_on_every_assessment():
    source = "import os\nos.system(cmd)\n"
    sinks = locate_python_sinks("a.py", source)
    finding = {
        "raw_id": "semgrep:0:0",
        "tool": "semgrep",
        "rule_id": "unknown.rule",
        "reported_path": "a.py",
        "snapshot_sha256": "a" * 64,
        "reported_region": sinks[0]["args"][0]["span"],
        "raw_result": {},
    }
    units = reconcile_findings([finding], sinks, {"a.py": source})
    provenance = {"policy_sha256": "p" * 64, "reconciler_version": "reconcile-v0.1"}
    assessments = assess_units(
        units,
        [finding],
        sinks,
        {"a.py": source},
        mapping=MAPPING,
        definitions=[],
        policy=POLICY,
        provenance=provenance,
    )
    assert len(assessments) == 1
    assert assessments[0]["unit_id"] == units[0]["unit_id"]
    assert assessments[0]["priority"] == "U"  # every claim is unclassified
    assert assessments[0].items() >= provenance.items()
