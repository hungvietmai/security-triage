"""Contract cases for pinned claims, SARIF paths, literal proof and decision order."""

import copy
import itertools
import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

from app.triage.claims import classify_claims
from app.triage.evidence import build_evidence
from app.triage.policy import PREDICATES, apply_policy
from app.triage.reconcile import reconcile_findings
from app.triage.sinks_python import locate_python_sinks
from app.triage.types import SinkRecord

ROOT = Path(__file__).resolve().parents[3]
MAPPING = json.loads((ROOT / "experiments/mappings/rule-claims-v2.json").read_text())
POLICY = yaml.safe_load((ROOT / "experiments/policy/priority-v0.1.yaml").read_text())


def test_all_pinned_rules_and_mismatch():
    config_paths = [
        "development-smoke-javascript.json",
        "development-paired-direct-alias.json",
        "development-batch-01-upstream.json",
        "development-owasp-python-upstream.json",
    ]
    rules = MAPPING["rules"]
    for name in config_paths:
        config = json.loads((ROOT / "experiments/configs" / name).read_text())
        language = config.get("language", "javascript")
        for item in config["semgrep_rules"]:
            matching = [
                r
                for r in rules
                if r["tool"] == "semgrep"
                and r["language"] == language
                and r["definition_sha256"] == item["sha256"]
            ]
            assert len(matching) == 1, (name, item)
        for path, sha in config["codeql_query_sha256"].items():
            matching = [
                r
                for r in rules
                if r["tool"] == "codeql"
                and r["language"] == language
                and r["query_path"] == path
                and r["definition_sha256"] == sha
            ]
            assert len(matching) == 1, (name, path)
    for rule in rules:
        definition = {key: rule[key] for key in MAPPING["identity_fields"]}
        if rule["tool"] == "codeql":
            definition.update(
                {key: rule[key] for key in MAPPING["codeql_additional_identity_fields"]}
            )
        finding = {"raw_id": "one", "tool": rule["tool"], "rule_id": rule["rule_id"]}
        assert (
            classify_claims(MAPPING, [finding], [definition])[0]["claim_family"]
            == rule["claim_family"]
        )
        wrong = {**definition, "definition_sha256": "0" * 64}
        assert (
            classify_claims(MAPPING, [finding], [wrong])[0]["claim_family"]
            == "classification_unresolved"
        )
    alias = next(r for r in rules if r["variant_id"] == "direct-alias-development")
    d = {key: alias[key] for key in MAPPING["identity_fields"]}
    assert classify_claims(
        MAPPING, [{"raw_id": "x", "tool": "semgrep", "rule_id": "rule-0.detect-child-process"}], [d]
    )[0]["definition_verified"]
    assert not classify_claims(
        MAPPING, [{"raw_id": "x", "tool": "semgrep", "rule_id": "otherdetect-child-process"}], [d]
    )[0]["definition_verified"]
    assert not classify_claims(
        MAPPING, [{"raw_id": "x", "tool": "semgrep", "rule_id": alias["rule_id"]}], [d, d]
    )[0]["definition_verified"]


def _case(source="import os\nos.system(command)\n", role="shell_command"):
    sinks = locate_python_sinks("a.py", source)
    sink = sinks[0]
    span = sink["args"][0]["span"]
    finding: dict[str, Any] = {
        "raw_id": "codeql:0:0",
        "tool": "codeql",
        "rule_id": "py/command-line-injection",
        "reported_path": "a.py",
        "snapshot_sha256": "a" * 64,
        "reported_region": span,
        "raw_result": {},
    }
    unit = reconcile_findings([finding], sinks, {"a.py": source})[0]
    assert unit["argument_role"] == role
    claim = {
        "raw_id": finding["raw_id"],
        "tool": "codeql",
        "rule_id": finding["rule_id"],
        "claim_family": "flow",
        "audit_oriented": False,
        "source_type": "remote",
    }
    return unit, finding, claim, sinks, {"a.py": source}


def _loc(line, start, end, path="a.py"):
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {
                    "startLine": line,
                    "endLine": line,
                    "startColumn": start,
                    "endColumn": end,
                },
            }
        }
    }


def test_sarif_trace_valid_missing_malformed_wrong_endpoint_and_source():
    unit, finding, claim, sinks, sources = _case()
    arg = sinks[0]["args"][0]["span"]
    source_loc = _loc(1, 1, 2)
    endpoint = _loc(arg["startLine"], arg["startColumn"], arg["endColumn"])
    cases: list[tuple[object, str]] = [
        (None, "missing"),
        ([], "missing"),
        ([{"threadFlows": []}], "malformed"),
        ([{"threadFlows": [{"locations": [source_loc, _loc(2, 1, 3)]}]}], "endpoint_mismatch"),
        (
            [{"threadFlows": [{"locations": [source_loc, _loc(2, 11, 18, "other.py")]}]}],
            "endpoint_unresolved",
        ),
        ([{"threadFlows": [{"locations": [source_loc, endpoint]}]}], "valid_endpoint"),
    ]
    for flow, expected in cases:
        row = copy.deepcopy(finding)
        if flow is not None:
            row["raw_result"]["codeFlows"] = flow
        evidence = build_evidence(unit, [row], [claim], sinks, sources)
        assert evidence["finding_evidence"][0]["trace_status"] == expected
        assert evidence["predicate_values"]["strong_flow"] == (expected == "valid_endpoint")


def test_trace_to_option_or_argument_list_does_not_prove_flow():
    source = 'import subprocess\nsubprocess.run(["ls", cmd], shell=False)\n'
    sinks = locate_python_sinks("a.py", source)
    list_arg = sinks[0]["args"][0]
    finding: dict[str, Any] = {
        "raw_id": "codeql:0:0",
        "tool": "codeql",
        "reported_path": "a.py",
        "snapshot_sha256": "a" * 64,
        "reported_region": list_arg["sequence_items"][0],
        "raw_result": {},
    }
    unit = reconcile_findings([finding], sinks, {"a.py": source})[0]
    claim = {
        "raw_id": finding["raw_id"],
        "tool": "codeql",
        "claim_family": "flow",
        "source_type": "remote",
        "audit_oriented": False,
    }
    for target in (list_arg["sequence_items"][1], sinks[0]["args"][1]["span"]):
        finding["raw_result"]["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            _loc(1, 1, 2),
                            _loc(target["startLine"], target["startColumn"], target["endColumn"]),
                        ]
                    }
                ]
            }
        ]
        result = build_evidence(unit, [finding], [claim], sinks, {"a.py": source})
        assert not result["predicate_values"]["strong_flow"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('import os\nos.system("echo fixed")\n', True),
        ('import os\nos.system("echo " + "fixed")\n', True),
        ('import os\nos.system("echo " + command)\n', False),
        ('import os\nos.system("sh -c echo")\n', False),
        ('import subprocess\nsubprocess.run("echo fixed", shell=True)\n', True),
        ('import subprocess\nsubprocess.run(["echo", "fixed"], shell=True)\n', False),
    ],
)
def test_python_literal_proof(source, expected):
    sinks = locate_python_sinks("a.py", source)
    arg = sinks[0]["args"][0]
    finding = {
        "raw_id": "s:0:0",
        "tool": "semgrep",
        "reported_path": "a.py",
        "snapshot_sha256": "a" * 64,
        "reported_region": arg["span"],
        "raw_result": {},
    }
    unit = reconcile_findings([finding], sinks, {"a.py": source})[0]
    claim = {
        "raw_id": finding["raw_id"],
        "tool": "semgrep",
        "claim_family": "audit",
        "source_type": "unknown",
        "audit_oriented": True,
    }
    evidence = build_evidence(unit, [finding], [claim], sinks, {"a.py": source})
    assert evidence["predicate_values"]["verified_blocker"] == expected


BASE = {key: False for key in PREDICATES}


@pytest.mark.parametrize(
    ("matched", "near_miss", "tier", "decision"),
    [
        ({"unresolved_unit": True}, {"unresolved_unit": False}, "U", "D00_UNRESOLVED"),
        (
            {"execution_candidate": True, "verified_blocker": True},
            {"execution_candidate": True},
            "P4",
            "D10_LITERAL",
        ),
        (
            {"execution_candidate": True, "strong_flow": True, "shell_semantics": True},
            {"execution_candidate": True, "strong_flow": True},
            "P1",
            "D20_STRONG",
        ),
        (
            {"execution_candidate": True, "flow_claim": True, "important_unknown": True},
            {"execution_candidate": True, "important_unknown": True},
            "P2",
            "D30_HIGH",
        ),
        (
            {"execution_candidate": True, "shell_semantics": True},
            {"execution_candidate": True},
            "P3",
            "D40_REVIEW",
        ),
        ({}, {"execution_candidate": True, "shell_semantics": True}, "P4", "D99_DEFAULT"),
    ],
)
def test_each_ordered_rule_and_near_miss(matched, near_miss, tier, decision):
    evidence = {"predicate_values": {**BASE, **matched}, "source_types": [], "unknown_fields": []}
    result = apply_policy(evidence, POLICY)
    assert (result["tier"], result["decision_id"]) == (tier, decision)
    other = apply_policy({**evidence, "predicate_values": {**BASE, **near_miss}}, POLICY)
    assert other["decision_id"] != decision
    assert result["reason"] and result["matched_conditions"]


def test_all_1024_signal_combinations_have_one_priority():
    keys = sorted(PREDICATES)
    for values in itertools.product((False, True), repeat=len(keys)):
        result = apply_policy(
            {
                "predicate_values": dict(zip(keys, values, strict=True)),
                "unknown_fields": [],
                "source_types": [],
            },
            POLICY,
        )
        assert result["tier"] in {"P1", "P2", "P3", "P4", "U"}
        assert result["decision_id"] in {rule["id"] for rule in POLICY["decisions"]}


def _js_case(arg0, suffix="", *, kind="child_process.exec"):
    source = f"run({arg0}{suffix})\n"
    first = {
        "position": 0,
        "keyword": None,
        "span": {"startLine": 1, "endLine": 1, "startColumn": 5, "endColumn": 5 + len(arg0)},
        "text": arg0,
        "value_kind": "string",
        "literal_bool": None,
    }
    args = [first]
    if suffix:
        from app.triage.sinks_javascript import _argument_ranges

        for position, (a, b) in enumerate(_argument_ranges(source), 1):
            if position == 1:
                continue
            text = source[a:b].strip()
            col = source.index(text, 4) + 1
            args.append(
                {
                    "position": position - 1,
                    "keyword": None,
                    "span": {
                        "startLine": 1,
                        "endLine": 1,
                        "startColumn": col,
                        "endColumn": col + len(text),
                    },
                    "text": text,
                    "value_kind": "dict"
                    if text.startswith("{")
                    else "list"
                    if text.startswith("[")
                    else "name",
                    "literal_bool": None,
                }
            )
    sink = {
        "path": "a.js",
        "span": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": len(source)},
        "sink_kind": kind,
        "callee": "run",
        "args": args,
    }
    finding = {
        "raw_id": "semgrep:0:0",
        "tool": "semgrep",
        "reported_path": "a.js",
        "snapshot_sha256": "a" * 64,
        "reported_region": first["span"],
        "raw_result": {},
    }
    typed_sink = cast(SinkRecord, sink)
    unit = reconcile_findings([finding], [typed_sink], {"a.js": source})[0]
    claim = {
        "raw_id": finding["raw_id"],
        "tool": "semgrep",
        "claim_family": "audit",
        "source_type": "unknown",
        "audit_oriented": True,
    }
    return build_evidence(unit, [finding], [claim], [typed_sink], {"a.js": source})


@pytest.mark.parametrize(
    ("kind", "command", "extra", "expected"),
    [
        ("child_process.exec", '"echo fixed"', "", True),
        ("child_process.exec", "('echo ' + 'fixed')", "", True),
        ("child_process.exec", '"echo " + user', "", False),
        ("child_process.exec", "`echo ${user}`", "", False),
        ("child_process.exec", '"sh -c echo"', "", False),
        ("child_process.exec", '"echo fixed"', ", opts", False),
        ("child_process.spawn", '"echo"', ', ["fixed"], {shell: true}', True),
        ("child_process.spawn", '"echo"', ', ["fixed" "other"], {shell: true}', False),
        ("child_process.spawn", '"echo"', ', ["fixed",, "other"], {shell: true}', False),
        ("child_process.spawn", '"echo"', ", [user], {shell: true}", False),
        ("child_process.spawn", '"echo"', ', ["fixed"], {shell: opts.shell}', False),
        ("child_process.spawn", '"echo"', ", [], {...opts, shell: true}", False),
        ("child_process.spawn", '"echo"', ", [], {shell: true, shell: false}", False),
        ("child_process.spawn", '"echo"', ", [], {shell: true, env: opts.env}", False),
        ("child_process.execFile", '"echo"', "", False),
    ],
)
def test_js_whole_command_literal(kind, command, extra, expected):
    evidence = _js_case(command, extra, kind=kind)
    assert evidence["predicate_values"]["verified_blocker"] == expected


def test_trace_unknowns_and_validation_errors():
    unit, finding, claim, sinks, sources = _case()
    endpoint_span = sinks[0]["args"][0]["span"]
    end = _loc(endpoint_span["startLine"], endpoint_span["startColumn"], endpoint_span["endColumn"])
    source_loc = _loc(1, 1, 2)
    examples = [
        ([{"threadFlows": [{"locations": [source_loc]}]}], "malformed"),
        ([{"threadFlows": [{"locations": [source_loc, end], "junk": True}]}], "valid_endpoint"),
        (
            [{"threadFlows": [{"locations": [{**source_loc, "executionOrder": 0}, end]}]}],
            "malformed",
        ),
        (
            [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {**source_loc, "executionOrder": 1},
                                {**end, "executionOrder": 1},
                            ]
                        }
                    ]
                }
            ],
            "malformed",
        ),
        (
            [{"threadFlows": [{"locations": [source_loc, _loc(2, 11, 18, "missing.py")]}]}],
            "endpoint_unresolved",
        ),
    ]
    for flow, expected in examples:
        row = copy.deepcopy(finding)
        row["raw_result"]["codeFlows"] = flow
        assert (
            build_evidence(unit, [row], [claim], sinks, sources)["finding_evidence"][0][
                "trace_status"
            ]
            == expected
        )
    row = copy.deepcopy(finding)
    row["raw_result"]["codeFlows"] = [
        {
            "threadFlows": [
                {"locations": [{**end, "executionOrder": 2}, {**source_loc, "executionOrder": 1}]}
            ]
        }
    ]
    assert build_evidence(unit, [row], [claim], sinks, sources)["predicate_values"]["strong_flow"]
    missing = build_evidence(unit, [finding], [claim], [], sources)
    assert "source_or_argument_parsing_unavailable" in missing["unknown_fields"]
    assert missing["predicate_values"]["important_unknown"]
    with pytest.raises(ValueError):
        build_evidence({**unit, "mapping_status": "unexpected"}, [finding], [claim], sinks, sources)
    with pytest.raises(ValueError):
        build_evidence({**unit, "raw_finding_ids": ["absent"]}, [finding], [claim], sinks, sources)
    with pytest.raises(ValueError):
        build_evidence(
            {**unit, "raw_finding_ids": ["codeql:0:0"] * 2}, [finding], [claim], sinks, sources
        )
    with pytest.raises(ValueError):
        classify_claims(MAPPING, [finding, finding], [])


def test_shell_library_input_strong_flow_remains_p1():
    unit, finding, claim, sinks, sources = _case()
    span = sinks[0]["args"][0]["span"]
    finding["raw_result"]["codeFlows"] = [
        {
            "threadFlows": [
                {
                    "locations": [
                        _loc(1, 1, 2),
                        _loc(span["startLine"], span["startColumn"], span["endColumn"]),
                    ]
                }
            ]
        }
    ]
    claim["source_type"] = "library_input"
    evidence = build_evidence(unit, [finding], [claim], sinks, sources)
    assert evidence["predicate_values"]["important_unknown"]
    assert evidence["predicate_values"]["strong_flow"]
    assert apply_policy(evidence, POLICY)["tier"] == "P1"


def test_policy_rejects_unknown_enums_and_missing_default():
    evidence = {"predicate_values": BASE, "unknown_fields": [], "source_types": []}
    with pytest.raises(ValueError):
        apply_policy({**evidence, "predicate_values": {**BASE, "other": True}}, POLICY)
    with pytest.raises(ValueError):
        apply_policy(evidence, {**POLICY, "decisions": POLICY["decisions"][:-1]})
