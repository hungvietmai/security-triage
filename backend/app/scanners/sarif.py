"""Strict SARIF 2.1.0 parsing for raw scanner findings."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypedDict, cast

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]


class Finding(TypedDict):
    raw_id: str
    tool: str
    snapshot_sha256: str
    rule_id: str | None
    reported_path: str | None
    reported_region: JsonObject
    reported_cwes: list[str]
    message: str
    sink_identity: None
    mapping_status: str
    technical_verdict: str
    scope_verdict: str
    raw_result: JsonObject


def _object(value: JsonValue | object) -> JsonObject:
    if not isinstance(value, dict):
        return {}
    raw = cast(dict[object, object], value)
    result: JsonObject = {}
    for key, item in raw.items():
        if isinstance(key, str):
            result[key] = cast(JsonValue, item)
    return result


def _list(value: JsonValue | object) -> list[JsonValue]:
    if not isinstance(value, list):
        return []
    return cast(list[JsonValue], value)


def _objects(value: JsonValue | object, field: str) -> list[JsonObject]:
    """Malformed scanner output must not become an empty, successful analysis."""
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Invalid SARIF {field}: expected an array of objects")
    return [_object(item) for item in value]


def _text(value: JsonValue | object) -> str | None:
    return value if isinstance(value, str) else None


def sarif_findings(path: Path, tool: str, snapshot: str) -> tuple[list[Finding], bool]:
    """Preserve every SARIF result without inferring sink identity or labels."""
    root_value = cast(object, json.loads(path.read_text(encoding="utf-8")))
    root = _object(root_value)
    if root.get("version") != "2.1.0" or not isinstance(root.get("runs"), list):
        raise ValueError("Invalid SARIF 2.1.0 document")

    records: list[Finding] = []
    complete = True
    for run_index, run in enumerate(_objects(root.get("runs"), "runs")):
        # A rule-metadata export may omit results, but it cannot prove a scan completed.
        if "results" not in run:
            complete = False
        for invocation in _objects(run.get("invocations", []), "invocations"):
            if invocation.get("executionSuccessful") is False:
                complete = False
            for note in _objects(
                invocation.get("toolExecutionNotifications", []), "toolExecutionNotifications"
            ):
                level = _text(note.get("level")) or "warning"
                if level not in {"none", "note"}:
                    complete = False

        driver = _object(_object(run.get("tool")).get("driver"))
        ordered_rules = _objects(driver.get("rules", []), "rules")
        rules: dict[str, JsonObject] = {}
        for rule in ordered_rules:
            rule_id = _text(rule.get("id"))
            if rule_id is not None:
                rules[rule_id] = rule

        for result_index, result in enumerate(_objects(run.get("results", []), "results")):
            locations = _list(result.get("locations"))
            location = _object(locations[0]) if locations else {}
            physical = _object(location.get("physicalLocation"))
            artifact = _object(physical.get("artifactLocation"))
            region = _object(physical.get("region"))

            rule_id = _text(result.get("ruleId"))
            rule_index = result.get("ruleIndex")
            if rule_id is None and isinstance(rule_index, int) and not isinstance(rule_index, bool):
                if 0 <= rule_index < len(ordered_rules):
                    rule_id = _text(ordered_rules[rule_index].get("id"))
            rule = rules.get(rule_id or "", {})
            properties = rule.get("properties", {})
            reported_cwes = sorted(
                set(re.findall(r"CWE-\d+", json.dumps(properties), re.IGNORECASE))
            )
            message = _text(_object(result.get("message")).get("text")) or ""
            records.append(
                {
                    "raw_id": f"{tool}:{run_index}:{result_index}",
                    "tool": tool,
                    "snapshot_sha256": snapshot,
                    "rule_id": rule_id,
                    "reported_path": _text(artifact.get("uri")),
                    "reported_region": region,
                    "reported_cwes": reported_cwes,
                    "message": message,
                    "sink_identity": None,
                    "mapping_status": "unresolved",
                    "technical_verdict": "unresolved",
                    "scope_verdict": "unresolved",
                    "raw_result": result,
                }
            )
    return records, complete
