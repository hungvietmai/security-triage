"""Strict SARIF 2.1.0 parsing for raw scanner findings."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypeAlias, TypedDict, cast

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


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


def _text(value: JsonValue | object) -> str | None:
    return value if isinstance(value, str) else None


def sarif_findings(path: Path, tool: str, snapshot: str) -> tuple[list[Finding], bool]:
    """Preserve every SARIF result without inferring sink identity or labels."""
    root_value = cast(object, json.loads(path.read_text()))
    root = _object(root_value)
    if root.get("version") != "2.1.0" or not isinstance(root.get("runs"), list):
        raise ValueError("Invalid SARIF 2.1.0 document")

    records: list[Finding] = []
    complete = True
    for run_index, run_value in enumerate(_list(root.get("runs"))):
        run = _object(run_value)
        for invocation_value in _list(run.get("invocations")):
            invocation = _object(invocation_value)
            if invocation.get("executionSuccessful") is False:
                complete = False
            for note_value in _list(invocation.get("toolExecutionNotifications")):
                note = _object(note_value)
                level = _text(note.get("level")) or "warning"
                if level not in {"none", "note"}:
                    complete = False

        driver = _object(_object(run.get("tool")).get("driver"))
        ordered_rules = [_object(value) for value in _list(driver.get("rules"))]
        rules: dict[str, JsonObject] = {}
        for rule in ordered_rules:
            rule_id = _text(rule.get("id"))
            if rule_id is not None:
                rules[rule_id] = rule

        for result_index, result_value in enumerate(_list(run.get("results"))):
            result = _object(result_value)
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
