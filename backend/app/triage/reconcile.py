"""Pure reconciliation of normalized findings to canonical sink units."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Literal, TypedDict, cast

from app.triage.types import SinkRecord, Span

MappingStatus = Literal[
    "mapped",
    "unmapped",
    "role_unresolved",
    "column_encoding_requires_review",
]
MappingMethod = Literal["explicit_link", "containment", "exact_span"]


class UnitMapping(TypedDict):
    raw_id: str
    tool: str
    mapping_status: MappingStatus
    mapping_method: MappingMethod | None


class ReconciledUnit(TypedDict):
    unit_id: str
    snapshot_sha256: str
    path: str | None
    sink_span: Span | None
    reported_region: dict[str, object] | None
    argument_role: str | None
    sink_kind: str | None
    callee: str | None
    mapping_status: MappingStatus
    raw_finding_ids: list[str]
    tools: list[str]
    mappings: list[UnitMapping]


_SHELL_COMMAND_KINDS = {
    "child_process.exec",
    "child_process.execSync",
    "shelljs.exec",
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_shell",
}
_JS_PROCESS_KINDS = {
    "child_process.spawn",
    "child_process.spawnSync",
    "child_process.execFile",
    "child_process.execFileSync",
    "child_process.fork",
}
_SHELL_LINK = re.compile(r"\[shell command\]\((\d+)\)")


def _dictionary(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {
        key: item
        for key, item in cast(dict[object, object], value).items()
        if isinstance(key, str)
    }


def _objects(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [_dictionary(item) for item in cast(list[object], value) if isinstance(item, dict)]


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _region(value: object) -> Span | None:
    raw = _dictionary(value)
    start_line = _integer(raw.get("startLine"))
    if start_line is None:
        return None
    start_column = _integer(raw.get("startColumn")) or 1
    end_line = _integer(raw.get("endLine")) or start_line
    end_column = _integer(raw.get("endColumn")) or start_column
    return {
        "startLine": start_line,
        "startColumn": start_column,
        "endLine": end_line,
        "endColumn": end_column,
    }


def _point(span: Span, *, end: bool) -> tuple[int, int]:
    if end:
        return span["endLine"], span["endColumn"]
    return span["startLine"], span["startColumn"]


def _contains(outer: Span, inner: Span, *, strict: bool = False) -> bool:
    contains = _point(outer, end=False) <= _point(inner, end=False) and _point(
        inner, end=True
    ) <= _point(outer, end=True)
    return contains and (not strict or outer != inner)


def _canonical_id(identity: Mapping[str, object]) -> str:
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalized_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _innermost(sinks: Sequence[SinkRecord]) -> SinkRecord | None:
    candidates = [
        sink
        for sink in sinks
        if all(
            sink is other or _contains(other["span"], sink["span"])
            for other in sinks
        )
    ]
    return candidates[0] if len(candidates) == 1 else None


def _relevant_lines(span: Span) -> range:
    return range(span["startLine"], span["endLine"] + 1)


def _has_non_ascii(
    path: str,
    evidence: Span,
    sink: SinkRecord,
    sources: Mapping[str, str],
) -> bool:
    source = sources.get(path)
    if source is None:
        return False
    lines = source.splitlines()
    line_numbers = set(_relevant_lines(evidence)) | set(_relevant_lines(sink["span"]))
    for line_number in line_numbers:
        if 1 <= line_number <= len(lines) and not lines[line_number - 1].isascii():
            return True
    return False


def _shell_true(sink: SinkRecord) -> bool:
    for argument in sink["args"]:
        if argument["keyword"] == "shell" and argument["literal_bool"] is True:
            return True
        if argument["value_kind"] == "dict" and re.search(
            r"(?:^|[,{]\s*)shell\s*:\s*true(?:\s*[,}]|$)",
            argument["text"],
        ):
            return True
    return False


def _argument_for_evidence(sink: SinkRecord, evidence: Span) -> int | None:
    positions = {
        argument["position"]
        for argument in sink["args"]
        if argument["position"] is not None and _contains(argument["span"], evidence)
    }
    return positions.pop() if len(positions) == 1 else None


def _argument_role(sink: SinkRecord, evidence: Span) -> str | None:
    kind = sink["sink_kind"]
    if kind in _SHELL_COMMAND_KINDS:
        return "shell_command"

    if kind in _JS_PROCESS_KINDS:
        if _shell_true(sink):
            return "shell_command"
        position = _argument_for_evidence(sink, evidence)
        if position == 0:
            return "executable"
        if position == 1:
            return "argument_list"
        return None

    if kind.startswith("subprocess."):
        if _shell_true(sink):
            return "shell_command"
        position = _argument_for_evidence(sink, evidence)
        if position == 0:
            first = next(
                (arg for arg in sink["args"] if arg["position"] == 0),
                None,
            )
            if first is not None and first["value_kind"] not in {"list", "tuple"}:
                return "executable"
        return None

    if kind == "asyncio.create_subprocess_exec":
        position = _argument_for_evidence(sink, evidence)
        if position == 0:
            return "executable"
        if position is not None and position > 0:
            return "argument_list"
        return None

    if kind == "pty.spawn" or kind.startswith("os.exec") or kind.startswith("os.spawn"):
        position = _argument_for_evidence(sink, evidence)
        if position == 0:
            return "executable"
        if position is not None and position > 0:
            return "argument_list"
    return None


def _related_shell_location(finding: Mapping[str, object]) -> tuple[str, Span] | None:
    message = finding.get("message")
    if not isinstance(message, str):
        return None
    identifiers = {int(match) for match in _SHELL_LINK.findall(message)}
    if len(identifiers) != 1:
        return None
    target_id = next(iter(identifiers))
    raw_result = _dictionary(finding.get("raw_result"))
    matches: list[tuple[str, Span]] = []
    for related in _objects(raw_result.get("relatedLocations")):
        if _integer(related.get("id")) != target_id:
            continue
        physical = _dictionary(related.get("physicalLocation"))
        artifact = _dictionary(physical.get("artifactLocation"))
        path = _normalized_path(artifact.get("uri"))
        region = _region(physical.get("region"))
        if path is not None and region is not None:
            matches.append((path, region))
    return matches[0] if len(matches) == 1 else None


def _mapped_unit(
    finding: Mapping[str, object],
    sink: SinkRecord,
    evidence: Span,
    *,
    method: MappingMethod,
    sources: Mapping[str, str],
) -> ReconciledUnit:
    snapshot = str(finding.get("snapshot_sha256") or "")
    path = _normalized_path(sink["path"])
    assert path is not None
    raw_id = str(finding.get("raw_id") or "")
    tool = str(finding.get("tool") or "")
    if _has_non_ascii(path, evidence, sink, sources):
        return _fallback_unit(
            finding,
            mapping_status="column_encoding_requires_review",
            method=None,
        )

    role = _argument_role(sink, evidence)
    status: MappingStatus = "mapped" if role is not None else "role_unresolved"
    identity: dict[str, object] = {
        "snapshot_sha256": snapshot,
        "path": path,
        "sink_span": sink["span"],
        "argument_role": role,
    }
    return {
        "unit_id": _canonical_id(identity),
        "snapshot_sha256": snapshot,
        "path": path,
        "sink_span": sink["span"],
        "reported_region": None,
        "argument_role": role,
        "sink_kind": sink["sink_kind"],
        "callee": sink["callee"],
        "mapping_status": status,
        "raw_finding_ids": [raw_id],
        "tools": [tool],
        "mappings": [
            {
                "raw_id": raw_id,
                "tool": tool,
                "mapping_status": status,
                "mapping_method": method,
            }
        ],
    }


def _fallback_unit(
    finding: Mapping[str, object],
    *,
    mapping_status: MappingStatus = "unmapped",
    method: MappingMethod | None = None,
) -> ReconciledUnit:
    snapshot = str(finding.get("snapshot_sha256") or "")
    path = _normalized_path(finding.get("reported_path"))
    raw_region = _dictionary(finding.get("reported_region"))
    raw_id = str(finding.get("raw_id") or "")
    tool = str(finding.get("tool") or "")
    identity: dict[str, object] = {
        "snapshot_sha256": snapshot,
        "path": path,
        "reported_region": raw_region,
    }
    if path is None or _region(raw_region) is None:
        identity["raw_id"] = raw_id
    return {
        "unit_id": _canonical_id(identity),
        "snapshot_sha256": snapshot,
        "path": path,
        "sink_span": None,
        "reported_region": raw_region,
        "argument_role": None,
        "sink_kind": None,
        "callee": None,
        "mapping_status": mapping_status,
        "raw_finding_ids": [raw_id],
        "tools": [tool],
        "mappings": [
            {
                "raw_id": raw_id,
                "tool": tool,
                "mapping_status": mapping_status,
                "mapping_method": method,
            }
        ],
    }


def _match_one(
    finding: Mapping[str, object],
    sinks: Sequence[SinkRecord],
    sources: Mapping[str, str],
) -> ReconciledUnit:
    related = _related_shell_location(finding)
    if related is not None:
        related_path, related_region = related
        related_sinks = [
            sink
            for sink in sinks
            if _normalized_path(sink["path"]) == related_path
            and _contains(sink["span"], related_region)
        ]
        selected = _innermost(related_sinks)
        if selected is not None:
            return _mapped_unit(
                finding,
                selected,
                related_region,
                method="explicit_link",
                sources=sources,
            )

    path = _normalized_path(finding.get("reported_path"))
    primary = _region(finding.get("reported_region"))
    if path is None or primary is None:
        return _fallback_unit(finding)

    same_path = [sink for sink in sinks if _normalized_path(sink["path"]) == path]
    containing = [
        sink for sink in same_path if _contains(sink["span"], primary, strict=True)
    ]
    selected = _innermost(containing)
    if selected is not None:
        return _mapped_unit(
            finding,
            selected,
            primary,
            method="containment",
            sources=sources,
        )

    exact = [sink for sink in same_path if sink["span"] == primary]
    if len(exact) == 1:
        return _mapped_unit(
            finding,
            exact[0],
            primary,
            method="exact_span",
            sources=sources,
        )
    return _fallback_unit(finding)


def reconcile_findings(
    findings: Sequence[Mapping[str, object]],
    sinks: Sequence[SinkRecord],
    sources: Mapping[str, str],
) -> list[ReconciledUnit]:
    """Map raw findings to deterministic canonical units without side effects."""
    by_id: dict[str, ReconciledUnit] = {}
    for finding in findings:
        unit = _match_one(finding, sinks, sources)
        existing = by_id.get(unit["unit_id"])
        if existing is None:
            by_id[unit["unit_id"]] = unit
            continue
        existing["raw_finding_ids"] = sorted(
            set(existing["raw_finding_ids"] + unit["raw_finding_ids"])
        )
        existing["tools"] = sorted(set(existing["tools"] + unit["tools"]))
        existing["mappings"].extend(unit["mappings"])
        existing["mappings"].sort(key=lambda item: (item["tool"], item["raw_id"]))

    return sorted(
        by_id.values(),
        key=lambda unit: (
            unit["path"] or "",
            unit["sink_span"]["startLine"] if unit["sink_span"] is not None else 0,
            unit["sink_span"]["startColumn"] if unit["sink_span"] is not None else 0,
            unit["argument_role"] or "",
            unit["unit_id"],
        ),
    )
