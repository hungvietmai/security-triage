"""Normalize versioned JavaScript sink-locator Semgrep JSON."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import cast

from app.triage.types import SinkArgument, SinkRecord, Span

_LOCATOR_VERSION = "sink-locator-v0"
_CHILD_METHODS = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
    "fork",
}


def _point(value: object, *, name: str) -> tuple[int, int, int]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    raw = cast(dict[object, object], value)
    line, col, offset = raw.get("line"), raw.get("col"), raw.get("offset")
    values = (line, col, offset)
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in values):
        raise ValueError(f"{name} must contain integer line/col/offset")
    return cast(int, line), cast(int, col), cast(int, offset)


def _span(start: tuple[int, int, int], end: tuple[int, int, int]) -> Span:
    return {
        "startLine": start[0],
        "startColumn": start[1],
        "endLine": end[0],
        "endColumn": end[1],
    }


def _slice_utf8(source: str, start: int, end: int) -> str:
    raw = source.encode("utf-8")
    if not 0 <= start <= end <= len(raw):
        raise ValueError("Semgrep byte offsets are outside the source file")
    return raw[start:end].decode("utf-8")


def _line_col_for_byte(source: str, offset: int) -> tuple[int, int]:
    prefix = source.encode("utf-8")[:offset]
    line = prefix.count(b"\n") + 1
    last_newline = prefix.rfind(b"\n")
    column = len(prefix) + 1 if last_newline < 0 else len(prefix) - last_newline
    return line, column


def _argument_ranges(call: str) -> list[tuple[int, int]]:
    open_index = call.find("(")
    close_index = call.rfind(")")
    if open_index < 0 or close_index < open_index:
        return []
    content_start = open_index + 1
    ranges: list[tuple[int, int]] = []
    start = content_start
    depth = 0
    quote: str | None = None
    escaped = False
    index = content_start
    while index < close_index:
        char = call[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            ranges.append((start, index))
            start = index + 1
        index += 1
    if call[start:close_index].strip():
        ranges.append((start, close_index))
    return ranges


def _kind(text: str) -> tuple[str, bool | None]:
    stripped = text.strip()
    if stripped in {"true", "false"}:
        return "bool", stripped == "true"
    if stripped.startswith("["):
        return "list", None
    if stripped.startswith("{"):
        return "dict", None
    if stripped.startswith(("'", '"', "`")):
        return "string", None
    if re.fullmatch(r"[A-Za-z_$][\w$]*", stripped):
        return "name", None
    return "expression", None


def _arguments(source: str, call: str, call_start_byte: int) -> list[SinkArgument]:
    args: list[SinkArgument] = []
    for position, (start, end) in enumerate(_argument_ranges(call)):
        raw = call[start:end]
        leading = len(raw) - len(raw.lstrip())
        trailing = len(raw.rstrip())
        clean_start = start + leading
        clean_end = start + trailing
        text = call[clean_start:clean_end]
        absolute_start = call_start_byte + len(call[:clean_start].encode("utf-8"))
        absolute_end = call_start_byte + len(call[:clean_end].encode("utf-8"))
        start_line, start_col = _line_col_for_byte(source, absolute_start)
        end_line, end_col = _line_col_for_byte(source, absolute_end)
        value_kind, literal_bool = _kind(text)
        args.append(
            {
                "position": position,
                "keyword": None,
                "span": {
                    "startLine": start_line,
                    "startColumn": start_col,
                    "endLine": end_line,
                    "endColumn": end_col,
                },
                "text": text,
                "value_kind": value_kind,
                "literal_bool": literal_bool,
            }
        )
    return args


def _direct_child_aliases(source: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    methods = "|".join(sorted(_CHILD_METHODS, key=len, reverse=True))
    direct = re.compile(
        rf"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"
        rf"require\(['\"]child_process['\"]\)\.({methods})\b"
    )
    for match in direct.finditer(source):
        aliases[match.group(1)] = match.group(2)

    imports = re.compile(r"import\s*{{([^}}]+)}}\s*from\s*['\"]child_process['\"]")
    for match in imports.finditer(source):
        for part in match.group(1).split(","):
            item = part.strip()
            alias_match = re.fullmatch(rf"({methods})(?:\s+as\s+([A-Za-z_$][\w$]*))?", item)
            if alias_match:
                aliases[alias_match.group(2) or alias_match.group(1)] = alias_match.group(1)

    destructured = re.compile(
        r"\b(?:var|let|const)\s*{([^}]+)}\s*=\s*require\(['\"]child_process['\"]\)"
    )
    for match in destructured.finditer(source):
        for part in match.group(1).split(","):
            item = part.strip()
            alias_match = re.fullmatch(rf"({methods})(?:\s*:\s*([A-Za-z_$][\w$]*))?", item)
            if alias_match:
                aliases[alias_match.group(2) or alias_match.group(1)] = alias_match.group(1)
    return aliases


def _canonical_kind(check_id: str, callee: str, source: str) -> str:
    if check_id.endswith("sink-locator-v0-shelljs-namespace"):
        return "shelljs.exec"
    method = callee.rsplit(".", 1)[-1]
    if method in _CHILD_METHODS:
        return f"child_process.{method}"
    resolved = _direct_child_aliases(source).get(callee)
    return f"child_process.{resolved}" if resolved is not None else "child_process.unresolved"


def parse_javascript_sink_output(
    payload: str,
    sources: Mapping[str, str],
) -> list[SinkRecord]:
    """Convert sink-locator-v0 Semgrep JSON into deterministic sink records.

    The Semgrep rules decide which calls are sinks. This reader only normalizes
    their spans, canonical kind and argument text; constant calls are not filtered.
    """
    decoded = cast(object, json.loads(payload))
    if not isinstance(decoded, dict):
        raise ValueError("Semgrep locator output must be an object")
    results = cast(dict[object, object], decoded).get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep locator output must contain results")

    sinks: list[SinkRecord] = []
    for value in cast(list[object], results):
        if not isinstance(value, dict):
            raise ValueError("Semgrep result must be an object")
        result = cast(dict[object, object], value)
        check_id = result.get("check_id")
        path = result.get("path")
        if not isinstance(check_id, str) or _LOCATOR_VERSION not in check_id:
            raise ValueError("Unexpected JavaScript sink-locator rule")
        if not isinstance(path, str) or path not in sources:
            raise ValueError("Semgrep result path is missing from source contents")
        start = _point(result.get("start"), name="start")
        end = _point(result.get("end"), name="end")
        source = sources[path]
        call = _slice_utf8(source, start[2], end[2])
        open_index = call.find("(")
        if open_index < 1:
            raise ValueError("Located JavaScript sink is not a call expression")
        callee = call[:open_index].strip()
        sinks.append(
            {
                "path": path,
                "span": _span(start, end),
                "callee": callee,
                "sink_kind": _canonical_kind(check_id, callee, source),
                "args": _arguments(source, call, start[2]),
            }
        )

    return sorted(
        sinks,
        key=lambda item: (
            item["path"],
            item["span"]["startLine"],
            item["span"]["startColumn"],
            item["span"]["endLine"],
            item["span"]["endColumn"],
            item["sink_kind"],
        ),
    )
