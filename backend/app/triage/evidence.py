"""Conservative, inspectable evidence for each reconciled command sink."""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

from app.triage.reconcile import _argument_role, _normalized_path, _shell_state
from app.triage.types import SinkRecord, Span

_COMMAND = re.compile(r"^[A-Za-z0-9_./ -]+$")
_INTERPRETERS = re.compile(
    r"^(?:sh|bash|dash|ksh|csh|tcsh|zsh|python\d*(?:\.\d+)*|node\d*|perl\d*|ruby\d*|env|eval|exec)$"
)
_ALLOWED_SHELL = {
    "child_process.exec",
    "child_process.execSync",
    "shelljs.exec",
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_shell",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}
_SUBPROCESS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
_JS_SPAWN = {"child_process.spawn", "child_process.spawnSync"}
_STATUSES = {"mapped", "role_unresolved", "unmapped", "column_encoding_requires_review"}
_ROLES = {"shell_command", "executable", "argument_list", None}


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _span(value: Any) -> Span | None:
    obj = _obj(value)
    line = obj.get("startLine")
    end = obj.get("endLine", line)
    col = obj.get("startColumn")
    end_col = obj.get("endColumn")
    if not all(type(x) is int and x > 0 for x in (line, end, col, end_col)):
        return None
    if (end, end_col) <= (line, col):
        return None
    return {
        "startLine": cast(int, line),
        "endLine": cast(int, end),
        "startColumn": cast(int, col),
        "endColumn": cast(int, end_col),
    }


def _contains(outer: Span, inner: Span) -> bool:
    return (outer["startLine"], outer["startColumn"]) <= (
        inner["startLine"],
        inner["startColumn"],
    ) and (inner["endLine"], inner["endColumn"]) <= (outer["endLine"], outer["endColumn"])


def _source_span(source: str, span: Span) -> str | None:
    lines = source.splitlines(keepends=True)
    a, b = span["startLine"], span["endLine"]
    if a < 1 or b > len(lines) or any(not lines[i - 1].isascii() for i in range(a, b + 1)):
        return None
    if span["startColumn"] > len(lines[a - 1]) + 1 or span["endColumn"] > len(lines[b - 1]) + 1:
        return None
    result = "".join(lines[a - 1 : b])
    start = span["startColumn"] - 1
    end = sum(len(line) for line in lines[a - 1 : b - 1]) + span["endColumn"] - 1
    return result[start:end]


def _argument_span(sink: SinkRecord, endpoint: Span) -> Span | None:
    """Only the execution arguments count: options, mode and wrapper spans never do."""
    kind = sink["sink_kind"]
    positions = {0} if kind in _ALLOWED_SHELL | _SUBPROCESS | _JS_SPAWN else {0, 1}
    if kind == "os.popen":
        positions = {0}
    if kind.startswith("os.spawn"):
        positions = {1, 2}
    candidates = [
        arg["span"]
        for arg in sink["args"]
        if arg["position"] in positions and _contains(arg["span"], endpoint)
    ]
    if len(candidates) != 1:
        return None
    argument = next(arg for arg in sink["args"] if arg["span"] == candidates[0])
    if argument["value_kind"] in {"list", "tuple"}:
        items = [item for item in argument.get("sequence_items", []) if _contains(item, endpoint)]
        return items[0] if len(items) == 1 else None
    return candidates[0]


def _trace(
    finding: Mapping[str, Any],
    sink: SinkRecord | None,
    unit: Mapping[str, Any],
    sources: Mapping[str, str],
) -> dict[str, Any]:
    flows = _obj(finding.get("raw_result")).get("codeFlows")
    initial: dict[str, Any] = {
        "trace_status": "missing",
        "trace_ref": None,
        "trace_length": 0,
        "source_location": None,
        "endpoint_location": None,
        "endpoint_argument_span": None,
        "endpoint_role": None,
        "has_trace": isinstance(flows, list) and bool(flows),
    }
    if flows is None or flows == []:
        return initial
    if not isinstance(flows, list):
        return {**initial, "trace_status": "malformed"}
    best: dict[str, Any] = {**initial, "trace_status": "malformed"}
    rank = {
        "malformed": 0,
        "endpoint_unresolved": 1,
        "coordinate_unverified": 2,
        "endpoint_mismatch": 3,
        "valid_endpoint": 4,
    }
    for fi, flow in enumerate(flows):
        threads = _obj(flow).get("threadFlows")
        if not isinstance(threads, list):
            continue
        for ti, thread in enumerate(threads):
            locations = _obj(thread).get("locations")
            if not isinstance(locations, list) or len(locations) < 2:
                continue
            orders = [_obj(loc).get("executionOrder") for loc in locations]
            if all(type(x) is int for x in orders) and len(set(orders)) == len(orders):
                locations = [x for _, x in sorted(zip(orders, locations, strict=True))]
            elif any(x is not None for x in orders):
                continue
            refs: list[dict[str, Any]] = []
            valid = True
            for loc in locations:
                physical = _obj(_obj(loc).get("location")).get("physicalLocation")
                physical = _obj(physical)
                path = _normalized_path(_obj(physical.get("artifactLocation")).get("uri"))
                region = _span(physical.get("region"))
                if path is None or region is None:
                    valid = False
                    break
                refs.append({"path": path, "span": region})
            if not valid:
                continue
            endpoint = refs[-1]
            candidate: dict[str, Any] = {
                **initial,
                "trace_ref": {"codeFlow": fi, "threadFlow": ti},
                "trace_length": len(refs),
                "source_location": refs[0],
                "endpoint_location": endpoint,
                "trace_status": "endpoint_unresolved",
            }
            if sink is None or unit.get("path") != endpoint["path"]:
                pass
            elif any(
                ref["path"] not in sources
                or _source_span(sources[ref["path"]], ref["span"]) is None
                for ref in refs
            ):
                candidate["trace_status"] = "coordinate_unverified"
            else:
                arg = _argument_span(sink, endpoint["span"])
                if arg is None or not _contains(sink["span"], endpoint["span"]):
                    candidate["trace_status"] = "endpoint_mismatch"
                else:
                    role = _argument_role(sink, endpoint["span"])
                    candidate.update(endpoint_argument_span=arg, endpoint_role=role)
                    candidate["trace_status"] = (
                        "valid_endpoint"
                        if role in {"shell_command", "executable"}
                        else "endpoint_mismatch"
                    )
            if rank[candidate["trace_status"]] > rank[best["trace_status"]]:
                best = candidate
    return best


def _python_literal(text: str) -> str | None:
    try:
        tree = ast.parse(text, mode="eval").body
    except (SyntaxError, ValueError):
        return None

    def resolve(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = resolve(node.left), resolve(node.right)
            return left + right if left is not None and right is not None else None
        return None

    return resolve(tree)


_JS_TOKEN = re.compile(
    r"\s*([()+]|'(?:[^'\\\r\n]|\\[\\'\"nrt])*'|\"(?:[^\"\\\r\n]|\\[\\'\"nrt])*\")"
)


def _js_literal(text: str) -> str | None:
    tokens = []
    index = 0
    while index < len(text):
        token = _JS_TOKEN.match(text, index)
        if token is None:
            return None
        tokens.append(token.group(1))
        index = token.end()
    if not tokens:
        return None

    def atom(pos: int) -> tuple[str | None, int]:
        if pos >= len(tokens):
            return None, pos
        token = tokens[pos]
        if token == "(":
            value, end = expression(pos + 1)
            return (value, end + 1) if end < len(tokens) and tokens[end] == ")" else (None, end)
        if token.startswith(("'", '"')):
            try:
                value = ast.literal_eval(token)
            except (ValueError, SyntaxError):
                return None, pos + 1
            return (value, pos + 1) if isinstance(value, str) else (None, pos + 1)
        return None, pos + 1

    def expression(pos: int) -> tuple[str | None, int]:
        value, pos = atom(pos)
        while value is not None and pos < len(tokens) and tokens[pos] == "+":
            other, pos = atom(pos + 1)
            value = value + other if other is not None else None
        return value, pos

    value, end = expression(0)
    return value if end == len(tokens) else None


def _safe_command(value: str | None) -> bool:
    if value is None or not value.strip() or not _COMMAND.fullmatch(value):
        return False
    first = value.strip().split()[0].rsplit("/", 1)[-1]
    return not _INTERPRETERS.fullmatch(first)


def _literal_proof(sink: SinkRecord | None, source: str | None) -> dict[str, Any] | None:
    if sink is None or source is None:
        return None
    kind = sink["sink_kind"]
    if kind not in _ALLOWED_SHELL | _SUBPROCESS | _JS_SPAWN:
        return None
    args = sink["args"]
    if any(_source_span(source, a["span"]) != a["text"] for a in args):
        return None
    first = next((a for a in args if a["position"] == 0), None)
    if first is None:
        return None
    python = kind.startswith(("subprocess.", "os.", "asyncio."))
    resolver = _python_literal if python else _js_literal
    command = resolver(first["text"])
    if not _safe_command(command):
        return None
    if kind in _SUBPROCESS:
        others = [a for a in args if a is not first]
        if (
            len(others) != 1
            or others[0]["keyword"] != "shell"
            or others[0]["literal_bool"] is not True
        ):
            return None
    elif kind in _JS_SPAWN:
        rest = sorted((a for a in args if a is not first), key=lambda a: a["position"] or -1)
        if not rest or rest[-1]["position"] not in {1, 2}:
            return None
        options = rest[-1]["text"]
        if not re.fullmatch(r"\{\s*shell\s*:\s*true\s*\}", options):
            return None
        if len(rest) == 2:
            argv = rest[0]["text"].strip()
            if not (argv.startswith("[") and argv.endswith("]")):
                return None
            literal = r"(?:'(?:[^'\\\r\n]|\\[\\'\"nrt])*'|\"(?:[^\"\\\r\n]|\\[\\'\"nrt])*\")"
            body = argv[1:-1]
            if re.fullmatch(rf"\s*(?:{literal}(?:\s*,\s*{literal})*)?\s*", body) is None:
                return None
            items = re.findall(literal, body)
            if any(not _safe_command(resolver(item)) for item in items):
                return None
            command = (command or "") + " " + " ".join(resolver(item) or "" for item in items)
        elif len(rest) != 1 or rest[0]["position"] != 1:
            return None
    elif kind.startswith("os.") or kind.startswith("asyncio."):
        if len(args) != 1:
            return None
    elif kind.startswith("subprocess."):
        if len(args) != 1:
            return None
    elif kind.startswith("child_process.") or kind == "shelljs.exec":
        if len(args) != 1:
            return None
    if not _safe_command(command):
        return None
    segment = _source_span(source, sink["span"])
    if segment is None:
        return None
    return {
        "id": "whole_command_literal_v1",
        "sink_kind": kind,
        "sink_span": sink["span"],
        "source_sha256": hashlib.sha256(segment.encode()).hexdigest(),
        "expression": first["text"],
        "resolved_command": command,
        "assumptions": "trusted POSIX runtime, executable and environment",
    }


def build_evidence(
    unit: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    claims: Sequence[Mapping[str, Any]],
    sinks: Sequence[SinkRecord],
    sources: Mapping[str, str],
) -> dict[str, Any]:
    """Join the exact unit, its findings and one sink; ambiguity remains visible."""
    ids = unit["raw_finding_ids"]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Unit needs distinct, nonempty findings")
    by_id = {f["raw_id"]: f for f in findings}
    by_claim = {c["raw_id"]: c for c in claims}
    if (
        len(by_id) != len(findings)
        or len(by_claim) != len(claims)
        or any(i not in by_id or i not in by_claim for i in ids)
    ):
        raise ValueError("Missing or duplicate finding/claim")
    status, role = unit["mapping_status"], unit["argument_role"]
    if status not in _STATUSES or role not in _ROLES:
        raise ValueError("Unknown mapping status or argument role")
    matches = [
        s
        for s in sinks
        if s["path"] == unit.get("path")
        and s["span"] == unit.get("sink_span")
        and s["sink_kind"] == unit.get("sink_kind")
    ]
    sink = matches[0] if len(matches) == 1 else None
    shell = _shell_state(sink) if sink else "unresolved"
    path = unit.get("path")
    source = sources.get(path) if isinstance(path, str) else None
    proof = _literal_proof(sink, source)
    records = []
    for identifier in ids:
        claim = by_claim[identifier]
        trace = _trace(by_id[identifier], sink, unit, sources)
        records.append({**claim, **trace})
    unknown = []
    if role is None:
        unknown.append("argument_role_null")
    if shell == "unresolved":
        unknown.append("shell_unresolved")
    if sink and any(a["value_kind"] == "name" or "..." in a["text"] for a in sink["args"][1:]):
        unknown.append("options_variable_or_spread")
    if any(c["source_type"] in {"unknown", "library_input"} for c in records):
        unknown.append("source_library_input_or_unknown")
    if any(c["claim_family"] == "flow" and c["trace_status"] != "valid_endpoint" for c in records):
        unknown.append("flow_claim_without_valid_endpoint_trace")
    if any(c["claim_family"] == "classification_unresolved" for c in records):
        unknown.append("some_claims_classification_unresolved")
    if sink is None or source is None:
        unknown.append("source_or_argument_parsing_unavailable")
    strong = any(
        c["claim_family"] == "flow" and c["trace_status"] == "valid_endpoint" for c in records
    )
    tools = sorted({by_id[i]["tool"] for i in ids})
    signals = {
        "execution_candidate": status in {"mapped", "role_unresolved"},
        "unresolved_unit": status in {"unmapped", "column_encoding_requires_review"}
        or all(c["claim_family"] == "classification_unresolved" for c in records),
        "flow_claim": any(c["claim_family"] == "flow" for c in records),
        "audit_claim": any(c["audit_oriented"] for c in records),
        "strong_flow": strong,
        "shell_semantics": role == "shell_command",
        "agreement": set(tools) >= {"semgrep", "codeql"},
        "verified_blocker": proof is not None,
        "important_unknown": bool(unknown),
        "evidence_conflict": proof is not None and strong,
    }
    lengths = {tool: [r["trace_length"] for r in records if r["tool"] == tool] for tool in tools}
    return {
        "unit_id": unit["unit_id"],
        "mapping_status": status,
        "argument_role": role,
        "shell_state": shell,
        "command_literal": proof is not None,
        "blocker_proof": proof,
        "tools": tools,
        "source_types": sorted({r["source_type"] for r in records}),
        "trace_lengths_by_tool": lengths,
        "traces_by_tool": {
            tool: any(r["has_trace"] for r in records if r["tool"] == tool) for tool in tools
        },
        "finding_evidence": records,
        "unknown_fields": sorted(set(unknown)),
        "predicate_values": signals,
    }
