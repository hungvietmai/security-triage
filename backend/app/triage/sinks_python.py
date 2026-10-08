"""Python command-execution sink locator using only the standard-library AST."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping, Sequence

from app.triage.types import SinkArgument, SinkRecord, Span

_SUPPORTED_MODULES = {"os", "subprocess", "asyncio", "pty"}
# Match Python's physical lines; str.splitlines() also splits form feeds and Unicode separators.
_PYTHON_LINES = re.compile(r".*?(?:\r\n|\n|\r|$)")


def _span(node: ast.AST) -> Span:
    line = getattr(node, "lineno", None)
    column = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    if not all(isinstance(value, int) for value in (line, column, end_line, end_column)):
        raise ValueError("AST node has no complete source span")
    assert isinstance(line, int)
    assert isinstance(column, int)
    assert isinstance(end_line, int)
    assert isinstance(end_column, int)
    return {
        "startLine": line,
        "startColumn": column + 1,
        "endLine": end_line,
        "endColumn": end_column + 1,
    }


def _segment(lines: Sequence[bytes], node: ast.AST) -> str:
    try:
        span = _span(node)
    except ValueError:
        return ast.unparse(node)
    start, end = span["startLine"] - 1, span["endLine"] - 1
    first, last = span["startColumn"] - 1, span["endColumn"] - 1
    if start == end:
        return lines[start][first:last].decode("utf-8")
    return b"".join([lines[start][first:], *lines[start + 1 : end], lines[end][:last]]).decode(
        "utf-8"
    )


def _value_kind(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return "bool"
        if isinstance(node.value, str):
            return "string"
        return "constant"
    if isinstance(node, ast.List):
        return "list"
    if isinstance(node, ast.Tuple):
        return "tuple"
    if isinstance(node, ast.Dict):
        return "dict"
    if isinstance(node, ast.Name):
        return "name"
    if isinstance(node, ast.Call):
        return "call"
    if isinstance(node, ast.Starred):
        return "starred"
    return node.__class__.__name__.lower()


def _argument(
    lines: Sequence[bytes],
    node: ast.AST,
    *,
    position: int | None,
    keyword: str | None,
) -> SinkArgument:
    literal_bool = (
        node.value if isinstance(node, ast.Constant) and isinstance(node.value, bool) else None
    )
    argument: SinkArgument = {
        "position": position,
        "keyword": keyword,
        "span": _span(node),
        "text": _segment(lines, node),
        "value_kind": _value_kind(node),
        "literal_bool": literal_bool,
    }
    if isinstance(node, (ast.List, ast.Tuple)):
        argument["sequence_items"] = [_span(item) for item in node.elts]
    return argument


def _canonical_supported(name: str) -> bool:
    if name in {
        "os.system",
        "os.popen",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "pty.spawn",
    }:
        return True
    if name.startswith("os.exec") or name.startswith("os.spawn"):
        return True
    return name.startswith("subprocess.")


def _imports(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    modules: dict[str, str] = {}
    direct: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _SUPPORTED_MODULES:
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in _SUPPORTED_MODULES:
            for alias in node.names:
                if alias.name == "*":
                    continue
                direct[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return modules, direct


def _callee(
    node: ast.Call,
    modules: Mapping[str, str],
    direct: Mapping[str, str],
) -> str | None:
    if isinstance(node.func, ast.Name):
        return direct.get(node.func.id)
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        module = modules.get(node.func.value.id)
        if module is not None:
            return f"{module}.{node.func.attr}"
    return None


def locate_python_sinks(path: str, source: str) -> list[SinkRecord]:
    """Return every supported process/command execution call in source.

    Import alias resolution is lexical and import-based only. Constant calls are
    deliberately retained because the locator does not judge vulnerability.
    """
    tree = ast.parse(source, filename=path)
    lines = [match[0].encode("utf-8") for match in _PYTHON_LINES.finditer(source)]
    modules, direct = _imports(tree)
    sinks: list[SinkRecord] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        canonical = _callee(node, modules, direct)
        if canonical is None or not _canonical_supported(canonical):
            continue
        args = [
            _argument(lines, value, position=index, keyword=None)
            for index, value in enumerate(node.args)
        ]
        args.extend(
            _argument(lines, keyword.value, position=None, keyword=keyword.arg)
            for keyword in node.keywords
        )
        sinks.append(
            {
                "path": path,
                "span": _span(node),
                "callee": _segment(lines, node.func),
                "sink_kind": canonical,
                "args": args,
            }
        )

    return sorted(
        sinks,
        key=lambda item: (
            item["span"]["startLine"],
            item["span"]["startColumn"],
            item["span"]["endLine"],
            item["span"]["endColumn"],
            item["sink_kind"],
        ),
    )
