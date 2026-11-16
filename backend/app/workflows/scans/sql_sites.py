"""Where a Python source executes a SQL statement: the call sites alerts of several tools share.

Alerts of the sql-injection family are merged into one unit only when there is evidence that
they point to the same point of SQL execution. Here that evidence is a located call: an alert
whose reported region lies inside the span of one call below is about that call. Anything
else stays a unit of its own.

A call is a SQL execution site when it is

- a method call named `execute`, `executemany` or `executescript` (DB-API 2.0 / PEP 249 cursors
  and connections, sqlite3, SQLAlchemy connections and sessions), `raw` (Django managers) or
  `extra` (Django query sets); or
- a call of a name or attribute named `RawSQL` (Django expressions).

The receiver's type is not checked: merging only ever joins alerts that already claim SQL
injection inside the same call, so a call that is not really SQL can at worst keep two alerts
about it together. Lines that are not pure ASCII are left out, because the tools count columns
differently there (UTF-8 bytes, UTF-16 units or characters) and a column-based containment
could not be trusted. A file that does not parse yields no site.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, TypedDict

from app.triage.types import Span

LOCATOR_VERSION = "sql-call-site-v1"
EXECUTION_METHODS = frozenset({"execute", "executemany", "executescript", "raw", "extra"})
EXECUTION_CALLEES = frozenset({"RawSQL"})

# Version 2 also follows a SQL string from the statement that builds it to the call that runs it.
LINK_LOCATOR_VERSION = "sql-call-site-v2"
LINKED = "linked"
# Why an alert on a string-building statement is not linked to an execution call.
NOT_IN_ASSIGNMENT = "not_in_simple_assignment"
NOT_STRING_OF_VALUE = "not_sql_string_of_value"
REBOUND = "variable_bound_more_than_once"
NESTED_USE = "variable_used_in_nested_scope"
NO_EXECUTION_CALL = "no_execution_call_takes_variable"
SEVERAL_EXECUTION_CALLS = "several_execution_calls_take_variable"
OTHER_USE = "variable_used_elsewhere"
USED_BEFORE = "used_before_assignment"
NOT_ASCII = "non_ascii_lines"


class SqlSite(TypedDict):
    path: str
    span: Span
    callee: str


class SqlString(TypedDict):
    """A statement `name = <string expression>` and what became of the string it builds."""

    path: str
    variable: str
    statement: Span
    # The string literals and f-strings the value is built from, through `+`, `%`, `.format`.
    strings: list[Span]
    # The one execution call that takes the variable as its first argument, when linked.
    site: SqlSite | None
    reason: str


def _callee(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Attribute):
        if function.attr in EXECUTION_METHODS or function.attr in EXECUTION_CALLEES:
            return ast.unparse(function)
        return None
    if isinstance(function, ast.Name) and function.id in EXECUTION_CALLEES:
        return function.id
    return None


def _span(node: ast.expr | ast.stmt, lines: Sequence[str]) -> Span | None:
    """The SARIF region of a node, or None when one of its lines is not pure ASCII."""
    end_line, end_column = node.end_lineno, node.end_col_offset
    if end_line is None or end_column is None:
        return None
    if not all(text.isascii() for text in lines[node.lineno - 1 : end_line]):
        return None
    # ast counts UTF-8 bytes from 0; on ASCII lines that equals SARIF's 1-based column - 1.
    return {
        "startLine": node.lineno,
        "startColumn": node.col_offset + 1,
        "endLine": end_line,
        "endColumn": end_column + 1,
    }


def _site(path: str, node: ast.Call, lines: Sequence[str]) -> SqlSite | None:
    callee = _callee(node)
    span = _span(node, lines) if callee is not None else None
    if callee is None or span is None:
        return None
    return {"path": path, "span": span, "callee": callee}


def locate_sql_sites(path: str, text: str) -> list[SqlSite]:
    """Every SQL execution call of one Python file, in source order; raises SyntaxError."""
    tree = ast.parse(text, filename=path)
    lines = text.splitlines()
    sites: list[SqlSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            site = _site(path, node, lines)
            if site is not None:
                sites.append(site)
    sites.sort(key=lambda site: (site["span"]["startLine"], site["span"]["startColumn"]))
    return sites


# Scopes whose names are not the enclosing scope's: a statement in one cannot be followed from
# outside, so a name used inside one is treated as an unknown use.
_NESTED = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_STATEMENT_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _scope_roots(scope: ast.AST) -> list[ast.AST]:
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return [scope.args, *scope.body]
    if isinstance(scope, (ast.Module, ast.ClassDef)):
        return list(scope.body)
    return []


def _scope_nodes(scope: ast.AST) -> tuple[list[ast.AST], list[ast.AST]]:
    """The nodes that belong to `scope` itself, and the nested scopes found in it."""
    direct: list[ast.AST] = []
    nested: list[ast.AST] = []
    stack = _scope_roots(scope)
    while stack:
        node = stack.pop()
        if isinstance(node, _NESTED):
            nested.append(node)
            continue
        direct.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return direct, nested


def _string_parts(node: ast.expr) -> Iterator[ast.expr]:
    """String literals and f-strings a value is built from through `+`, `%` and `str.format`.

    An f-string counts as a whole and by each of its literal parts: since Python 3.12 those
    parts carry their own positions, and Bandit reports such a part.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node
    elif isinstance(node, ast.JoinedStr):
        yield node
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                yield value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        yield from _string_parts(node.left)
        yield from _string_parts(node.right)
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        yield from _string_parts(node.func.value)


def _bindings(
    direct: Sequence[ast.AST], nested: Sequence[ast.AST]
) -> tuple[Counter[str], set[str]]:
    """How often each name is bound in a scope, and the names it declares global or nonlocal."""
    bound: Counter[str] = Counter()
    declared: set[str] = set()
    for node in direct:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound[node.id] += 1
        elif isinstance(node, ast.arg):
            bound[node.arg] += 1
        elif isinstance(node, ast.alias):
            bound[node.asname or node.name.split(".")[0]] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound[node.name] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            declared.update(node.names)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound[node.rest] += 1
    for node in nested:
        name = getattr(node, "name", None)
        if isinstance(name, str):
            bound[name] += 1
    return bound, declared


def _scope_strings(scope: ast.AST, path: str, lines: Sequence[str]) -> list[SqlString]:
    direct, nested = _scope_nodes(scope)
    bound, declared = _bindings(direct, nested)
    in_nested = {
        node.id for inner in nested for node in ast.walk(inner) if isinstance(node, ast.Name)
    }
    loads: dict[str, list[ast.Name]] = {}
    for node in direct:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loads.setdefault(node.id, []).append(node)
    # The call that takes a bare name as its first positional argument, for execution calls.
    executing: dict[int, ast.Call] = {}
    for node in direct:
        if isinstance(node, ast.Call) and _callee(node) is not None and node.args:
            first = node.args[0]
            if isinstance(first, ast.Name):
                executing[id(first)] = node
    found: list[SqlString] = []
    for node in direct:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None and node.simple:
            target, value = node.target, node.value
        else:
            continue
        if not isinstance(target, ast.Name):
            continue
        statement: Span = {
            "startLine": node.lineno,
            "startColumn": node.col_offset + 1,
            "endLine": node.end_lineno or node.lineno,
            "endColumn": (node.end_col_offset or 0) + 1,
        }
        ascii_lines = _span(node, lines) is not None
        parts = [_span(part, lines) for part in _string_parts(value)]
        strings = [part for part in parts if part is not None]
        name = target.id
        uses = loads.get(name, [])
        calls = [executing[id(use)] for use in uses if id(use) in executing]
        site: SqlSite | None = None
        if not ascii_lines or len(strings) != len(parts):
            reason = NOT_ASCII
        elif name in declared or bound[name] != 1:
            reason = REBOUND
        elif name in in_nested:
            reason = NESTED_USE
        elif not calls:
            reason = NO_EXECUTION_CALL
        elif len(calls) > 1:
            reason = SEVERAL_EXECUTION_CALLS
        elif len(uses) > 1:
            reason = OTHER_USE
        elif (calls[0].lineno, calls[0].col_offset) < (
            node.end_lineno or 0,
            node.end_col_offset or 0,
        ):
            reason = USED_BEFORE
        else:
            site = _site(path, calls[0], lines)
            reason = LINKED if site is not None else NOT_ASCII
        found.append(
            {
                "path": path,
                "variable": name,
                "statement": statement,
                "strings": strings,
                "site": site,
                "reason": reason,
            }
        )
    return found


def locate_sql_strings(path: str, text: str) -> list[SqlString]:
    """Every `name = <string expression>` of one Python file, linked or not; raises SyntaxError.

    A statement is linked to an execution call when, in its own scope (module, class or
    function), the name is bound by this statement only, is not used in a nested scope, and is
    read exactly once: as the first positional argument of one execution call after the
    statement. Anything else (a second binding, `+=`, a parameter of that name, `global`, a
    second execution call, any other read, a project's own wrapper taking the string) leaves the
    statement unlinked, with the reason.
    """
    tree = ast.parse(text, filename=path)
    lines = text.splitlines()
    found: list[SqlString] = []
    for scope in ast.walk(tree):
        if isinstance(scope, _STATEMENT_SCOPES):
            found.extend(_scope_strings(scope, path, lines))
    found.sort(key=lambda item: item["statement"]["startLine"])
    return found


def locate_all_strings(sources: Mapping[str, str]) -> list[SqlString]:
    """String-building statements of every file; a file that does not parse has none."""
    found: list[SqlString] = []
    for path in sorted(sources):
        try:
            found.extend(locate_sql_strings(path, sources[path]))
        except (SyntaxError, ValueError, RecursionError):
            continue
    return found


def string_link(
    region: Mapping[str, Any] | None, path: str | None, strings: Sequence[SqlString]
) -> tuple[SqlString | None, str]:
    """The string-building statement a reported region is one of the literals of, and its fate.

    The region must be exactly one of the string literals (or f-strings) the assigned value is
    built from, as Bandit's B608 reports it; a region anywhere else in the statement is not
    evidence that it is the assigned SQL string.

    The region is compared by its start and its end column, not its end line: for a string over
    several lines Bandit 1.9.4 writes the literal's start and end column but an `endLine` that
    is not the literal's last line. Two literals cannot start at the same position, so the
    start alone names the literal.
    """
    corners = _corners(region) if region is not None else None
    if corners is None or path is None:
        return None, NOT_IN_ASSIGNMENT
    start, end_column = corners[0], corners[1][1]
    for item in strings:
        if item["path"] != path:
            continue
        statement = _corners(item["statement"])
        if statement is None or not (statement[0] <= start <= statement[1]):
            continue
        for part in item["strings"]:
            literal = _corners(part)
            if literal is not None and literal[0] == start and literal[1][1] == end_column:
                return item, item["reason"]
        return item, NOT_STRING_OF_VALUE
    return None, NOT_IN_ASSIGNMENT


def locate_all(sources: Mapping[str, str]) -> tuple[list[SqlSite], list[str]]:
    """Sites of every file, and the files that did not parse (they have no site)."""
    sites: list[SqlSite] = []
    unparsed: list[str] = []
    for path in sorted(sources):
        try:
            sites.extend(locate_sql_sites(path, sources[path]))
        except (SyntaxError, ValueError, RecursionError):
            unparsed.append(path)
    return sites, unparsed


def _corners(span: Mapping[str, Any]) -> tuple[tuple[int, int], tuple[int, int]] | None:
    """Start and end of a region; SARIF lets a one-line region leave out `endLine`."""
    try:
        start_line = int(span["startLine"])
        start = (start_line, int(span["startColumn"]))
        end = (int(span.get("endLine", start_line)), int(span["endColumn"]))
    except (KeyError, TypeError, ValueError):
        return None
    return start, end


def site_of(
    region: Mapping[str, Any] | None, path: str | None, sites: Sequence[SqlSite]
) -> SqlSite | None:
    """The innermost site whose call contains the whole reported region, or None.

    A region without both columns, or one that no single call contains, has no site. A
    missing `endLine` means the region ends on its start line (SARIF 2.1.0, 3.30.6).
    """
    if region is None or path is None:
        return None
    corners = _corners(region)
    if corners is None:
        return None
    start, end = corners
    containing = []
    for site in sites:
        if site["path"] != path:
            continue
        outer = _corners(site["span"])
        assert outer is not None
        if outer[0] <= start and end <= outer[1]:
            containing.append(site)
    if not containing:
        return None

    # Calls nest, so the calls containing one region form a chain: the innermost starts last
    # and, among those, ends first. Two different calls with the same span cannot exist.
    def inner_first(site: SqlSite) -> tuple[int, int, int, int]:
        outer = _corners(site["span"])
        assert outer is not None
        return (-outer[0][0], -outer[0][1], outer[1][0], outer[1][1])

    containing.sort(key=inner_first)
    if len(containing) > 1 and inner_first(containing[0]) == inner_first(containing[1]):
        return None
    return containing[0]
