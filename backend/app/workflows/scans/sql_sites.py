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
from collections.abc import Mapping, Sequence
from typing import Any, TypedDict

from app.triage.types import Span

LOCATOR_VERSION = "sql-call-site-v1"
EXECUTION_METHODS = frozenset({"execute", "executemany", "executescript", "raw", "extra"})
EXECUTION_CALLEES = frozenset({"RawSQL"})


class SqlSite(TypedDict):
    path: str
    span: Span
    callee: str


def _callee(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Attribute):
        if function.attr in EXECUTION_METHODS or function.attr in EXECUTION_CALLEES:
            return ast.unparse(function)
        return None
    if isinstance(function, ast.Name) and function.id in EXECUTION_CALLEES:
        return function.id
    return None


def locate_sql_sites(path: str, text: str) -> list[SqlSite]:
    """Every SQL execution call of one Python file, in source order; raises SyntaxError."""
    tree = ast.parse(text, filename=path)
    lines = text.splitlines()
    sites: list[SqlSite] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _callee(node)
        if callee is None or node.end_lineno is None or node.end_col_offset is None:
            continue
        covered = lines[node.lineno - 1 : node.end_lineno]
        if not all(line.isascii() for line in covered):
            continue
        # ast counts UTF-8 bytes from 0; on ASCII lines that equals SARIF's 1-based column - 1.
        span: Span = {
            "startLine": node.lineno,
            "startColumn": node.col_offset + 1,
            "endLine": node.end_lineno,
            "endColumn": node.end_col_offset + 1,
        }
        sites.append({"path": path, "span": span, "callee": callee})
    sites.sort(key=lambda site: (site["span"]["startLine"], site["span"]["startColumn"]))
    return sites


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
