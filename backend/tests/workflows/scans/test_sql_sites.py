"""The SQL call locator: where alerts of several tools may be merged, and where they may not."""

import pytest

from app.workflows.scans.sql_sites import locate_all, locate_sql_sites, site_of

SOURCE = (
    "cur.execute('SELECT 1')\n"  # 1
    "conn.executemany(sql, rows)\n"  # 2
    "db.executescript(script)\n"  # 3
    "User.objects.raw(query)\n"  # 4
    "qs.extra(where=[w])\n"  # 5
    "RawSQL(sql, [])\n"  # 6
    "models.RawSQL(sql, [])\n"  # 7
    "print(query)\n"  # 8
    "cur.execute(str(cur.execute(inner)))\n"  # 9
    "cur.execute(\n"  # 10
    "    query\n"  # 11
    ")\n"  # 12
    "cur.execute('é' + x)\n"  # 13
)


def _span(line: int, start: int, end_line: int, end: int) -> dict[str, int]:
    return {"startLine": line, "startColumn": start, "endLine": end_line, "endColumn": end}


def test_execution_calls_are_located_with_sarif_columns():
    sites = locate_sql_sites("a.py", SOURCE)
    assert [(s["span"]["startLine"], s["callee"]) for s in sites] == [
        (1, "cur.execute"),
        (2, "conn.executemany"),
        (3, "db.executescript"),
        (4, "User.objects.raw"),
        (5, "qs.extra"),
        (6, "RawSQL"),
        (7, "models.RawSQL"),
        (9, "cur.execute"),
        (9, "cur.execute"),
        (10, "cur.execute"),
    ]
    # 1-based columns, end exclusive, as SARIF regions are.
    assert sites[0]["span"] == _span(1, 1, 1, len("cur.execute('SELECT 1')") + 1)
    assert sites[-1]["span"] == _span(10, 1, 12, 2)


def test_a_line_that_is_not_ascii_is_not_located():
    # Tools count columns differently on such lines; a containment there could not be trusted.
    sites = locate_sql_sites("a.py", SOURCE)
    assert all(site["span"]["startLine"] != 13 for site in sites)


def test_a_region_inside_one_call_belongs_to_it_and_to_the_innermost_when_nested():
    sites = locate_sql_sites("a.py", SOURCE)
    first = site_of(_span(1, 13, 1, 23), "a.py", sites)
    assert first is not None and first["span"]["startLine"] == 1
    inner_start = SOURCE.splitlines()[8].index("cur.execute(inner)") + 1
    inner = site_of(_span(9, inner_start + 12, 9, inner_start + 17), "a.py", sites)
    assert inner is not None and inner["span"]["startColumn"] == inner_start
    # The outer call's own argument, outside the inner call, belongs to the outer call.
    outer = site_of(_span(9, 13, 9, 16), "a.py", sites)
    assert outer is not None and outer["span"]["startColumn"] == 1
    multi = site_of(_span(11, 5, 11, 10), "a.py", sites)
    assert multi is not None and multi["span"]["startLine"] == 10
    # CodeQL leaves out endLine for a one-line region; SARIF says it is the start line.
    one_line = site_of({"startLine": 1, "startColumn": 13, "endColumn": 23}, "a.py", sites)
    assert one_line is not None and one_line["span"]["startLine"] == 1


@pytest.mark.parametrize(
    ("region", "path"),
    [
        (_span(8, 7, 8, 12), "a.py"),  # a call that is not SQL execution
        (_span(1, 1, 2, 5), "a.py"),  # spans two calls, inside neither
        ({"startLine": 1}, "a.py"),  # no columns: containment cannot be shown
        (_span(1, 13, 1, 23), "b.py"),  # another file
        (None, "a.py"),
    ],
)
def test_a_region_no_single_call_contains_has_no_site(region, path):
    assert site_of(region, path, locate_sql_sites("a.py", SOURCE)) is None


def test_files_that_do_not_parse_have_no_site_and_are_reported():
    sites, unparsed = locate_all({"ok.py": "cur.execute(q)\n", "py2.py": "print 'x'\n"})
    assert [site["path"] for site in sites] == ["ok.py"]
    assert unparsed == ["py2.py"]
