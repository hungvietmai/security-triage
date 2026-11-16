"""Linking an alert on a SQL-building statement to the one call that runs it (sql-call-site-v2).

A Bandit B608 alert reports the string literal a query is built from. When that statement is
`name = <string expression>` and the name is bound once and read only as the SQL argument of one
execution call, the alert is about that call. Any doubt (a second binding, a second call, another
read, a wrapper, a nested scope) leaves it unlinked, with the reason.
"""

import pytest

from app.workflows.scans import sql_sites
from app.workflows.scans.sql_sites import locate_sql_strings, string_link


def _strings(body: str) -> dict[str, sql_sites.SqlString]:
    return {item["variable"]: item for item in locate_sql_strings("a.py", body)}


def _region(text: str, source: str, literal: str) -> dict[str, int]:
    """The SARIF region Bandit reports for `literal`, which must occur once in `source`."""
    assert source.count(literal) == 1
    start = source.index(literal)
    line = source[:start].count("\n") + 1
    column = start - (source.rfind("\n", 0, start) + 1) + 1
    end_line = line + literal.count("\n")
    end_column = (
        column + len(literal) if "\n" not in literal else len(literal.rsplit("\n", 1)[1]) + 1
    )
    return {"startLine": line, "startColumn": column, "endLine": end_line, "endColumn": end_column}


LINKED = (
    "def find(cur, name):\n"
    "    sql = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
    "    cur.execute(sql)\n"
)


def test_a_string_bound_once_and_run_by_one_call_is_linked_to_that_call():
    item = _strings(LINKED)["sql"]
    assert item["reason"] == sql_sites.LINKED
    assert item["site"] is not None and item["site"]["callee"] == "cur.execute"
    assert item["site"]["span"] == {"startLine": 3, "startColumn": 5, "endLine": 3, "endColumn": 21}
    literal = "\"SELECT * FROM users WHERE name = '%s'\""
    found, reason = string_link(_region("x", LINKED, literal), "a.py", [item])
    assert (found, reason) == (item, sql_sites.LINKED)


@pytest.mark.parametrize(
    "value",
    [
        '"SELECT {} FROM t".format(col)',
        'f"SELECT * FROM t WHERE a = {a}"',
        '"SELECT * FROM t WHERE a = \'" + a + "\'"',
        '("SELECT * "\n        "FROM t WHERE a = %s" % a)',
    ],
)
def test_format_f_strings_concatenation_and_implicit_joins_are_followed(value):
    source = f"def f(cur, a, col):\n    q = {value}\n    cur.execute(q)\n"
    item = _strings(source)["q"]
    assert item["reason"] == sql_sites.LINKED
    # Each literal of the value is one of the strings a B608 region may be.
    first = item["strings"][0]
    assert first["startLine"] == 2


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        # Bound again: which string reaches the call is not one statement any more.
        (
            "    sql = 'SELECT 1 WHERE a = %s' % a\n"
            "    sql = sql + ' LIMIT 1'\n"
            "    cur.execute(sql)\n",
            sql_sites.REBOUND,
        ),
        (
            "    sql = 'SELECT 1 WHERE a = %s' % a\n    sql += ' LIMIT 1'\n    cur.execute(sql)\n",
            sql_sites.REBOUND,
        ),
        (
            "    for sql in ['x']:\n"
            "        pass\n"
            "    sql = 'SELECT %s' % a\n"
            "    cur.execute(sql)\n",
            sql_sites.REBOUND,
        ),
        # Two execution calls run it: two points of execution.
        (
            "    sql = 'SELECT %s' % a\n    cur.execute(sql)\n    other.execute(sql)\n",
            sql_sites.SEVERAL_EXECUTION_CALLS,
        ),
        # A project's own function takes the string: what it does is not known here.
        ("    sql = 'SELECT %s' % a\n    db.run_query(sql)\n", sql_sites.NO_EXECUTION_CALL),
        ("    sql = 'SELECT %s' % a\n    return sql\n", sql_sites.NO_EXECUTION_CALL),
        # Read somewhere else too: it may reach another call through that use.
        ("    sql = 'SELECT %s' % a\n    log(sql)\n    cur.execute(sql)\n", sql_sites.OTHER_USE),
        ("    sql = 'SELECT %s' % a\n    cur.execute(sql, sql)\n", sql_sites.OTHER_USE),
        # Not the SQL argument: the first positional argument is the statement.
        (
            "    sql = 'SELECT %s' % a\n    cur.execute('SELECT 1', sql)\n",
            sql_sites.NO_EXECUTION_CALL,
        ),
        # Used inside a nested function: the scope cannot be followed from here.
        (
            "    sql = 'SELECT %s' % a\n    def run():\n        cur.execute(sql)\n    run()\n",
            sql_sites.NESTED_USE,
        ),
        (
            "    sql = 'SELECT %s' % a\n    cur.execute(sql)\n    f = lambda: sql\n",
            sql_sites.NESTED_USE,
        ),
        ("    global sql\n    sql = 'SELECT %s' % a\n    cur.execute(sql)\n", sql_sites.REBOUND),
        ("    cur.execute(sql)\n    sql = 'SELECT %s' % a\n", sql_sites.USED_BEFORE),
        ("    sql = 'SELECT é %s' % a\n    cur.execute(sql)\n", sql_sites.NOT_ASCII),
    ],
)
def test_any_doubt_leaves_the_statement_unlinked_with_the_reason(body, reason):
    item = _strings(f"def f(cur, other, db, a, log):\n{body}")["sql"]
    assert (item["site"], item["reason"]) == (None, reason)


def test_a_parameter_of_the_same_name_is_a_second_binding():
    item = _strings("def f(cur, sql):\n    sql = 'SELECT %s' % sql\n    cur.execute(sql)\n")["sql"]
    assert item["reason"] == sql_sites.REBOUND


def test_module_and_function_scopes_are_kept_apart():
    source = "sql = 'SELECT %s' % x\ndef f(cur):\n    cur.execute(sql)\n"
    # The module statement is read only inside a function: a nested scope.
    assert _strings(source)["sql"]["reason"] == sql_sites.NESTED_USE
    module = "sql = 'SELECT %s' % x\ncur.execute(sql)\n"
    assert _strings(module)["sql"]["reason"] == sql_sites.LINKED


def test_a_region_that_is_not_one_of_the_literals_is_not_linked():
    item = _strings(LINKED)["sql"]
    whole = "\"SELECT * FROM users WHERE name = '%s'\" % name"
    assert string_link(_region("x", LINKED, whole), "a.py", [item]) == (
        item,
        sql_sites.NOT_STRING_OF_VALUE,
    )
    # A string wrapped in a call is not the assigned value: the walk stops at the call.
    wrapped = "def f(cur, a):\n    q = clean('SELECT %s' % a)\n    cur.execute(q)\n"
    q = _strings(wrapped)["q"]
    assert q["strings"] == []
    assert string_link(_region("x", wrapped, "'SELECT %s'"), "a.py", [q]) == (
        q,
        sql_sites.NOT_STRING_OF_VALUE,
    )
    # Outside any assignment, or in another file, there is nothing to link.
    other = _region("x", LINKED, "cur.execute(sql)")
    assert string_link(other, "a.py", [item]) == (None, sql_sites.NOT_IN_ASSIGNMENT)
    literal = _region("x", LINKED, "\"SELECT * FROM users WHERE name = '%s'\"")
    assert string_link(literal, "b.py", [item]) == (None, sql_sites.NOT_IN_ASSIGNMENT)
    assert string_link(None, "a.py", [item]) == (None, sql_sites.NOT_IN_ASSIGNMENT)


def test_files_that_do_not_parse_have_no_statement():
    assert sql_sites.locate_all_strings({"a.py": "def (:\n", "b.py": LINKED})[0]["path"] == "b.py"
    with pytest.raises(SyntaxError):
        locate_sql_strings("a.py", "def (:\n")


def test_a_literal_part_of_an_f_string_is_one_of_its_strings():
    # Since Python 3.12 the literal parts of an f-string have positions; Bandit reports one.
    source = (
        "def f(cur, user):\n"
        "    sql_query = (\n"
        "        f\"SELECT * FROM users WHERE name='{user}' AND x=1\"\n"
        "    )\n"
        "    cur.execute(sql_query)\n"
    )
    item = _strings(source)["sql_query"]
    assert item["reason"] == sql_sites.LINKED
    part = _region("x", source, "SELECT * FROM users WHERE name='")
    assert string_link(part, "a.py", [item]) == (item, sql_sites.LINKED)


def test_a_multi_line_literal_is_named_by_its_start_and_end_column():
    # Bandit 1.9.4 writes the literal's start and end column with an endLine that is not the
    # literal's last line; the start names the literal.
    source = (
        "def f(cur, a):\n"
        '    q = """\n'
        "        SELECT * FROM t\n"
        "        WHERE a = %s\n"
        '    """ % a\n'
        "    cur.execute(q)\n"
    )
    item = _strings(source)["q"]
    assert item["reason"] == sql_sites.LINKED
    literal = item["strings"][0]
    assert (literal["startLine"], literal["endLine"]) == (2, 5)
    bandit = {**literal, "endLine": 3}
    assert string_link(bandit, "a.py", [item]) == (item, sql_sites.LINKED)
    # Another start, or another end column, is not that literal.
    assert (
        string_link({**bandit, "startColumn": 5}, "a.py", [item])[1]
        == sql_sites.NOT_STRING_OF_VALUE
    )
    assert (
        string_link({**bandit, "endColumn": 3}, "a.py", [item])[1] == sql_sites.NOT_STRING_OF_VALUE
    )
