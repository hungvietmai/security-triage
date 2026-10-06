import pytest

from app.triage.reconcile import reconcile_findings
from app.triage.sinks_python import locate_python_sinks
from app.triage.types import SinkRecord


def _sink(
    *,
    path="a.js",
    start=10,
    end=10,
    start_col=1,
    end_col=20,
    kind="child_process.exec",
):
    return {
        "path": path,
        "span": {
            "startLine": start,
            "startColumn": start_col,
            "endLine": end,
            "endColumn": end_col,
        },
        "callee": "exec",
        "sink_kind": kind,
        "args": [
            {
                "position": 0,
                "keyword": None,
                "span": {
                    "startLine": start,
                    "startColumn": start_col + 5,
                    "endLine": end,
                    "endColumn": end_col - 1,
                },
                "text": "command",
                "value_kind": "name",
                "literal_bool": None,
            }
        ],
    }


def _finding(
    *,
    raw_id="codeql:0:0",
    path="a.js",
    region=None,
    message="",
    raw_result=None,
):
    return {
        "raw_id": raw_id,
        "tool": "codeql",
        "snapshot_sha256": "a" * 64,
        "reported_path": path,
        "reported_region": region
        or {
            "startLine": 10,
            "startColumn": 6,
            "endLine": 10,
            "endColumn": 12,
        },
        "message": message,
        "raw_result": raw_result or {},
    }


def test_explicit_link_merges_multiple_findings_into_one_shell_unit():
    sink = _sink(start=56, end=58, start_col=3, end_col=5)
    related = {
        "relatedLocations": [
            {
                "id": 2,
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.js"},
                    "region": {
                        "startLine": 56,
                        "startColumn": 3,
                        "endLine": 58,
                        "endColumn": 5,
                    },
                },
            }
        ]
    }
    findings = [
        _finding(
            raw_id="codeql:0:0",
            region={"startLine": 20, "startColumn": 1, "endLine": 20, "endColumn": 5},
            message="later used in a [shell command](2)",
            raw_result=related,
        ),
        _finding(
            raw_id="codeql:0:1",
            region={"startLine": 30, "startColumn": 1, "endLine": 30, "endColumn": 5},
            message="later used in a [shell command](2)",
            raw_result=related,
        ),
    ]

    units = reconcile_findings(findings, [sink], {"a.js": "\n" * 60})

    assert len(units) == 1
    unit = units[0]
    assert unit["mapping_status"] == "mapped"
    assert unit["argument_role"] == "shell_command"
    assert unit["sink_kind"] == "child_process.exec"
    assert unit["raw_finding_ids"] == ["codeql:0:0", "codeql:0:1"]
    assert [row["mapping_method"] for row in unit["mappings"]] == [
        "explicit_link",
        "explicit_link",
    ]


def test_containment_prefers_unique_innermost_sink():
    outer = _sink(start=10, end=12, start_col=1, end_col=30)
    inner = _sink(start=10, end=10, start_col=5, end_col=20)
    finding = _finding(
        region={
            "startLine": 10,
            "startColumn": 7,
            "endLine": 10,
            "endColumn": 12,
        }
    )

    unit = reconcile_findings([finding], [outer, inner], {"a.js": "\n" * 15})[0]

    assert unit["mapping_status"] == "mapped"
    assert unit["sink_span"] == inner["span"]
    assert unit["mappings"][0]["mapping_method"] == "containment"


def test_exact_span_maps_when_containment_is_strict():
    sink = _sink()
    finding = _finding(region=dict(sink["span"]))

    unit = reconcile_findings([finding], [sink], {"a.js": "\n" * 15})[0]

    assert unit["mapping_status"] == "mapped"
    assert unit["mappings"][0]["mapping_method"] == "exact_span"


def test_ambiguous_incomparable_sinks_fall_back():
    first = _sink(start=10, end=10, start_col=1, end_col=15)
    second = _sink(start=10, end=10, start_col=5, end_col=20)
    finding = _finding(
        region={
            "startLine": 10,
            "startColumn": 7,
            "endLine": 10,
            "endColumn": 10,
        }
    )

    unit = reconcile_findings([finding], [first, second], {"a.js": "\n" * 15})[0]

    assert unit["mapping_status"] == "unmapped"
    assert unit["sink_span"] is None
    assert unit["argument_role"] is None


def test_non_ascii_relevant_line_requires_review():
    sink = _sink(start=1, end=1, start_col=1, end_col=20)
    finding = _finding(
        region={
            "startLine": 1,
            "startColumn": 6,
            "endLine": 1,
            "endColumn": 12,
        }
    )

    unit = reconcile_findings([finding], [sink], {"a.js": "éxec(command)\n"})[0]

    assert unit["mapping_status"] == "column_encoding_requires_review"
    assert unit["sink_span"] is None


def test_process_sink_without_role_evidence_is_role_unresolved():
    sink = _sink(kind="child_process.spawn")
    finding = _finding(region=dict(sink["span"]))

    unit = reconcile_findings([finding], [sink], {"a.js": "\n" * 15})[0]

    assert unit["mapping_status"] == "role_unresolved"
    assert unit["argument_role"] is None
    assert unit["sink_span"] == sink["span"]


def test_missing_location_uses_raw_id_to_keep_fallbacks_distinct():
    first = _finding(raw_id="semgrep:0:0", path=None, region={})
    second = _finding(raw_id="semgrep:0:1", path=None, region={})

    units = reconcile_findings([first, second], [], {})

    assert len(units) == 2
    assert units[0]["unit_id"] != units[1]["unit_id"]


def _region_for_token(source: str, token: str) -> dict[str, int]:
    offset = source.index(token)
    prefix = source[:offset]
    line = prefix.count("\n") + 1
    last_newline = prefix.rfind("\n")
    zero_column = offset if last_newline < 0 else offset - last_newline - 1
    return {
        "startLine": line,
        "startColumn": zero_column + 1,
        "endLine": line,
        "endColumn": zero_column + len(token) + 1,
    }


def _python_unit(source: str, token: str):
    path = "fixture.py"
    sinks = locate_python_sinks(path, source)
    assert len(sinks) == 1
    finding = _finding(path=path, region=_region_for_token(source, token))
    return reconcile_findings([finding], sinks, {path: source})[0]


@pytest.mark.parametrize(
    ("source", "token", "expected_role"),
    [
        (
            'import subprocess\nsubprocess.run(["ls", user_arg])\n',
            '"ls"',
            "executable",
        ),
        (
            'import subprocess\nsubprocess.run(["ls", user_arg])\n',
            "user_arg",
            "argument_list",
        ),
        (
            'import pty\npty.spawn(["sh", user_arg])\n',
            '"sh"',
            "executable",
        ),
        (
            'import pty\npty.spawn(["sh", user_arg])\n',
            "user_arg",
            "argument_list",
        ),
        (
            'import os\nos.spawnv(os.P_WAIT, program, ["argv0", user_arg])\n',
            "os.P_WAIT",
            None,
        ),
        (
            'import os\nos.spawnv(os.P_WAIT, program, ["argv0", user_arg])\n',
            "program",
            "executable",
        ),
        (
            'import os\nos.spawnv(os.P_WAIT, program, ["argv0", user_arg])\n',
            "user_arg",
            "argument_list",
        ),
        (
            'import os\nos.execv(program, ["argv0", user_arg])\n',
            "program",
            "executable",
        ),
        (
            'import os\nos.execv(program, ["argv0", user_arg])\n',
            "user_arg",
            "argument_list",
        ),
        (
            "import asyncio\nasyncio.create_subprocess_exec(program, user_arg)\n",
            "program",
            "executable",
        ),
        (
            "import asyncio\nasyncio.create_subprocess_exec(program, user_arg)\n",
            "user_arg",
            "argument_list",
        ),
        (
            "import asyncio\nasyncio.create_subprocess_shell(user_cmd)\n",
            "user_cmd",
            "shell_command",
        ),
        (
            "import subprocess\nsubprocess.getoutput(user_cmd)\n",
            "user_cmd",
            "shell_command",
        ),
        (
            "import subprocess\nsubprocess.getstatusoutput(user_cmd)\n",
            "user_cmd",
            "shell_command",
        ),
        (
            "import subprocess\nsubprocess.run(user_cmd, shell=False)\n",
            "user_cmd",
            "executable",
        ),
        (
            "import subprocess\nsubprocess.run(user_cmd, shell=True)\n",
            "user_cmd",
            "shell_command",
        ),
        (
            "import subprocess\nsubprocess.run(user_cmd, shell=use_shell)\n",
            "user_cmd",
            None,
        ),
    ],
)
def test_python_argument_role_table_v01(source, token, expected_role):
    unit = _python_unit(source, token)
    assert unit["argument_role"] == expected_role
    assert unit["mapping_status"] == ("mapped" if expected_role is not None else "role_unresolved")


def _js_arg(
    position: int,
    start_column: int,
    end_column: int,
    *,
    text: str,
    value_kind: str,
):
    return {
        "position": position,
        "keyword": None,
        "span": {
            "startLine": 1,
            "startColumn": start_column,
            "endLine": 1,
            "endColumn": end_column,
        },
        "text": text,
        "value_kind": value_kind,
        "literal_bool": None,
    }


def _js_process_unit(kind: str, evidence_position: int, option_text: str | None = None):
    args = [
        _js_arg(0, 6, 12, text="command", value_kind="name"),
        _js_arg(1, 14, 24, text="args", value_kind="list"),
    ]
    if option_text is not None:
        args.append(_js_arg(2, 26, 55, text=option_text, value_kind="dict"))
    sink: SinkRecord = {
        "path": "a.js",
        "span": {
            "startLine": 1,
            "startColumn": 1,
            "endLine": 1,
            "endColumn": 60,
        },
        "callee": kind.rsplit(".", 1)[-1],
        "sink_kind": kind,
        "args": args,
    }
    evidence = args[evidence_position]["span"]
    finding = _finding(
        path="a.js",
        region={
            "startLine": 1,
            "startColumn": evidence["startColumn"],
            "endLine": 1,
            "endColumn": evidence["endColumn"],
        },
    )
    return reconcile_findings([finding], [sink], {"a.js": "x" * 80 + "\n"})[0]


@pytest.mark.parametrize(
    ("kind", "evidence_position", "option_text", "expected_role"),
    [
        ("child_process.spawn", 0, None, "executable"),
        ("child_process.spawn", 1, None, "argument_list"),
        ("child_process.spawn", 0, "{shell: true}", "shell_command"),
        ("child_process.spawn", 0, "{shell: false}", "executable"),
        ("child_process.spawn", 0, "{shell: opts.shell}", None),
        ("child_process.spawn", 0, "{shell: '/bin/bash'}", None),
        ("child_process.spawn", 0, "{'shell': true}", "shell_command"),
        ("child_process.spawn", 0, '{"shell": false}', "executable"),
        ("child_process.fork", 0, "{shell: true}", "executable"),
    ],
)
def test_javascript_argument_role_table_v01(
    kind,
    evidence_position,
    option_text,
    expected_role,
):
    unit = _js_process_unit(kind, evidence_position, option_text)
    assert unit["argument_role"] == expected_role
    assert unit["mapping_status"] == ("mapped" if expected_role is not None else "role_unresolved")


def test_missing_source_never_uses_column_matching_automatically():
    sink = _sink()
    finding = _finding(
        region={
            "startLine": 10,
            "startColumn": 6,
            "endLine": 10,
            "endColumn": 12,
        }
    )

    unit = reconcile_findings([finding], [sink], {})[0]

    assert unit["mapping_status"] == "column_encoding_requires_review"
    assert unit["sink_span"] is None
    assert unit["argument_role"] is None
