import json
from pathlib import Path

from app.triage.sinks_javascript import parse_javascript_sink_output

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RECORDED = FIXTURES / "sink-locator-v0-recorded.json"
SOURCES = FIXTURES / "sink-locator-v0-sources.json"


def _fixture():
    payload = RECORDED.read_text()
    sources = json.loads(SOURCES.read_text())
    return payload, sources


def test_recorded_javascript_locator_finds_all_r1_and_direct_alias_calls():
    payload, sources = _fixture()
    sinks = parse_javascript_sink_output(payload, sources)

    r1 = [sink for sink in sinks if "/r1-feasibility/" in sink["path"]]
    direct = [sink for sink in sinks if sink["path"].endswith("direct-alias/cases.js")]

    assert len(sinks) == 14
    assert len(r1) == 10
    assert len(direct) == 4
    assert {Path(sink["path"]).name for sink in r1} == {
        "01-literal-exec.js",
        "02-folded-exec.js",
        "03-dynamic-exec.js",
        "04-fixed-spawn-shell.js",
        "05-dynamic-spawn-shell.js",
        "06-explicit-interpreter.js",
        "07-dynamic-executable.js",
        "08-fixed-executable-argv.js",
        "09-shelljs-literal.js",
        "10-shelljs-dynamic.js",
    }
    assert [sink["span"]["startLine"] for sink in direct] == [7, 10, 13, 16]


def test_javascript_locator_keeps_constant_commands_and_normalizes_aliases():
    payload, sources = _fixture()
    sinks = parse_javascript_sink_output(payload, sources)

    literal_exec = next(sink for sink in sinks if sink["path"].endswith("01-literal-exec.js"))
    literal_shelljs = next(sink for sink in sinks if sink["path"].endswith("09-shelljs-literal.js"))
    fixed_alias = next(
        sink
        for sink in sinks
        if sink["path"].endswith("direct-alias/cases.js") and sink["span"]["startLine"] == 16
    )
    sync_alias = next(
        sink
        for sink in sinks
        if sink["path"].endswith("direct-alias/cases.js") and sink["span"]["startLine"] == 13
    )

    assert literal_exec["sink_kind"] == "child_process.exec"
    assert literal_exec["args"][0]["text"] == "'printf fixed'"
    assert literal_exec["args"][0]["value_kind"] == "string"

    assert literal_shelljs["sink_kind"] == "shelljs.exec"
    assert literal_shelljs["args"][0]["text"] == "'printf fixed'"

    assert fixed_alias["callee"] == "exec"
    assert fixed_alias["sink_kind"] == "child_process.exec"
    assert fixed_alias["args"][0]["text"] == '"printf hello"'

    assert sync_alias["callee"] == "execSync"
    assert sync_alias["sink_kind"] == "child_process.execSync"


def test_javascript_locator_preserves_spawn_arguments_and_shell_option():
    payload, sources = _fixture()
    sinks = parse_javascript_sink_output(payload, sources)

    spawn = next(sink for sink in sinks if sink["path"].endswith("04-fixed-spawn-shell.js"))
    assert spawn["sink_kind"] == "child_process.spawn"
    assert [arg["value_kind"] for arg in spawn["args"]] == ["string", "list", "dict"]
    assert spawn["args"][0]["text"] == "'printf'"
    assert spawn["args"][1]["text"] == "['fixed']"
    assert spawn["args"][2]["text"] == "{shell: true}"


def test_javascript_locator_rejects_unknown_or_missing_source_result():
    payload, sources = _fixture()
    data = json.loads(payload)
    data["results"][0]["check_id"] = "other-rule"

    try:
        parse_javascript_sink_output(json.dumps(data), sources)
    except ValueError as exc:
        assert str(exc) == "Unexpected JavaScript sink-locator rule"
    else:
        raise AssertionError("unexpected rule was accepted")

    data = json.loads(payload)
    missing_path = data["results"][0]["path"]
    del sources[missing_path]
    try:
        parse_javascript_sink_output(json.dumps(data), sources)
    except ValueError as exc:
        assert str(exc) == "Semgrep result path is missing from source contents"
    else:
        raise AssertionError("missing source was accepted")


def _one_result(source, call, check_id):
    start_offset = source.index(call)
    before = source[:start_offset]
    start_line = before.count("\n") + 1
    start_col = len(before.rsplit("\n", 1)[-1].encode()) + 1
    end_offset = start_offset + len(call.encode())
    end_before = source.encode()[:end_offset].decode()
    end_line = end_before.count("\n") + 1
    end_col = len(end_before.rsplit("\n", 1)[-1].encode()) + 1
    path = "synthetic.js"
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": check_id,
                    "path": path,
                    "start": {
                        "line": start_line,
                        "col": start_col,
                        "offset": start_offset,
                    },
                    "end": {
                        "line": end_line,
                        "col": end_col,
                        "offset": end_offset,
                    },
                }
            ]
        }
    )
    return payload, {path: source}


def test_javascript_reader_resolves_import_and_destructured_aliases():
    imported = """\
import { spawnSync as launch } from 'child_process';
launch("echo", ["x"], true);
"""
    payload, sources = _one_result(
        imported,
        'launch("echo", ["x"], true)',
        "sink-locator-v0-child-process-import-alias",
    )
    sink = parse_javascript_sink_output(payload, sources)[0]
    assert sink["callee"] == "launch"
    assert sink["sink_kind"] == "child_process.spawnSync"
    assert [arg["value_kind"] for arg in sink["args"]] == ["string", "list", "bool"]
    assert sink["args"][2]["literal_bool"] is True

    destructured = """\
const { execFile: runFile } = require('child_process');
runFile("echo", ["x"]);
"""
    payload, sources = _one_result(
        destructured,
        'runFile("echo", ["x"])',
        "sink-locator-v0-child-process-direct-require",
    )
    sink = parse_javascript_sink_output(payload, sources)[0]
    assert sink["callee"] == "runFile"
    assert sink["sink_kind"] == "child_process.execFile"
    assert sink["args"][1]["text"] == '["x"]'


def test_javascript_reader_validates_semgrep_shape_offsets_and_call_expression():
    payload, sources = _fixture()

    for bad_payload, expected in (
        ("[]", "Semgrep locator output must be an object"),
        (json.dumps({}), "Semgrep locator output must contain results"),
        (json.dumps({"results": [1]}), "Semgrep result must be an object"),
    ):
        try:
            parse_javascript_sink_output(bad_payload, sources)
        except ValueError as exc:
            assert str(exc) == expected
        else:
            raise AssertionError(f"invalid payload accepted: {bad_payload}")

    data = json.loads(payload)
    data["results"][0]["start"] = None
    try:
        parse_javascript_sink_output(json.dumps(data), sources)
    except ValueError as exc:
        assert str(exc) == "start must be an object"
    else:
        raise AssertionError("missing start object was accepted")

    data = json.loads(payload)
    data["results"][0]["start"]["line"] = True
    try:
        parse_javascript_sink_output(json.dumps(data), sources)
    except ValueError as exc:
        assert str(exc) == "start must contain integer line/col/offset"
    else:
        raise AssertionError("boolean line was accepted as an integer")

    data = json.loads(payload)
    data["results"][0]["end"]["offset"] = 10**9
    try:
        parse_javascript_sink_output(json.dumps(data), sources)
    except ValueError as exc:
        assert str(exc) == "Semgrep byte offsets are outside the source file"
    else:
        raise AssertionError("out-of-range byte offset was accepted")

    source = "const value = 1;\n"
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "sink-locator-v0-child-process-namespace",
                    "path": "synthetic.js",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 6, "offset": 5},
                }
            ]
        }
    )
    try:
        parse_javascript_sink_output(payload, {"synthetic.js": source})
    except ValueError as exc:
        assert str(exc) == "Located JavaScript sink is not a call expression"
    else:
        raise AssertionError("non-call locator result was accepted")
