import json
from pathlib import Path

from app.triage.sinks_javascript import parse_javascript_sink_output

ROOT = Path(__file__).resolve().parents[3]
RECORDED = ROOT / "experiments/locators/fixtures/sink-locator-v0-recorded.json"


def _fixture():
    payload = RECORDED.read_text()
    data = json.loads(payload)
    paths = {row["path"] for row in data["results"]}
    sources = {path: (ROOT / path).read_text() for path in paths}
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

    literal_exec = next(
        sink for sink in sinks if sink["path"].endswith("01-literal-exec.js")
    )
    literal_shelljs = next(
        sink for sink in sinks if sink["path"].endswith("09-shelljs-literal.js")
    )
    fixed_alias = next(
        sink
        for sink in sinks
        if sink["path"].endswith("direct-alias/cases.js")
        and sink["span"]["startLine"] == 16
    )
    sync_alias = next(
        sink
        for sink in sinks
        if sink["path"].endswith("direct-alias/cases.js")
        and sink["span"]["startLine"] == 13
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

    spawn = next(
        sink for sink in sinks if sink["path"].endswith("04-fixed-spawn-shell.js")
    )
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
