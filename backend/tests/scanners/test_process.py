import json
import sys

from app.scanners.process import invoke, tool_version


def test_invoke_runs_argument_list_and_captures_logs(tmp_path):
    output = tmp_path / "output"
    output.mkdir()

    record = invoke(
        [sys.executable, "-c", "print('ok')"],
        tmp_path,
        output,
        "probe",
        30,
        {},
    )

    assert record["status"] == "completed"
    assert record["exit_code"] == 0
    assert (output / "probe.stdout.log").read_text().strip() == "ok"


def test_tool_version_uses_injected_invoke(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    steps = {}
    calls = []

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None):
        calls.append([str(item) for item in argv])
        assert cwd == tmp_path
        assert output_dir == output
        assert timeout == 60
        (output / "codeql-version.stdout.log").write_text(json.dumps({"version": "2.27.1"}))
        return {
            "argv": [str(item) for item in argv],
            "status": "completed",
            "exit_code": 0,
            "seconds": 0.0,
        }

    tool_version(
        "/tools/codeql",
        "2.27.1",
        output,
        "codeql",
        steps,
        working_directory=tmp_path,
        invoke_fn=fake_invoke,
    )

    assert calls == [["/tools/codeql", "version", "--format=json"]]
    assert steps["codeql-version"]["status"] == "completed"
