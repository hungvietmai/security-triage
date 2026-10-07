import json
import sys

from app.scanners.process import ProcessRecord, invoke, tool_version


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
    assert record.get("exit_code") == 0
    assert (output / "probe.stdout.log").read_text().strip() == "ok"


def test_tool_version_uses_injected_invoke(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    steps: dict[str, ProcessRecord] = {}
    calls = []

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
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


def test_invoke_reports_nonzero_missing_binary_and_timeout(tmp_path):
    output = tmp_path / "output"
    output.mkdir()

    failed = invoke(
        [sys.executable, "-c", "raise SystemExit(3)"],
        tmp_path,
        output,
        "failed",
        30,
        {},
    )
    assert failed["status"] == "failed"
    assert failed.get("exit_code") == 3

    missing = invoke(
        ["/definitely/missing/binary"],
        tmp_path,
        output,
        "missing",
        30,
        {},
    )
    assert missing["status"] == "failed"
    assert "error" in missing

    timed_out = invoke(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        tmp_path,
        output,
        "timeout",
        0.01,
        {},
    )
    assert timed_out["status"] == "timeout"


def test_invoke_sanitizes_semgrep_environment(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    record = invoke(
        [
            sys.executable,
            "-c",
            (
                "import os; "
                "print(os.environ.get('SEMGREP_SEND_METRICS')); "
                "print(os.environ.get('SEMGREP_ENABLE_VERSION_CHECK')); "
                "print(os.environ.get('SEMGREP_APP_TOKEN'))"
            ),
        ],
        tmp_path,
        output,
        "semgrep-probe",
        30,
        {"SEMGREP_APP_TOKEN": "secret"},
    )

    assert record["status"] == "completed"
    assert (output / "semgrep-probe.stdout.log").read_text().splitlines() == [
        "off",
        "0",
        "None",
    ]


def test_tool_version_rejects_mismatch(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    steps: dict[str, ProcessRecord] = {}

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        (output / "semgrep-version.stdout.log").write_text("1.177.0\n")
        return {"status": "completed", "exit_code": 0}

    try:
        tool_version(
            "semgrep",
            "1.178.0",
            output,
            "semgrep",
            steps,
            working_directory=tmp_path,
            invoke_fn=fake_invoke,
        )
    except ValueError as exc:
        assert "version mismatch" in str(exc)
    else:
        raise AssertionError("version mismatch was accepted")


def test_invoke_timeout_survives_group_exiting_before_kill(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()

    def gone(pid, sig):
        raise ProcessLookupError(pid)

    monkeypatch.setattr("app.scanners.process.os.killpg", gone)
    record = invoke(
        [sys.executable, "-c", "import time; time.sleep(0.3)"],
        tmp_path,
        output,
        "race",
        0.01,
        {},
    )
    assert record["status"] == "timeout"
