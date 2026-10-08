import json
from threading import Barrier, Event

import pytest

from app.scanners.pipeline import run_pipeline
from app.scanners.process import ProcessRecord, ToolName
from app.scanners.provenance import digest


@pytest.mark.parametrize(
    ("runs", "expected_status"),
    [([], "completed"), ([None], "failed"), ([{"results": {}}], "failed")],
)
def test_pipeline_accepts_injected_process_functions(tmp_path, runs, expected_status):
    repository_root = tmp_path / "repo"
    repository_root.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    rule = repository_root / "rule.yaml"
    rule.write_text("rules: []\n")

    version_calls = []
    invoke_calls = []

    def fake_version(
        binary,
        expected,
        output_dir,
        tool,
        steps,
        *,
        working_directory,
        invoke_fn,
    ):
        version_calls.append((binary, expected, tool, working_directory, invoke_fn))
        steps[tool + "-version"] = {"status": "completed"}

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        invoke_calls.append((name, [str(item) for item in argv]))
        if name == "semgrep":
            (output / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": runs}))
        return {
            "argv": [str(item) for item in argv],
            "status": "completed",
            "exit_code": 0,
            "seconds": 0.0,
        }

    scanners: list[ToolName] = ["semgrep"]
    result = run_pipeline(
        scanners=scanners,
        language="javascript",
        source=source,
        output=output,
        snapshot_sha256="e" * 64,
        repository_root=repository_root,
        semgrep_binary="/tools/semgrep",
        codeql_binary="/tools/codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[{"path": "rule.yaml", "sha256": digest(rule)}],
        codeql_queries=[],
        codeql_query_sha256={},
        javascript_query_pack=None,
        python_query_pack=None,
        jobs=1,
        timeout_seconds=600,
        codeql_ram_mb=2048,
        invoke_fn=fake_invoke,
        tool_version_fn=fake_version,
    )

    assert result.status == expected_status
    assert result.findings == []
    if expected_status == "failed":
        assert "Invalid SARIF" in result.steps["semgrep"].get("error", "")
    assert version_calls[0][:4] == (
        "/tools/semgrep",
        "1.178.0",
        "semgrep",
        repository_root,
    )
    assert version_calls[0][4] is fake_invoke
    assert invoke_calls[0][0] == "semgrep"


def test_pipeline_runs_codeql_and_isolates_failure(tmp_path):
    repository_root = tmp_path / "repo"
    repository_root.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    pack = tmp_path / "pack"
    pack.mkdir()
    query = pack / "query.ql"
    query.write_text("select 1\n")
    (pack / "qlpack.yml").write_text("name: codeql/javascript-queries\n")

    def fake_version(
        binary,
        expected,
        output_dir,
        tool,
        steps,
        *,
        working_directory,
        invoke_fn,
    ):
        steps[tool + "-version"] = {"status": "completed"}

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        if name == "codeql":
            (output / "codeql.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
        return {"status": "completed", "exit_code": 0}

    scanners: list[ToolName] = ["codeql"]
    result = run_pipeline(
        scanners=scanners,
        language="javascript",
        source=source,
        output=output,
        snapshot_sha256="f" * 64,
        repository_root=repository_root,
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[],
        codeql_queries=["query.ql"],
        codeql_query_sha256={"query.ql": digest(query)},
        javascript_query_pack=pack,
        python_query_pack=None,
        jobs=1,
        timeout_seconds=60,
        codeql_ram_mb=2048,
        invoke_fn=fake_invoke,
        tool_version_fn=fake_version,
    )
    assert result.status == "completed"
    assert result.codeql_query_files == {"query.ql": digest(query)}
    assert result.codeql_pack_manifest == "name: codeql/javascript-queries\n"

    failed = run_pipeline(
        scanners=scanners,
        language="javascript",
        source=source,
        output=output,
        snapshot_sha256="f" * 64,
        repository_root=repository_root,
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[],
        codeql_queries=["query.ql"],
        codeql_query_sha256={"query.ql": digest(query)},
        javascript_query_pack=None,
        python_query_pack=None,
        jobs=1,
        timeout_seconds=60,
        codeql_ram_mb=2048,
        invoke_fn=fake_invoke,
        tool_version_fn=fake_version,
    )
    assert failed.status == "failed"
    assert failed.steps["codeql"]["status"] == "failed"
    assert "--javascript-query-pack" in failed.steps["codeql"].get("error", "")


@pytest.mark.parametrize("workers", [1, 2])
def test_pipeline_is_partial_when_one_scanner_fails(tmp_path, workers):
    repository_root = tmp_path / "repo"
    repository_root.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    rule = repository_root / "rule.yaml"
    rule.write_text("rules: []\n")

    def fake_version(
        binary,
        expected,
        output_dir,
        tool,
        steps,
        *,
        working_directory,
        invoke_fn,
    ):
        steps[tool + "-version"] = {"status": "completed"}

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        if name == "semgrep":
            (output / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
        return {"status": "completed", "exit_code": 0}

    scanners: list[ToolName] = ["semgrep", "codeql"]
    result = run_pipeline(
        scanners=scanners,
        language="javascript",
        source=source,
        output=output,
        snapshot_sha256="f" * 64,
        repository_root=repository_root,
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[{"path": "rule.yaml", "sha256": digest(rule)}],
        codeql_queries=[],
        codeql_query_sha256={},
        javascript_query_pack=None,
        python_query_pack=None,
        jobs=1,
        timeout_seconds=60,
        codeql_ram_mb=2048,
        max_workers=workers,
        invoke_fn=fake_invoke,
        tool_version_fn=fake_version,
    )
    assert result.status == "partial"
    assert result.steps["semgrep"]["status"] == "completed"
    assert result.steps["codeql"]["status"] == "failed"


@pytest.fixture
def pipeline_input(tmp_path):
    repository = tmp_path / "repo"
    source = tmp_path / "source"
    output = tmp_path / "output"
    pack = tmp_path / "pack"
    for path in (repository, source, output, pack):
        path.mkdir()
    rule = repository / "rule.yaml"
    rule.write_text("rules: []\n")
    query = pack / "query.ql"
    query.write_text("select 1\n")
    (pack / "qlpack.yml").write_text("name: codeql/javascript-queries\n")
    return {
        "scanners": ["semgrep", "codeql"],
        "language": "javascript",
        "source": source,
        "output": output,
        "snapshot_sha256": "a" * 64,
        "repository_root": repository,
        "semgrep_binary": "semgrep",
        "codeql_binary": "codeql",
        "semgrep_version": "1",
        "codeql_version": "2",
        "semgrep_rules": [{"path": "rule.yaml", "sha256": digest(rule)}],
        "codeql_queries": ["query.ql"],
        "codeql_query_sha256": {"query.ql": digest(query)},
        "javascript_query_pack": pack,
        "python_query_pack": None,
        "jobs": 1,
        "timeout_seconds": 5,
        "codeql_ram_mb": 2048,
    }


def test_parallel_scanners_overlap_and_merge_in_configured_order(pipeline_input):
    started = Barrier(2, timeout=5)
    codeql_done = Event()

    def version(binary, expected, output, tool, steps, **kwargs):
        steps[tool + "-version"] = {"status": "completed"}
        started.wait()

    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        if name == "semgrep":
            assert codeql_done.wait(timeout=5)
        if name in {"semgrep", "codeql"}:
            result = {"ruleId": name, "message": {"text": name}}
            (output / f"{name}.sarif").write_text(
                json.dumps({"version": "2.1.0", "runs": [{"results": [result]}]})
            )
            if name == "codeql":
                codeql_done.set()
        return {"status": "completed", "exit_code": 0}

    result = run_pipeline(
        **pipeline_input, max_workers=2, invoke_fn=invoke, tool_version_fn=version
    )
    assert result.status == "completed"
    assert [finding["tool"] for finding in result.findings] == ["semgrep", "codeql"]
    assert [finding["raw_id"] for finding in result.findings] == ["semgrep:0:0", "codeql:0:0"]
    assert result.codeql_query_files == pipeline_input["codeql_query_sha256"]
    assert set(result.steps) == {
        "semgrep-version",
        "semgrep",
        "codeql-version",
        "codeql-create",
        "codeql",
    }


def test_parallel_scanners_finish_before_an_unexpected_error_propagates(pipeline_input):
    started = Barrier(2, timeout=5)
    completed = Event()

    def version(binary, expected, output, tool, steps, **kwargs):
        started.wait()
        if tool == "semgrep":
            raise TypeError("unexpected adapter error")
        steps[tool + "-version"] = {"status": "completed"}

    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        if name == "codeql":
            (output / "codeql.sarif").write_text(
                json.dumps({"version": "2.1.0", "runs": [{"results": []}]})
            )
            completed.set()
        return {"status": "completed", "exit_code": 0}

    with pytest.raises(TypeError, match="unexpected adapter error"):
        run_pipeline(**pipeline_input, max_workers=2, invoke_fn=invoke, tool_version_fn=version)
    assert completed.is_set()


def test_duplicate_scanners_retain_sequential_output_and_failure_history(pipeline_input):
    calls = 0

    def version(binary, expected, output, tool, steps, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("version unavailable on retry")
        steps[tool + "-version"] = {"status": "completed"}

    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        (output / "semgrep.sarif").write_text(
            json.dumps({"version": "2.1.0", "runs": [{"results": []}]})
        )
        return {"status": "completed", "exit_code": 0, "argv": ["semgrep"]}

    result = run_pipeline(
        **{**pipeline_input, "scanners": ["semgrep", "semgrep"]},
        max_workers=2,
        invoke_fn=invoke,
        tool_version_fn=version,
    )
    assert calls == 2
    assert result.status == "failed"
    assert result.steps["semgrep"].get("argv") == ["semgrep"]
    assert "version unavailable" in result.steps["semgrep"].get("error", "")
