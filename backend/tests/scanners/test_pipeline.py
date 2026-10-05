import json

from app.scanners.pipeline import run_pipeline
from app.scanners.process import ToolName
from app.scanners.provenance import digest


def test_pipeline_accepts_injected_process_functions(tmp_path):
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

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None):
        invoke_calls.append((name, [str(item) for item in argv]))
        if name == "semgrep":
            (output / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
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

    assert result.status == "completed"
    assert result.findings == []
    assert version_calls[0][:4] == (
        "/tools/semgrep",
        "1.178.0",
        "semgrep",
        repository_root,
    )
    assert version_calls[0][4] is fake_invoke
    assert invoke_calls[0][0] == "semgrep"
