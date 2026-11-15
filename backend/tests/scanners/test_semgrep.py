import json

import pytest

from app.scanners.process import ProcessRecord
from app.scanners.provenance import digest
from app.scanners.semgrep import control_semgrep_targets, run_semgrep, run_sink_locator


def test_run_semgrep_preserves_cli_arguments(tmp_path):
    repository_root = tmp_path / "repo"
    repository_root.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    rule = repository_root / "rule.yaml"
    rule.write_text("rules: []\n", encoding="utf-8")

    commands = []

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        commands.append([str(item) for item in argv])
        assert cwd == source
        assert output_dir == output
        assert name == "semgrep"
        assert timeout == 600
        (output / "semgrep.sarif").write_text(
            json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
        )
        return {
            "argv": [str(item) for item in argv],
            "status": "completed",
            "exit_code": 0,
            "seconds": 0.1,
        }

    record, findings, complete = run_semgrep(
        binary="/tools/semgrep",
        source=source,
        output=output,
        snapshot_sha256="a" * 64,
        repository_root=repository_root,
        rules=[{"path": "rule.yaml", "sha256": digest(rule)}],
        jobs=1,
        timeout_seconds=600,
        invoke_fn=fake_invoke,
    )

    assert commands == [
        [
            "/tools/semgrep",
            "scan",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--dataflow-traces",
            "--jobs",
            "1",
            "--sarif",
            "--output",
            str(output / "semgrep.sarif"),
            "--config",
            str(output / "rule-0.yaml"),
            ".",
        ]
    ]
    assert record["status"] == "completed"
    assert record.get("raw_findings") == 0
    assert findings == []
    assert complete is True


def test_stage_rule_rejects_path_escape(tmp_path):
    from app.scanners.semgrep import stage_rule

    target = tmp_path / "target.yaml"
    outside = tmp_path / "outside.yaml"
    outside.write_text("rules: []\n", encoding="utf-8")
    repository_root = tmp_path / "repo"
    repository_root.mkdir()

    try:
        stage_rule(
            {"path": "../outside.yaml", "sha256": digest(outside)},
            target,
            repository_root=repository_root,
        )
    except ValueError as exc:
        assert str(exc) == "Local rule must stay inside repository"
    else:
        raise AssertionError("path escape was accepted")


def test_stage_remote_rule_uses_injected_fetch(tmp_path):
    from app.scanners.semgrep import stage_rule

    target = tmp_path / "rule.yaml"
    calls = []

    def fake_fetch(url, output, expected_hash, max_bytes):
        calls.append((url, output, expected_hash, max_bytes))
        output.write_text("rules: []\n", encoding="utf-8")

    stage_rule(
        {"url": "https://example.test/rule.yaml", "sha256": "a" * 64},
        target,
        repository_root=tmp_path,
        fetch_fn=fake_fetch,
    )

    assert target.read_text(encoding="utf-8") == "rules: []\n"
    assert calls == [
        (
            "https://example.test/rule.yaml",
            target,
            "a" * 64,
            2 * 1024 * 1024,
        )
    ]


def test_run_sink_locator_returns_json_and_fails_closed(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    rule = tmp_path / "locator.yaml"
    calls = []

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        calls.append((argv, cwd, name, timeout))
        (output_dir / "sink-locator-v0.json").write_text('{"results": []}', encoding="utf-8")
        return {"argv": [str(a) for a in argv], "status": "completed", "exit_code": 0}

    record, text = run_sink_locator(
        binary="semgrep",
        source=tmp_path,
        output=output,
        rule=rule,
        jobs=2,
        timeout_seconds=9,
        invoke_fn=fake_invoke,
    )
    assert json.loads(text) == {"results": []}
    assert record["status"] == "completed"
    argv, cwd, name, timeout = calls[0]
    assert argv[-3:] == ["--config", rule, "."]
    assert (cwd, name, timeout) == (tmp_path, "sink-locator-javascript", 9)

    def failing_invoke(argv, cwd, output_dir, name, timeout, env=None) -> ProcessRecord:
        return {"argv": [], "status": "failed", "exit_code": 2}

    with pytest.raises(RuntimeError, match="sink locator failed"):
        run_sink_locator(
            binary="semgrep",
            source=tmp_path,
            output=output,
            rule=rule,
            jobs=1,
            timeout_seconds=1,
            invoke_fn=failing_invoke,
        )


def test_the_scanned_source_cannot_decide_which_files_semgrep_skips(tmp_path):
    # A repository can ship ignore files at any depth; Semgrep would honour each of them.
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "app.js").write_text("exec(x)\n", encoding="utf-8")
    (tmp_path / ".semgrepignore").write_text("build/\n", encoding="utf-8")
    (tmp_path / "build" / ".semgrepignore").write_text("*.js\n", encoding="utf-8")

    assert control_semgrep_targets(tmp_path, "worker-controlled-v1") == 2
    assert [p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob(".semgrepignore")] == [
        ".semgrepignore"
    ]
    assert (tmp_path / ".semgrepignore").read_bytes() == b"node_modules/\n"
    # Source files are left alone, and a second call (the next language) changes nothing.
    assert control_semgrep_targets(tmp_path, "worker-controlled-v1") == 1
    assert (tmp_path / "build" / "app.js").read_text(encoding="utf-8") == "exec(x)\n"
    with pytest.raises(KeyError):
        control_semgrep_targets(tmp_path, "unknown-selection")
