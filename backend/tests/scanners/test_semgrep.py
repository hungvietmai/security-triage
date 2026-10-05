import json

from app.scanners.provenance import digest
from app.scanners.semgrep import run_semgrep


def test_run_semgrep_preserves_cli_arguments(tmp_path):
    repository_root = tmp_path / "repo"
    repository_root.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    rule = repository_root / "rule.yaml"
    rule.write_text("rules: []\n")

    commands = []

    def fake_invoke(argv, cwd, output_dir, name, timeout, env=None):
        commands.append([str(item) for item in argv])
        assert cwd == source
        assert output_dir == output
        assert name == "semgrep"
        assert timeout == 600
        (output / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}))
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
    assert record["raw_findings"] == 0
    assert findings == []
    assert complete is True


def test_stage_rule_rejects_path_escape(tmp_path):
    from app.scanners.semgrep import stage_rule

    target = tmp_path / "target.yaml"
    outside = tmp_path / "outside.yaml"
    outside.write_text("rules: []\n")
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
        output.write_text("rules: []\n")

    stage_rule(
        {"url": "https://example.test/rule.yaml", "sha256": "a" * 64},
        target,
        repository_root=tmp_path,
        fetch_fn=fake_fetch,
    )

    assert target.read_text() == "rules: []\n"
    assert calls == [
        (
            "https://example.test/rule.yaml",
            target,
            "a" * 64,
            2 * 1024 * 1024,
        )
    ]
