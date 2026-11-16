"""A member's own Semgrep and Bandit passes: named files, named raw IDs, one folder per rule."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.scanners.passes import run_bandit_pass, run_member_pass, run_semgrep_pass
from app.scanners.provenance import digest

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "tool", "rules": []}},
            "invocations": [{"executionSuccessful": True}],
            "results": [
                {
                    "ruleId": "tmp.out.semgrep-sql-injection-rules.r01.tainted-sql-string",
                    "message": {"text": "sql"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "db.py"},
                                "region": {"startLine": 4, "startColumn": 13, "endColumn": 20},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def _rules(root: Path) -> list[dict[str, Any]]:
    rules = []
    for index in range(2):
        path = root / f"rule{index}.yaml"
        path.write_text(f"rules: [{{id: r{index}}}]\n", encoding="utf-8")
        rules.append({"path": path.name, "sha256": digest(path)})
    return rules


class Invoke:
    def __init__(self, sarif: dict[str, Any] | None = SARIF, status: str = "completed") -> None:
        self.calls: list[tuple[list[str], str]] = []
        self.sarif, self.status = sarif, status

    def __call__(self, argv, cwd, output, name, timeout, env=None):
        self.calls.append(([str(a) for a in argv], name))
        if self.sarif is not None:
            target = Path(argv[argv.index("--output") + 1])
            target.write_text(json.dumps(self.sarif), encoding="utf-8")
        return {"status": self.status, "exit_code": 0, "seconds": 1.0}


def test_semgrep_pass_stages_each_rule_in_its_own_folder_and_names_its_files(tmp_path):
    root, source, output = tmp_path / "repo", tmp_path / "src", tmp_path / "out"
    for folder in (root, source, output):
        folder.mkdir()
    invoke = Invoke()
    record, findings, complete = run_semgrep_pass(
        name="semgrep-sql-injection",
        binary="semgrep",
        source=source,
        output=output,
        snapshot_sha256="5" * 64,
        repository_root=root,
        rules=_rules(root),
        jobs=1,
        timeout_seconds=60,
        invoke_fn=invoke,
    )
    ((argv, name),) = invoke.calls
    assert name == "semgrep-sql-injection"
    configs = [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]
    assert [Path(c).relative_to(output).as_posix() for c in configs] == [
        "semgrep-sql-injection-rules/r00/rule.yaml",
        "semgrep-sql-injection-rules/r01/rule.yaml",
    ]
    assert argv[argv.index("--output") + 1] == str(output / "semgrep-sql-injection.sarif")
    assert "--dataflow-traces" in argv and argv[-1] == "."
    assert complete and record["raw_findings"] == 1 and record["sarif_sha256"]
    (finding,) = findings
    # The pass name stays in the raw ID; the tool is Semgrep, so filters and labels still work.
    assert finding["raw_id"].startswith("semgrep-sql-injection:0:")
    assert finding["tool"] == "semgrep"


def test_a_rule_that_differs_from_its_pin_is_refused(tmp_path):
    root, source, output = tmp_path / "repo", tmp_path / "src", tmp_path / "out"
    for folder in (root, source, output):
        folder.mkdir()
    rules = _rules(root)
    (root / "rule0.yaml").write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        run_semgrep_pass(
            name="semgrep-sql-injection",
            binary="semgrep",
            source=source,
            output=output,
            snapshot_sha256="5" * 64,
            repository_root=root,
            rules=rules,
            jobs=1,
            timeout_seconds=60,
            invoke_fn=Invoke(),
        )


def test_bandit_pass_runs_the_pinned_tests_under_its_own_name(tmp_path):
    root, source, output = tmp_path / "repo", tmp_path / "src", tmp_path / "out"
    for folder in (root, source, output):
        folder.mkdir()
    (root / "bandit.ini").write_text("[bandit]\n", encoding="utf-8")
    invoke = Invoke(status="completed")
    record, findings, _ = run_bandit_pass(
        name="bandit-sql-injection",
        binary="bandit",
        source=source,
        output=output,
        snapshot_sha256="5" * 64,
        repository_root=root,
        config={"path": "bandit.ini", "sha256": digest(root / "bandit.ini")},
        tests=["B608", "B610", "B611"],
        timeout_seconds=60,
        invoke_fn=invoke,
    )
    ((argv, name),) = invoke.calls
    assert name == "bandit-sql-injection"
    assert argv[argv.index("--tests") + 1] == "B608,B610,B611"
    assert argv[argv.index("--ini") + 1] == str(output / "bandit-sql-injection.ini")
    assert "--ignore-nosec" in argv and "--exit-zero" in argv
    assert findings[0]["tool"] == "bandit" and findings[0]["raw_id"].startswith(
        "bandit-sql-injection:"
    )
    # The primary member's own files are never written by a member's pass.
    assert not (output / "bandit.ini").exists() and not (output / "bandit.sarif").exists()


def test_a_pass_without_sarif_fails_and_an_unknown_tool_is_refused(tmp_path):
    root, source, output = tmp_path / "repo", tmp_path / "src", tmp_path / "out"
    for folder in (root, source, output):
        folder.mkdir()
    config = {"semgrep_rules": _rules(root), "jobs": 1, "timeout_seconds": 60}
    with pytest.raises(RuntimeError, match="no SARIF"):
        run_member_pass(
            "semgrep",
            name="semgrep-sql-injection",
            config=config,
            source=source,
            output=output,
            snapshot_sha256="5" * 64,
            repository_root=root,
            invoke_fn=Invoke(sarif=None, status="failed"),
        )
    with pytest.raises(ValueError, match="No member pass for eslint"):
        run_member_pass(
            "eslint",
            name="eslint-sql-injection",
            config=config,
            source=source,
            output=output,
            snapshot_sha256="5" * 64,
            repository_root=root,
        )
