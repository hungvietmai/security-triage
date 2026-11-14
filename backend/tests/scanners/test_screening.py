"""Bandit and ESLint adapters: pinned configuration, hostile-source flags and status rules."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.scanners.bandit import run_bandit
from app.scanners.codeql import run_codeql_evidence
from app.scanners.eslint import FORMATTER, run_eslint
from app.scanners.pipeline import run_pipeline
from app.scanners.process import ProcessRecord, tool_version
from app.scanners.provenance import digest, pinned_file
from app.scanners.semgrep import run_semgrep_evidence

SNAPSHOT = "a" * 64


def _sarif(results: list[dict[str, Any]], *, successful: bool = True) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "tool", "rules": []}},
                    "invocations": [{"executionSuccessful": successful}],
                    "results": results,
                }
            ],
        }
    )


def _result(rule_id: str, uri: str, line: int) -> dict[str, Any]:
    region = {"startLine": line, "startColumn": 1, "endLine": line, "endColumn": 9}
    location = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
    return {"ruleId": rule_id, "message": {"text": "found"}, "locations": [location]}


@pytest.fixture
def tree(tmp_path: Path) -> dict[str, Path]:
    folders = {name: tmp_path / name for name in ("repo", "source", "output")}
    for folder in folders.values():
        folder.mkdir()
    return folders


def _pin(root: Path, relative: str, text: str) -> dict[str, str]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return {"path": relative, "sha256": digest(path)}


def _invoke(sarif: str | None, *, exit_code: int = 0, calls: list[list[str]] | None = None) -> Any:
    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        command = [str(item) for item in argv]
        if calls is not None:
            calls.append(command)
        if sarif is not None:
            (output / f"{name}.sarif").write_text(sarif, encoding="utf-8")
        status = "completed" if exit_code == 0 else "failed"
        return {"argv": command, "status": status, "exit_code": exit_code}

    return invoke


def test_bandit_runs_the_configured_tests_with_the_pinned_ini(tree):
    config = _pin(tree["repo"], "tools/bandit/bandit.ini", "[bandit]\n")
    calls: list[list[str]] = []
    record, findings, complete = run_bandit(
        binary="bandit",
        source=tree["source"],
        output=tree["output"],
        snapshot_sha256=SNAPSHOT,
        repository_root=tree["repo"],
        config=config,
        tests=["B602", "B605"],
        timeout_seconds=600,
        invoke_fn=_invoke(_sarif([_result("B605", "pkg/app.py", 6)]), calls=calls),
    )
    staged = tree["output"] / "bandit.ini"
    argv = calls[0]
    assert digest(staged) == config["sha256"]
    # The staged ini, not one from the scanned source; no "# nosec" suppression; exit 0 on issues.
    assert argv[argv.index("--ini") + 1] == str(staged)
    assert argv[argv.index("--tests") + 1] == "B602,B605"
    assert {"--ignore-nosec", "--exit-zero", "--recursive"} <= set(argv)
    assert (record["status"], record["raw_findings"], complete) == ("completed", 1, True)
    assert [(f["tool"], f["rule_id"], f["reported_path"]) for f in findings] == [
        ("bandit", "B605", "pkg/app.py")
    ]


@pytest.mark.parametrize(
    ("tests", "tamper", "message"),
    [([], False, "non-empty list of test IDs"), (["B602"], True, "checksum mismatch")],
)
def test_bandit_refuses_no_tests_or_a_changed_ini(tree, tests, tamper, message):
    config = _pin(tree["repo"], "bandit.ini", "[bandit]\n")
    if tamper:
        (tree["repo"] / "bandit.ini").write_text("[bandit]\nskips = B602\n", encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        run_bandit(
            binary="bandit",
            source=tree["source"],
            output=tree["output"],
            snapshot_sha256=SNAPSHOT,
            repository_root=tree["repo"],
            config=config,
            tests=tests,
            timeout_seconds=600,
            invoke_fn=_invoke(_sarif([])),
        )


def test_bandit_without_sarif_or_with_an_unsuccessful_run_is_not_a_clean_scan(tree):
    config = _pin(tree["repo"], "bandit.ini", "[bandit]\n")
    arguments: dict[str, Any] = {
        "binary": "bandit",
        "source": tree["source"],
        "output": tree["output"],
        "snapshot_sha256": SNAPSHOT,
        "repository_root": tree["repo"],
        "config": config,
        "tests": ["B602"],
        "timeout_seconds": 600,
    }
    with pytest.raises(RuntimeError, match="no SARIF output"):
        run_bandit(**arguments, invoke_fn=_invoke(None))
    record, _, complete = run_bandit(**arguments, invoke_fn=_invoke(_sarif([], successful=False)))
    assert (record["status"], complete) == ("partial", False)


def _eslint(tree: dict[str, Path], invoke_fn: Any, *, formatter: bool = True) -> Any:
    config = _pin(tree["repo"], "tools/eslint/eslint.config.mjs", "export default [];\n")
    lockfile = _pin(tree["repo"], "tools/eslint/package-lock.json", "{}\n")
    if formatter:
        _pin(tree["repo"], f"tools/eslint/{FORMATTER}", "module.exports = () => '';\n")
    return run_eslint(
        binary="eslint",
        source=tree["source"],
        output=tree["output"],
        snapshot_sha256=SNAPSHOT,
        repository_root=tree["repo"],
        config=config,
        lockfile=lockfile,
        rules=["security/detect-child-process"],
        timeout_seconds=600,
        invoke_fn=invoke_fn,
    )


def test_eslint_uses_the_pinned_toolchain_and_reports_paths_relative_to_the_source(tree):
    inside = (tree["source"].resolve() / "lib" / "a b.js").as_uri()
    outside = (tree["repo"].resolve() / "elsewhere.js").as_uri()
    calls: list[list[str]] = []
    record, findings, complete = _eslint(
        tree,
        _invoke(
            _sarif(
                [
                    _result("security/detect-child-process", inside, 3),
                    _result("security/detect-child-process", outside, 4),
                ]
            ),
            calls=calls,
        ),
    )
    argv = calls[0]
    toolchain = tree["repo"].resolve() / "tools/eslint"
    # Configuration and formatter are absolute paths into the pinned toolchain: ESLint would
    # otherwise look both up from the scanned directory.
    assert argv[argv.index("--config") + 1] == str(toolchain / "eslint.config.mjs")
    assert argv[argv.index("--format") + 1] == str(toolchain / FORMATTER)
    assert argv[argv.index("--rule") + 1] == "security/detect-child-process: warn"
    assert (tree["output"] / "eslint.config.mjs").is_file()
    assert (record["status"], complete) == ("completed", True)
    # A URI outside the source root is kept as reported, so it can never match a source file.
    assert [f["reported_path"] for f in findings] == ["lib/a b.js", outside]


@pytest.mark.parametrize(
    ("exit_code", "successful", "status"),
    [(1, False, "partial"), (1, True, "completed"), (2, True, "failed")],
)
def test_eslint_exit_one_is_a_finished_run_and_a_parse_error_makes_it_partial(
    tree, exit_code, successful, status
):
    record, _, _ = _eslint(tree, _invoke(_sarif([], successful=successful), exit_code=exit_code))
    assert record["status"] == status


def test_eslint_refuses_a_missing_formatter_missing_sarif_or_empty_rules(tree):
    with pytest.raises(RuntimeError, match="not installed next to its pinned configuration"):
        _eslint(tree, _invoke(_sarif([])), formatter=False)
    with pytest.raises(RuntimeError, match="no SARIF output"):
        _eslint(tree, _invoke(None))
    with pytest.raises(ValueError, match="non-empty list of rule IDs"):
        run_eslint(
            binary="eslint",
            source=tree["source"],
            output=tree["output"],
            snapshot_sha256=SNAPSHOT,
            repository_root=tree["repo"],
            config={},
            lockfile={},
            rules=[],
            timeout_seconds=600,
        )


@pytest.mark.parametrize(
    ("tool", "stdout", "expected"),
    [
        ("bandit", "bandit 1.9.4\n  python version = 3.12.3 (main)\n", "1.9.4"),
        ("eslint", "v10.15.0\n", "10.15.0"),
    ],
)
def test_tool_version_reads_bandit_and_eslint_output(tmp_path, tool, stdout, expected):
    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        assert [str(item) for item in argv] == [tool, "--version"]
        (output / f"{name}.stdout.log").write_text(stdout, encoding="utf-8")
        return {"status": "completed", "exit_code": 0}

    steps: dict[str, ProcessRecord] = {}
    tool_version(
        tool, expected, tmp_path, tool, steps, working_directory=tmp_path, invoke_fn=invoke
    )
    assert steps[f"{tool}-version"]["status"] == "completed"
    with pytest.raises(ValueError, match="version mismatch"):
        tool_version(
            tool, "0.0.0", tmp_path, tool, steps, working_directory=tmp_path, invoke_fn=invoke
        )


def _pipeline(tree: dict[str, Path], scanners: list[str], **screening: Any) -> Any:
    versions: list[tuple[str, str]] = []

    def version(binary, expected, output, tool, steps, *, working_directory, invoke_fn):
        versions.append((tool, expected))
        steps[tool + "-version"] = {"status": "completed"}

    result = run_pipeline(
        scanners=scanners,  # type: ignore[arg-type]
        language="python",
        source=tree["source"],
        output=tree["output"],
        snapshot_sha256=SNAPSHOT,
        repository_root=tree["repo"],
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[],
        codeql_queries=[],
        codeql_query_sha256={},
        javascript_query_pack=None,
        python_query_pack=None,
        jobs=1,
        timeout_seconds=600,
        codeql_ram_mb=2048,
        invoke_fn=_invoke(_sarif([_result("B602", "app.py", 2)])),
        tool_version_fn=version,
        **screening,
    )
    return result, versions


def test_pipeline_runs_a_screening_tool_from_its_language_config_entry(tree):
    entry = {
        "version": "1.9.4",
        "config": _pin(tree["repo"], "bandit.ini", "[bandit]\n"),
        "rules": ["B602"],
    }
    result, versions = _pipeline(tree, ["bandit"], bandit=entry)
    assert versions == [("bandit", "1.9.4")]
    assert result.status == "completed"
    assert result.steps["bandit"]["raw_findings"] == 1
    assert [finding["raw_id"] for finding in result.findings] == ["bandit:0:0"]


@pytest.mark.parametrize(
    ("screening", "error"),
    [({}, "lists bandit but does not configure it"), ({"bandit": {"version": "1.9.4"}}, "config")],
)
def test_pipeline_records_an_unconfigured_screening_tool_as_a_failed_step(tree, screening, error):
    result, _ = _pipeline(tree, ["bandit"], **screening)
    assert result.status == "failed"
    assert result.steps["bandit"]["status"] == "failed"
    assert error in result.steps["bandit"]["error"]


def test_pipeline_runs_eslint_from_its_language_config_entry(tree):
    entry = {
        "version": "10.15.0",
        "config": _pin(tree["repo"], "tools/eslint/eslint.config.mjs", "export default [];\n"),
        "lockfile": _pin(tree["repo"], "tools/eslint/package-lock.json", "{}\n"),
        "rules": ["security/detect-child-process"],
    }
    _pin(tree["repo"], f"tools/eslint/{FORMATTER}", "module.exports = () => '';\n")
    result, versions = _pipeline(tree, ["eslint"], eslint=entry)
    assert versions == [("eslint", "10.15.0")]
    assert result.status == "completed"
    assert [finding["tool"] for finding in result.findings] == ["eslint"]


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"path": "", "sha256": "0" * 64}, "needs a path and a sha256"),
        ({"path": "../outside.ini", "sha256": "0" * 64}, "must stay inside the repository"),
        ({"path": "missing.ini", "sha256": "0" * 64}, "missing or checksum mismatch"),
    ],
)
def test_pinned_file_rejects_entries_that_are_malformed_outside_or_missing(tree, entry, message):
    (tree["repo"].parent / "outside.ini").write_text("[bandit]\n", encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        pinned_file(entry, tree["repo"])


def _database(tree: dict[str, Path]) -> dict[str, Any]:
    """A pinned evidence pack and the database directory `run_codeql` would have left."""
    (tree["output"] / "codeql-db").mkdir()
    pack = tree["repo"] / "pack"
    query = _pin(tree["repo"], "pack/queries/all.ql", "select 1\n")
    return {
        "binary": "codeql",
        "source": tree["source"],
        "output": tree["output"],
        "snapshot_sha256": SNAPSHOT,
        "query_pack": pack,
        "queries": ["queries/all.ql"],
        "expected_query_sha256": {"queries/all.ql": query["sha256"]},
        "jobs": 1,
        "ram_mb": 2048,
        "timeout_seconds": 600,
    }


def test_evidence_queries_reuse_the_scan_database_and_rerun(tree):
    calls: list[list[str]] = []
    sarif = _sarif([_result("st/cwe-78/all", "app.py", 2)])

    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        calls.append([str(item) for item in argv])
        (output / "codeql-evidence.sarif").write_text(sarif, encoding="utf-8")
        return {"status": "completed", "exit_code": 0}

    record, findings, complete = run_codeql_evidence(**_database(tree), invoke_fn=invoke)
    argv = calls[0]
    # One analyze call on the existing database: no "database create".
    assert argv[1:4] == ["database", "analyze", str(tree["output"] / "codeql-db")]
    assert "--rerun" in argv and len(calls) == 1
    assert (record["status"], record["raw_findings"], complete) == ("completed", 1, True)
    assert [(f["tool"], f["rule_id"]) for f in findings] == [("codeql-evidence", "st/cwe-78/all")]


def test_evidence_queries_need_a_database_and_the_pinned_query_bytes(tree):
    arguments = _database(tree)
    (tree["repo"] / "pack/queries/all.ql").write_text("select 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="evidence query digest mismatch"):
        run_codeql_evidence(**arguments, invoke_fn=_invoke(_sarif([])))
    (tree["output"] / "codeql-db").rmdir()
    with pytest.raises(RuntimeError, match="No CodeQL database"):
        run_codeql_evidence(**arguments, invoke_fn=_invoke(_sarif([])))


@pytest.mark.parametrize("evidence_fails", [False, True])
def test_pipeline_runs_evidence_queries_on_the_codeql_database_and_survives_their_failure(
    tree, evidence_fails
):
    pack = tree["repo"] / "pack"
    query = _pin(tree["repo"], "pack/Security/q.ql", "select 1\n")
    _pin(tree["repo"], "pack/qlpack.yml", "name: p\n")
    evidence = _pin(tree["repo"], "evidence/queries/all.ql", "select 2\n")
    names: list[str] = []

    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        names.append(name)
        if name == "codeql-create":
            (output / "codeql-db").mkdir()
        elif name == "codeql":
            sarif = _sarif([_result("py/command-line-injection", "app.py", 2)])
            (output / "codeql.sarif").write_text(sarif, encoding="utf-8")
        elif name == "codeql-evidence" and not evidence_fails:
            sarif = _sarif([_result("st/cwe-78/none", "app.py", 2)])
            (output / "codeql-evidence.sarif").write_text(sarif, encoding="utf-8")
        return {"status": "completed", "exit_code": 0}

    def version(binary, expected, output, tool, steps, *, working_directory, invoke_fn):
        steps[tool + "-version"] = {"status": "completed"}

    result = run_pipeline(
        scanners=["codeql"],
        language="python",
        source=tree["source"],
        output=tree["output"],
        snapshot_sha256=SNAPSHOT,
        repository_root=tree["repo"],
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[],
        codeql_queries=["Security/q.ql"],
        codeql_query_sha256={"Security/q.ql": query["sha256"]},
        javascript_query_pack=None,
        python_query_pack=pack,
        jobs=1,
        timeout_seconds=600,
        codeql_ram_mb=2048,
        codeql_evidence={
            "query_pack": tree["repo"] / "evidence",
            "queries": ["queries/all.ql"],
            "query_sha256": {"queries/all.ql": evidence["sha256"]},
        },
        invoke_fn=invoke,
        tool_version_fn=version,
    )
    # Evidence queries run last, on the database CodeQL just analyzed.
    assert names == ["codeql-create", "codeql", "codeql-evidence"]
    # The scan's own status and alerts never depend on the adjudication step.
    assert result.status == "completed"
    assert [finding["raw_id"] for finding in result.findings] == ["codeql:0:0"]
    if evidence_fails:
        assert result.steps["codeql-evidence"]["status"] == "failed"
        assert "no SARIF output" in result.steps["codeql-evidence"]["error"]
        assert result.evidence_findings == []
    else:
        assert result.steps["codeql-evidence"]["raw_findings"] == 1
        assert [f["tool"] for f in result.evidence_findings] == ["codeql-evidence"]


def test_semgrep_evidence_rules_run_from_the_pinned_file_and_stay_out_of_the_alerts(tree):
    rules = _pin(tree["repo"], "rules/semgrep/evidence.yaml", "rules: []\n")
    calls: list[list[str]] = []
    sarif = _sarif([_result("tmp.st-cmd-flow-none", "app.py", 2)])
    record, findings, complete = run_semgrep_evidence(
        binary="semgrep",
        source=tree["source"],
        output=tree["output"],
        snapshot_sha256=SNAPSHOT,
        repository_root=tree["repo"],
        rules=rules,
        jobs=1,
        timeout_seconds=600,
        invoke_fn=_invoke(sarif, calls=calls),
    )
    staged = tree["output"] / "semgrep-evidence.yaml"
    argv = calls[0]
    assert digest(staged) == rules["sha256"]
    assert argv[argv.index("--config") + 1] == str(staged)
    assert {"--disable-nosem", "--no-git-ignore", "--metrics=off"} <= set(argv)
    assert (record["status"], complete) == ("completed", True)
    assert [(f["tool"], f["raw_id"]) for f in findings] == [
        ("semgrep-evidence", "semgrep-evidence:0:0")
    ]
    (tree["repo"] / "rules/semgrep/evidence.yaml").write_text("rules: [x]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        run_semgrep_evidence(
            binary="semgrep",
            source=tree["source"],
            output=tree["output"],
            snapshot_sha256=SNAPSHOT,
            repository_root=tree["repo"],
            rules=rules,
            jobs=1,
            timeout_seconds=600,
            invoke_fn=_invoke(sarif),
        )


@pytest.mark.parametrize("evidence_fails", [False, True])
def test_pipeline_runs_semgrep_evidence_after_semgrep_and_survives_its_failure(
    tree, evidence_fails
):
    rules = _pin(tree["repo"], "evidence.yaml", "rules: []\n")
    names: list[str] = []

    def invoke(argv, cwd, output, name, timeout, env=None) -> ProcessRecord:
        names.append(name)
        if name == "semgrep":
            (output / "semgrep.sarif").write_text(_sarif([]), encoding="utf-8")
        elif not evidence_fails:
            sarif = _sarif([_result("tmp.st-cmd-flow-none", "app.py", 2)])
            (output / "semgrep-evidence.sarif").write_text(sarif, encoding="utf-8")
        return {"status": "completed", "exit_code": 0}

    def version(binary, expected, output, tool, steps, *, working_directory, invoke_fn):
        steps[tool + "-version"] = {"status": "completed"}

    result = run_pipeline(
        scanners=["semgrep"],
        language="python",
        source=tree["source"],
        output=tree["output"],
        snapshot_sha256=SNAPSHOT,
        repository_root=tree["repo"],
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version="1.178.0",
        codeql_version="2.27.1",
        semgrep_rules=[],
        codeql_queries=[],
        codeql_query_sha256={},
        javascript_query_pack=None,
        python_query_pack=None,
        jobs=1,
        timeout_seconds=600,
        codeql_ram_mb=2048,
        semgrep_evidence={"rules": rules},
        invoke_fn=invoke,
        tool_version_fn=version,
    )
    assert names == ["semgrep", "semgrep-evidence"]
    assert result.status == "completed" and result.findings == []
    if evidence_fails:
        assert result.steps["semgrep-evidence"]["status"] == "failed"
        assert result.evidence_findings == []
    else:
        assert [f["tool"] for f in result.evidence_findings] == ["semgrep-evidence"]
