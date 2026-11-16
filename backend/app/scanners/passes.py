"""Named Semgrep and Bandit passes for a member of a composite scan.

The primary member of a composite scan runs Semgrep and Bandit under their own names
(`semgrep.sarif`, `bandit.sarif`, `rule-N.yaml`, `bandit.ini`); `app.scanners.semgrep` and
`app.scanners.bandit` write those names and the research registrations pin the Semgrep
adapter. A second member that runs the same tools with its own pinned rules gets a pass of its
own here, named after it (for example `semgrep-sql-injection`): its SARIF, logs, staged rules
and raw IDs carry that name, so nothing collides with the primary member's run. The command
lines are the adapters' own, with two differences for Semgrep:

- every rule file is staged in a folder of its own (`<name>-rules/r<index>/rule.yaml`), because
  Semgrep names a rule by the folder of its file plus the rule's ID, and several pinned files
  may define the same ID: the folder makes each reported rule traceable to one pinned file;
- the dataflow traces flag is kept, as in `run_semgrep`.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.provenance import digest, pinned_file
from app.scanners.sarif import Finding, sarif_findings
from app.scanners.semgrep import stage_rule

# The staged folder of a rule file, as it appears in Semgrep's rule ID: `...r<index>.<rule id>`.
STAGED_RULE_ID = re.compile(r"(?:^|\.)r(\d+)\.([A-Za-z0-9_-]+)$")


def rules_folder(name: str) -> str:
    return f"{name}-rules"


def run_semgrep_pass(
    *,
    name: str,
    binary: str,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    repository_root: Path,
    rules: Sequence[Mapping[str, object]],
    jobs: int,
    timeout_seconds: float,
    invoke_fn: InvokeCallable = invoke,
) -> tuple[ProcessRecord, list[Finding], bool]:
    """Run a member's pinned Semgrep rules as the pass `name`; raw IDs start with `name`."""
    if not rules:
        raise ValueError("A Semgrep pass needs at least one pinned rule")
    sarif = output / f"{name}.sarif"
    argv: list[str | Path] = [
        binary,
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        "--dataflow-traces",
        "--jobs",
        str(jobs),
        "--sarif",
        "--output",
        str(sarif),
    ]
    staged = output / rules_folder(name)
    for index, rule in enumerate(rules):
        folder = staged / f"r{index:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / "rule.yaml"
        stage_rule(rule, target, repository_root=repository_root)
        argv += ["--config", str(target)]
    argv += ["."]
    record = invoke_fn(argv, source, output, name, timeout_seconds)
    if not sarif.exists():
        raise RuntimeError("Scanner produced no SARIF output")
    findings, complete = sarif_findings(sarif, name, snapshot_sha256)
    for finding in findings:
        # The pass name stays in the raw ID; the tool is Semgrep, as when run alone.
        finding["tool"] = "semgrep"
    record["raw_findings"] = len(findings)
    record["sarif_sha256"] = digest(sarif)
    if record["status"] == "completed" and not complete:
        record["status"] = "partial"
    return record, findings, complete


def run_bandit_pass(
    *,
    name: str,
    binary: str,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    repository_root: Path,
    config: Mapping[str, object],
    tests: Sequence[str],
    timeout_seconds: float,
    invoke_fn: InvokeCallable = invoke,
) -> tuple[ProcessRecord, list[Finding], bool]:
    """Run a member's pinned Bandit tests as the pass `name`; raw IDs start with `name`."""
    if not tests or any(not isinstance(test, str) or not test for test in tests):
        raise ValueError("Bandit needs a non-empty list of test IDs")
    ini = output / f"{name}.ini"
    shutil.copyfile(pinned_file(config, repository_root), ini)
    sarif = output / f"{name}.sarif"
    argv: list[str | Path] = [
        binary,
        "--recursive",
        ".",
        "--format",
        "sarif",
        "--output",
        sarif,
        # An explicit ini stops Bandit from loading a .bandit file found in the scanned source.
        "--ini",
        ini,
        "--tests",
        ",".join(tests),
        # The scanned source must not be able to silence a test with a "# nosec" comment.
        "--ignore-nosec",
        # Without this Bandit exits 1 whenever it reports an issue.
        "--exit-zero",
        "--quiet",
    ]
    record = invoke_fn(argv, source, output, name, timeout_seconds)
    if not sarif.exists():
        raise RuntimeError("Scanner produced no SARIF output")
    findings, complete = sarif_findings(sarif, name, snapshot_sha256)
    for finding in findings:
        finding["tool"] = "bandit"
    record["raw_findings"] = len(findings)
    record["sarif_sha256"] = digest(sarif)
    if record["status"] == "completed" and not complete:
        record["status"] = "partial"
    return record, findings, complete


def run_member_pass(
    tool: str,
    *,
    name: str,
    config: Mapping[str, Any],
    source: Path,
    output: Path,
    snapshot_sha256: str,
    repository_root: Path,
    invoke_fn: InvokeCallable = invoke,
) -> tuple[ProcessRecord, list[Finding], bool]:
    """A member's own pass of `tool` ("semgrep" or "bandit"), configured by its language config."""
    if tool == "semgrep":
        return run_semgrep_pass(
            name=name,
            binary="semgrep",
            source=source,
            output=output,
            snapshot_sha256=snapshot_sha256,
            repository_root=repository_root,
            rules=config["semgrep_rules"],
            jobs=config["jobs"],
            timeout_seconds=config["timeout_seconds"],
            invoke_fn=invoke_fn,
        )
    if tool == "bandit":
        bandit = config["bandit"]
        return run_bandit_pass(
            name=name,
            binary="bandit",
            source=source,
            output=output,
            snapshot_sha256=snapshot_sha256,
            repository_root=repository_root,
            config=bandit["config"],
            tests=bandit["rules"],
            timeout_seconds=config["timeout_seconds"],
            invoke_fn=invoke_fn,
        )
    raise ValueError(f"No member pass for {tool}")
