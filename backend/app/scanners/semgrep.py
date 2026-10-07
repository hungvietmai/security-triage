"""Semgrep subprocess adapter."""

from __future__ import annotations

import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from app.scanners.acquisition import fetch
from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.provenance import digest
from app.scanners.sarif import Finding, sarif_findings

MAX_RULE_BYTES = 2 * 1024 * 1024


class FetchCallable(Protocol):
    def __call__(self, url: str, target: Path, expected_hash: str, max_bytes: int, /) -> None: ...


def _required_rule_str(rule: Mapping[str, object], key: str) -> str:
    value = rule.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Semgrep rule {key} must be a non-empty string")
    return value


def stage_rule(
    rule: Mapping[str, object],
    target: Path,
    *,
    repository_root: Path,
    fetch_fn: FetchCallable = fetch,
) -> None:
    """Stage one pinned local or remote Semgrep rule."""
    if ("path" in rule) == ("url" in rule):
        raise ValueError("Rule needs exactly one of path or url")
    expected_hash = _required_rule_str(rule, "sha256")
    if "url" in rule:
        fetch_fn(_required_rule_str(rule, "url"), target, expected_hash, MAX_RULE_BYTES)
        return

    relative = Path(_required_rule_str(rule, "path"))
    source = (repository_root / relative).resolve()
    root = repository_root.resolve()
    if relative.is_absolute() or not source.is_relative_to(root):
        raise ValueError("Local rule must stay inside repository")
    if source.stat().st_size > MAX_RULE_BYTES or digest(source) != expected_hash:
        raise ValueError("Local rule size limit or checksum mismatch")
    shutil.copyfile(source, target)


def run_semgrep(
    *,
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
    """Run Semgrep with the exact development-runner CLI arguments."""
    sarif = output / "semgrep.sarif"
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
    for index, rule in enumerate(rules):
        local = output / f"rule-{index}.yaml"
        stage_rule(rule, local, repository_root=repository_root)
        argv += ["--config", str(local)]
    argv += ["."]

    record = invoke_fn(argv, source, output, "semgrep", timeout_seconds)
    if not sarif.exists():
        raise RuntimeError("Scanner produced no SARIF output")
    findings, complete = sarif_findings(sarif, "semgrep", snapshot_sha256)
    record["raw_findings"] = len(findings)
    record["sarif_sha256"] = digest(sarif)
    if record["status"] == "completed" and not complete:
        record["status"] = "partial"
    return record, findings, complete


def run_sink_locator(
    *,
    binary: str,
    source: Path,
    output: Path,
    rule: Path,
    jobs: int,
    timeout_seconds: float,
    invoke_fn: InvokeCallable = invoke,
) -> tuple[ProcessRecord, str]:
    """Run the versioned JavaScript sink-locator rule and return its JSON text."""
    result = output / "sink-locator-v0.json"
    argv: list[str | Path] = [
        binary,
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        "--jobs",
        str(jobs),
        "--json",
        "--output",
        result,
        "--config",
        rule,
        ".",
    ]
    record = invoke_fn(argv, source, output, "sink-locator-javascript", timeout_seconds)
    if record["status"] != "completed":
        raise RuntimeError("JavaScript sink locator failed; see locator logs")
    return record, result.read_text(encoding="utf-8")
