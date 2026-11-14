"""Bandit subprocess adapter: a Python screening scanner that reports call-site patterns."""

from __future__ import annotations

import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path

from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.provenance import digest, pinned_file
from app.scanners.sarif import Finding, sarif_findings

STAGED_CONFIG = "bandit.ini"


def run_bandit(
    *,
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
    """Run the configured Bandit tests on the whole source tree and return its SARIF results."""
    if not tests or any(not isinstance(test, str) or not test for test in tests):
        raise ValueError("Bandit needs a non-empty list of test IDs")
    ini = output / STAGED_CONFIG
    shutil.copyfile(pinned_file(config, repository_root), ini)
    sarif = output / "bandit.sarif"
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
    record = invoke_fn(argv, source, output, "bandit", timeout_seconds)
    if not sarif.exists():
        raise RuntimeError("Scanner produced no SARIF output")
    findings, complete = sarif_findings(sarif, "bandit", snapshot_sha256)
    record["raw_findings"] = len(findings)
    record["sarif_sha256"] = digest(sarif)
    if record["status"] == "completed" and not complete:
        record["status"] = "partial"
    return record, findings, complete
