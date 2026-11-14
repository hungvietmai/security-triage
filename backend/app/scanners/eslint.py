"""ESLint subprocess adapter: JavaScript/TypeScript screening with eslint-plugin-security."""

from __future__ import annotations

import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import unquote

from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.provenance import digest, pinned_file
from app.scanners.sarif import Finding, sarif_findings

STAGED_CONFIG = "eslint.config.mjs"
# Installed by npm ci next to the pinned configuration (tools/install-scanners.sh).
FORMATTER = "node_modules/@microsoft/eslint-formatter-sarif/sarif.js"


def _relative_path(uri: str | None, source: Path) -> str | None:
    """ESLint reports absolute file URIs; findings carry paths relative to the source root."""
    prefix = source.resolve().as_uri().rstrip("/") + "/"
    if uri is None or not uri.startswith(prefix):
        return uri
    return unquote(uri[len(prefix) :])


def run_eslint(
    *,
    binary: str,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    repository_root: Path,
    config: Mapping[str, object],
    lockfile: Mapping[str, object],
    rules: Sequence[str],
    timeout_seconds: float,
    invoke_fn: InvokeCallable = invoke,
) -> tuple[ProcessRecord, list[Finding], bool]:
    """Run the configured ESLint rules on the whole source tree and return its SARIF results."""
    if not rules or any(not isinstance(rule, str) or not rule for rule in rules):
        raise ValueError("ESLint needs a non-empty list of rule IDs")
    # The lockfile decides which plugin, parser and formatter code the image installed.
    pinned_file(lockfile, repository_root)
    # The configuration imports the plugin and the parser, so it runs from where they are
    # installed; the copy in the output directory records the bytes that were verified.
    configuration = pinned_file(config, repository_root)
    shutil.copyfile(configuration, output / STAGED_CONFIG)
    # ESLint resolves a formatter name from the scanned directory. An absolute path to the
    # pinned formatter means no module is ever loaded from the scanned source.
    formatter = configuration.parent / FORMATTER
    if not formatter.is_file():
        raise RuntimeError("ESLint toolchain is not installed next to its pinned configuration")
    sarif = output / "eslint.sarif"
    argv: list[str | Path] = [binary, "--config", configuration]
    for rule in rules:
        # "warn" keeps a finding from changing the exit code; only a fatal error does.
        argv += ["--rule", f"{rule}: warn"]
    argv += [
        "--no-error-on-unmatched-pattern",
        "--no-warn-ignored",
        "--format",
        formatter,
        "--output-file",
        sarif,
        ".",
    ]
    record = invoke_fn(argv, source, output, "eslint", timeout_seconds)
    if not sarif.exists():
        raise RuntimeError("Scanner produced no SARIF output")
    findings, complete = sarif_findings(sarif, "eslint", snapshot_sha256)
    for finding in findings:
        finding["reported_path"] = _relative_path(finding["reported_path"], source)
    record["raw_findings"] = len(findings)
    record["sarif_sha256"] = digest(sarif)
    # Exit 1 means linting ran and reported a problem. With every rule at "warn" that is a file
    # ESLint could not parse, which the SARIF invocation already marks as unsuccessful.
    if record["status"] == "failed" and record.get("exit_code") == 1:
        record["status"] = "completed"
    if record["status"] == "completed" and not complete:
        record["status"] = "partial"
    return record, findings, complete
