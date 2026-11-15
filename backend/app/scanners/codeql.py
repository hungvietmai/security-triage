"""CodeQL subprocess adapter."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.provenance import digest
from app.scanners.sarif import Finding, sarif_findings


@dataclass(frozen=True, slots=True)
class CodeQLRun:
    create_record: ProcessRecord
    analyze_record: ProcessRecord
    findings: list[Finding]
    complete: bool
    query_files: dict[str, str]
    pack_manifest: str


def query_pack_for_language(
    language: str,
    *,
    javascript_query_pack: Path | None,
    python_query_pack: Path | None,
) -> Path:
    """Select an explicitly supplied pinned query pack for a language."""
    if language == "javascript":
        pack = javascript_query_pack
    elif language == "python":
        pack = python_query_pack
    else:
        raise ValueError(f"Unsupported CodeQL language: {language}")
    if pack is None:
        raise ValueError(f"--{language}-query-pack must point to bundled pinned queries")
    return pack.resolve()


def run_codeql(
    *,
    binary: str,
    language: str,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    query_pack: Path,
    queries: Sequence[str],
    expected_query_sha256: Mapping[str, str],
    jobs: int,
    ram_mb: int,
    timeout_seconds: float,
    invoke_fn: InvokeCallable = invoke,
) -> CodeQLRun:
    """Create and analyze a CodeQL database with pinned query bytes."""
    query_paths = [query_pack / query for query in queries]
    if not all(path.is_file() for path in query_paths):
        raise ValueError("Configured CodeQL query missing from pack")

    query_files = {path.relative_to(query_pack).as_posix(): digest(path) for path in query_paths}
    if query_files != dict(expected_query_sha256):
        raise ValueError("CodeQL query digest mismatch")
    pack_manifest = (query_pack / "qlpack.yml").read_text(encoding="utf-8")

    database = output / "codeql-db"
    create_record = invoke_fn(
        [
            binary,
            "database",
            "create",
            str(database),
            "--language=" + language,
            "--source-root",
            str(source),
            "--build-mode=none",
            "--threads",
            str(jobs),
            f"--ram={ram_mb}",
        ],
        source,
        output,
        "codeql-create",
        timeout_seconds,
    )
    if create_record["status"] != "completed":
        raise RuntimeError("CodeQL extraction failed")

    sarif = output / "codeql.sarif"
    analyze_record = invoke_fn(
        [
            binary,
            "database",
            "analyze",
            str(database),
            *[str(path) for path in query_paths],
            "--format=sarif-latest",
            "--output",
            str(sarif),
            "--threads",
            str(jobs),
            f"--ram={ram_mb}",
        ],
        source,
        output,
        "codeql",
        timeout_seconds,
    )
    if not sarif.exists():
        raise RuntimeError("Scanner produced no SARIF output")
    findings, complete = sarif_findings(sarif, "codeql", snapshot_sha256)
    analyze_record["raw_findings"] = len(findings)
    analyze_record["sarif_sha256"] = digest(sarif)
    if analyze_record["status"] == "completed" and not complete:
        analyze_record["status"] = "partial"

    return CodeQLRun(
        create_record=create_record,
        analyze_record=analyze_record,
        findings=findings,
        complete=complete,
        query_files=query_files,
        pack_manifest=pack_manifest,
    )


def run_codeql_evidence(
    *,
    binary: str,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    query_pack: Path,
    queries: Sequence[str],
    expected_query_sha256: Mapping[str, str],
    jobs: int,
    ram_mb: int,
    timeout_seconds: float,
    invoke_fn: InvokeCallable = invoke,
    name: str = "codeql-evidence",
) -> tuple[ProcessRecord, list[Finding], bool]:
    """Run pinned safety-evidence queries on the database `run_codeql` already created.

    The adjudication step reuses the extraction: no second database is built. Its alerts are
    evidence about the scan's CodeQL alerts, so they carry the tool name "codeql-evidence" and
    are never reconciled into units.

    `name` names this analysis pass: its SARIF and log files, its process record and the
    prefix of its results' raw IDs. Several packs can be analyzed on one database, one pass
    each, without overwriting one another; the default is the adjudication step's name.
    """
    database = output / "codeql-db"
    if not database.is_dir():
        raise RuntimeError("No CodeQL database to run evidence queries on")
    query_paths = [query_pack / query for query in queries]
    if not all(path.is_file() for path in query_paths):
        raise ValueError("Configured CodeQL evidence query missing from pack")
    observed = {path.relative_to(query_pack).as_posix(): digest(path) for path in query_paths}
    if observed != dict(expected_query_sha256):
        raise ValueError("CodeQL evidence query digest mismatch")
    sarif = output / f"{name}.sarif"
    record = invoke_fn(
        [
            binary,
            "database",
            "analyze",
            str(database),
            *[str(path) for path in query_paths],
            "--format=sarif-latest",
            "--output",
            str(sarif),
            # A cached result of the same query path would otherwise be reused across packs.
            "--rerun",
            "--threads",
            str(jobs),
            f"--ram={ram_mb}",
        ],
        source,
        output,
        name,
        timeout_seconds,
    )
    if not sarif.exists():
        raise RuntimeError("Evidence queries produced no SARIF output")
    findings, complete = sarif_findings(sarif, name, snapshot_sha256)
    record["raw_findings"] = len(findings)
    record["sarif_sha256"] = digest(sarif)
    if record["status"] == "completed" and not complete:
        record["status"] = "partial"
    return record, findings, complete
