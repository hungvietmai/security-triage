"""Scanner orchestration independent of CLI and worker frameworks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from app.scanners.codeql import query_pack_for_language, run_codeql
from app.scanners.process import (
    InvokeCallable,
    ProcessRecord,
    ToolName,
    ToolVersionCallable,
    invoke,
    tool_version,
)
from app.scanners.sarif import Finding
from app.scanners.semgrep import run_semgrep

PipelineStatus = Literal["completed", "partial", "failed"]


@dataclass(frozen=True, slots=True)
class PipelineResult:
    status: PipelineStatus
    steps: dict[str, ProcessRecord]
    findings: list[Finding]
    codeql_query_files: dict[str, str] | None
    codeql_pack_manifest: str | None


def _status(scanners: Sequence[ToolName], steps: Mapping[str, ProcessRecord]) -> PipelineStatus:
    statuses = [steps.get(scanner, {}).get("status") for scanner in scanners]
    if scanners and all(status == "completed" for status in statuses):
        return "completed"
    if any(status in {"completed", "partial"} for status in statuses):
        return "partial"
    return "failed"


def run_pipeline(
    *,
    scanners: Sequence[ToolName],
    language: str,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    repository_root: Path,
    semgrep_binary: str,
    codeql_binary: str,
    semgrep_version: str,
    codeql_version: str,
    semgrep_rules: Sequence[Mapping[str, object]],
    codeql_queries: Sequence[str],
    codeql_query_sha256: Mapping[str, str],
    javascript_query_pack: Path | None,
    python_query_pack: Path | None,
    jobs: int,
    timeout_seconds: float,
    codeql_ram_mb: int,
    invoke_fn: InvokeCallable = invoke,
    tool_version_fn: ToolVersionCallable = tool_version,
) -> PipelineResult:
    """Run configured scanners while preserving independent partial failures."""
    steps: dict[str, ProcessRecord] = {}
    findings: list[Finding] = []
    codeql_query_files: dict[str, str] | None = None
    codeql_pack_manifest: str | None = None

    for tool in scanners:
        try:
            binary = semgrep_binary if tool == "semgrep" else codeql_binary
            expected_version = semgrep_version if tool == "semgrep" else codeql_version
            tool_version_fn(
                binary,
                expected_version,
                output,
                tool,
                steps,
                working_directory=repository_root,
                invoke_fn=invoke_fn,
            )

            if tool == "semgrep":
                record, tool_findings, _ = run_semgrep(
                    binary=binary,
                    source=source,
                    output=output,
                    snapshot_sha256=snapshot_sha256,
                    repository_root=repository_root,
                    rules=semgrep_rules,
                    jobs=jobs,
                    timeout_seconds=timeout_seconds,
                    invoke_fn=invoke_fn,
                )
                steps[tool] = record
                findings.extend(tool_findings)
                continue

            query_pack = query_pack_for_language(
                language,
                javascript_query_pack=javascript_query_pack,
                python_query_pack=python_query_pack,
            )
            result = run_codeql(
                binary=binary,
                language=language,
                source=source,
                output=output,
                snapshot_sha256=snapshot_sha256,
                query_pack=query_pack,
                queries=codeql_queries,
                expected_query_sha256=codeql_query_sha256,
                jobs=jobs,
                ram_mb=codeql_ram_mb,
                timeout_seconds=timeout_seconds,
                invoke_fn=invoke_fn,
            )
            steps["codeql-create"] = result.create_record
            steps[tool] = result.analyze_record
            findings.extend(result.findings)
            codeql_query_files = result.query_files
            codeql_pack_manifest = result.pack_manifest
        except (OSError, RuntimeError, ValueError) as exc:
            failure = steps.setdefault(tool, {})
            failure["status"] = "timeout" if failure.get("status") == "timeout" else "failed"
            failure["error"] = str(exc)

    return PipelineResult(
        status=_status(scanners, steps),
        steps=steps,
        findings=findings,
        codeql_query_files=codeql_query_files,
        codeql_pack_manifest=codeql_pack_manifest,
    )
