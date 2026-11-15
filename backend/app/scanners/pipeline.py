"""Scanner orchestration independent of CLI and worker frameworks."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.scanners.bandit import run_bandit
from app.scanners.codeql import query_pack_for_language, run_codeql, run_codeql_evidence
from app.scanners.eslint import run_eslint
from app.scanners.process import (
    InvokeCallable,
    ProcessRecord,
    ToolName,
    ToolVersionCallable,
    invoke,
    tool_version,
)
from app.scanners.sarif import Finding
from app.scanners.semgrep import (
    control_semgrep_targets,
    remove_source_ignore_files,
    run_semgrep,
    run_semgrep_evidence,
)

PipelineStatus = Literal["completed", "partial", "failed"]


@dataclass(frozen=True, slots=True)
class PipelineResult:
    status: PipelineStatus
    steps: dict[str, ProcessRecord]
    findings: list[Finding]
    codeql_query_files: dict[str, str] | None
    codeql_pack_manifest: str | None
    # Alerts of the adjudication step's evidence queries; never part of `findings`.
    evidence_findings: list[Finding] = field(default_factory=list)


def _status(scanners: Sequence[ToolName], steps: Mapping[str, ProcessRecord]) -> PipelineStatus:
    statuses = [steps[scanner]["status"] if scanner in steps else None for scanner in scanners]
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
    max_workers: int = 1,
    bandit: Mapping[str, Any] | None = None,
    eslint: Mapping[str, Any] | None = None,
    bandit_binary: str = "bandit",
    eslint_binary: str = "eslint",
    codeql_evidence: Mapping[str, Any] | None = None,
    semgrep_evidence: Mapping[str, Any] | None = None,
    semgrep_target_selection: str | None = None,
    invoke_fn: InvokeCallable = invoke,
    tool_version_fn: ToolVersionCallable = tool_version,
) -> PipelineResult:
    """Run configured scanners while preserving independent partial failures.

    `bandit` and `eslint` are the language config's entries for those screening tools:
    {version, config: {path, sha256}, rules: [...]}, plus lockfile for ESLint.
    `codeql_evidence` is {query_pack: Path, queries: [...], query_sha256: {...}}: evidence
    queries run on the scan's own CodeQL database after its analysis. Their failure is
    recorded as the step "codeql-evidence" and never changes the scan's status.
    `semgrep_evidence` is {rules: {path, sha256}}: a pinned file of evidence rules that
    Semgrep runs after its scan, recorded as the step "semgrep-evidence" the same way.
    `semgrep_target_selection` names the ignore file the worker writes into the extracted
    source before any tool runs (see `control_semgrep_targets`); None keeps Semgrep's default
    selection. In both cases an ignore file shipped inside the scanned source is removed.
    """
    if max_workers < 1:
        raise ValueError("Scanner workers must be positive")
    if semgrep_target_selection is not None:
        control_semgrep_targets(source, semgrep_target_selection)
    else:
        remove_source_ignore_files(source)

    def run_one(
        tool: ToolName, prior_steps: dict[str, ProcessRecord] | None = None
    ) -> PipelineResult:
        steps = prior_steps if prior_steps is not None else {}
        findings: list[Finding] = []
        evidence_findings: list[Finding] = []
        codeql_query_files: dict[str, str] | None = None
        codeql_pack_manifest: str | None = None

        try:
            screening = {"bandit": bandit, "eslint": eslint}.get(tool)
            if tool in {"bandit", "eslint"} and screening is None:
                raise ValueError(f"Configuration lists {tool} but does not configure it")
            binary = {
                "semgrep": semgrep_binary,
                "codeql": codeql_binary,
                "bandit": bandit_binary,
                "eslint": eslint_binary,
            }[tool]
            expected_version = (
                screening["version"]
                if screening is not None
                else semgrep_version
                if tool == "semgrep"
                else codeql_version
            )
            tool_version_fn(
                binary,
                expected_version,
                output,
                tool,
                steps,
                working_directory=repository_root,
                invoke_fn=invoke_fn,
            )

            if tool != "codeql":
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
                elif tool == "bandit":
                    assert screening is not None
                    record, tool_findings, _ = run_bandit(
                        binary=binary,
                        source=source,
                        output=output,
                        snapshot_sha256=snapshot_sha256,
                        repository_root=repository_root,
                        config=screening["config"],
                        tests=screening["rules"],
                        timeout_seconds=timeout_seconds,
                        invoke_fn=invoke_fn,
                    )
                else:
                    assert screening is not None
                    record, tool_findings, _ = run_eslint(
                        binary=binary,
                        source=source,
                        output=output,
                        snapshot_sha256=snapshot_sha256,
                        repository_root=repository_root,
                        config=screening["config"],
                        lockfile=screening["lockfile"],
                        rules=screening["rules"],
                        timeout_seconds=timeout_seconds,
                        invoke_fn=invoke_fn,
                    )
                steps[tool] = record
                findings.extend(tool_findings)
                if tool == "semgrep" and semgrep_evidence is not None:
                    try:
                        evidence_record, evidence_findings, _ = run_semgrep_evidence(
                            binary=binary,
                            source=source,
                            output=output,
                            snapshot_sha256=snapshot_sha256,
                            repository_root=repository_root,
                            rules=semgrep_evidence["rules"],
                            jobs=jobs,
                            timeout_seconds=timeout_seconds,
                            invoke_fn=invoke_fn,
                        )
                        steps["semgrep-evidence"] = evidence_record
                    except (KeyError, OSError, RuntimeError, ValueError) as exc:
                        steps["semgrep-evidence"] = {"status": "failed", "error": str(exc)}
                return PipelineResult(
                    status=_status([tool], steps),
                    steps=steps,
                    findings=findings,
                    codeql_query_files=None,
                    codeql_pack_manifest=None,
                    evidence_findings=evidence_findings,
                )

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
            if codeql_evidence is not None and result.analyze_record["status"] == "completed":
                try:
                    record, evidence_findings, _ = run_codeql_evidence(
                        binary=binary,
                        source=source,
                        output=output,
                        snapshot_sha256=snapshot_sha256,
                        query_pack=Path(codeql_evidence["query_pack"]),
                        queries=codeql_evidence["queries"],
                        expected_query_sha256=codeql_evidence["query_sha256"],
                        jobs=jobs,
                        ram_mb=codeql_ram_mb,
                        timeout_seconds=timeout_seconds,
                        invoke_fn=invoke_fn,
                    )
                    steps["codeql-evidence"] = record
                except (KeyError, OSError, RuntimeError, ValueError) as exc:
                    steps["codeql-evidence"] = {"status": "failed", "error": str(exc)}
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            failure = steps.setdefault(tool, {"status": "failed"})
            failure["status"] = "timeout" if failure.get("status") == "timeout" else "failed"
            failure["error"] = str(exc)

        return PipelineResult(
            status=_status([tool], steps),
            steps=steps,
            findings=findings,
            codeql_query_files=codeql_query_files,
            codeql_pack_manifest=codeql_pack_manifest,
            evidence_findings=evidence_findings,
        )

    def merge(outcomes: Iterable[PipelineResult]) -> PipelineResult:
        steps: dict[str, ProcessRecord] = {}
        findings: list[Finding] = []
        evidence_findings: list[Finding] = []
        codeql_query_files: dict[str, str] | None = None
        codeql_pack_manifest: str | None = None
        for outcome in outcomes:
            steps.update(outcome.steps)
            findings.extend(outcome.findings)
            evidence_findings.extend(outcome.evidence_findings)
            if outcome.codeql_query_files is not None:
                codeql_query_files = outcome.codeql_query_files
                codeql_pack_manifest = outcome.codeql_pack_manifest
        return PipelineResult(
            status=_status(scanners, steps),
            steps=steps,
            findings=findings,
            codeql_query_files=codeql_query_files,
            codeql_pack_manifest=codeql_pack_manifest,
            evidence_findings=evidence_findings,
        )

    # Duplicate tools share output paths and must retain their sequential retry behavior.
    if max_workers == 1 or len(scanners) < 2 or len(set(scanners)) != len(scanners):
        steps: dict[str, ProcessRecord] = {}
        return merge(run_one(tool, steps) for tool in scanners)
    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(scanners)), thread_name_prefix="scanner"
    ) as pool:
        # map preserves configured tool order even when completion order differs.
        return merge(pool.map(run_one, scanners))
