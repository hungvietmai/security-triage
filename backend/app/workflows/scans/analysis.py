"""Run pinned scanners and assess their findings for one source language."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.scanners.acquisition import load_source_texts
from app.scanners.pipeline import PipelineResult
from app.scanners.process import InvokeCallable, ProcessRecord
from app.scanners.profile import ScanProfile
from app.scanners.provenance import digest
from app.scanners.semgrep import run_sink_locator
from app.triage.assess import assert_finding_conservation, assess_units, verified_definitions
from app.triage.policy import validate_policy
from app.triage.reconcile import RECONCILIATION_VERSION, ReconciledUnit, reconcile_findings
from app.triage.sinks_javascript import parse_javascript_sink_output
from app.triage.sinks_python import locate_python_sinks
from app.triage.types import SinkRecord
from app.workflows.scans.results import LanguageResult

RunPipeline = Callable[..., PipelineResult]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _locate_sinks(
    language: str,
    profile: ScanProfile,
    source: Path,
    output: Path,
    sources: dict[str, str],
    config: dict[str, Any],
    invoke_fn: InvokeCallable,
) -> tuple[list[SinkRecord], ProcessRecord]:
    if language == "python":
        sinks = [
            sink for path in sorted(sources) for sink in locate_python_sinks(path, sources[path])
        ]
        return sinks, {"status": "completed", "raw_findings": len(sinks)}
    record, text = run_sink_locator(
        binary="semgrep",
        source=source,
        output=output,
        rule=profile.sink_locators[language],
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
        invoke_fn=invoke_fn,
    )
    sinks = parse_javascript_sink_output(text, sources)
    return sinks, {**record, "raw_findings": len(sinks)}


def _assess_pipeline(
    result: PipelineResult,
    language: str,
    *,
    profile: ScanProfile,
    source: Path,
    files: list[str],
    output: Path,
    invoke_fn: InvokeCallable,
) -> tuple[list[ReconciledUnit], list[dict[str, Any]]]:
    config = profile.configs[language]
    pack_version = config["codeql_bundle"][f"{language}_query_pack"]
    sources = load_source_texts(source, files, language)
    sinks, locator = _locate_sinks(language, profile, source, output, sources, config, invoke_fn)
    result.steps["sink-locator"] = locator
    units = reconcile_findings(result.findings, sinks, sources)
    assert_finding_conservation(result.findings, units)
    staged: list[tuple[str | None, object]] = []
    for index, rule in enumerate(config["semgrep_rules"]):
        path = output / f"rule-{index}.yaml"
        rule_id = profile.semgrep_rule_ids[rule["path"]]
        staged.append((digest(path) if path.is_file() else None, {"rules": [{"id": rule_id}]}))
    definitions = verified_definitions(
        language=language,
        semgrep_version=config["semgrep_version"],
        codeql_version=config["codeql_version"],
        semgrep_rules=config["semgrep_rules"],
        staged_rules=staged,
        expected_query_sha256=config["codeql_query_sha256"],
        observed_query_sha256=result.codeql_query_files,
        query_pack_version=pack_version,
    )
    assessments = assess_units(
        units,
        result.findings,
        sinks,
        sources,
        mapping=profile.rule_claims,
        definitions=definitions,
        policy=validate_policy(profile.policy),
        provenance={
            "policy_sha256": profile.policy_sha256,
            "spec_sha256": profile.specification_sha256,
            "rule_claims_version": profile.rule_claims["version"],
            "rule_claims_sha256": profile.rule_claims_sha256,
            "reconciler_version": RECONCILIATION_VERSION,
        },
    )
    return units, assessments


def scan_language(
    language: str,
    *,
    profile: ScanProfile,
    settings: Settings,
    source: Path,
    files: list[str],
    output: Path,
    snapshot_sha256: str,
    run_pipeline_fn: RunPipeline,
    invoke_fn: InvokeCallable,
) -> LanguageResult:
    """Preserve scanner output and assess only runs with usable results."""
    config = profile.configs[language]
    pack_version = config["codeql_bundle"][f"{language}_query_pack"]
    pack = settings.codeql_home / f"qlpacks/codeql/{language}-queries/{pack_version}"
    result = run_pipeline_fn(
        scanners=config["scanners"],
        language=language,
        source=source,
        output=output,
        snapshot_sha256=snapshot_sha256,
        repository_root=profile.root,
        semgrep_binary="semgrep",
        codeql_binary="codeql",
        semgrep_version=config["semgrep_version"],
        codeql_version=config["codeql_version"],
        semgrep_rules=config["semgrep_rules"],
        codeql_queries=config["codeql_queries"],
        codeql_query_sha256=config["codeql_query_sha256"],
        javascript_query_pack=pack if language == "javascript" else None,
        python_query_pack=pack if language == "python" else None,
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
        codeql_ram_mb=2048,
        max_workers=settings.scanner_workers,
        invoke_fn=invoke_fn,
    )
    versions = {"semgrep": config["semgrep_version"], "codeql": config["codeql_version"]}
    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    if result.status != "failed":
        units, assessments = _assess_pipeline(
            result,
            language,
            profile=profile,
            source=source,
            files=files,
            output=output,
            invoke_fn=invoke_fn,
        )
    _write_json(
        output / "run.json",
        {
            "language": language,
            "status": result.status,
            "steps": result.steps,
            "snapshot_sha256": snapshot_sha256,
            "profile_id": profile.profile_id,
            "profile_sha256": profile.manifest_sha256,
            "scanner_workers": settings.scanner_workers,
            "codeql_query_files": result.codeql_query_files,
            "raw_findings": len(result.findings),
            "unit_count": len(units),
        },
    )
    _write_json(output / "findings.json", result.findings)
    _write_json(output / "units.json", units)
    _write_json(output / "assessments.json", assessments)
    return LanguageResult(language, result, versions, units, assessments)
