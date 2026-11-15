"""Run pinned scanners and assess their findings for one source language."""

import dataclasses
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.scanners import bandit, eslint
from app.scanners.acquisition import load_source_texts
from app.scanners.pipeline import PipelineResult
from app.scanners.process import InvokeCallable, ProcessRecord
from app.scanners.profile import EvidenceProfile, ScanProfile
from app.scanners.provenance import digest
from app.scanners.semgrep import run_sink_locator
from app.triage.adjudicate import (
    adjudicate,
    codeql_evidence_index,
    constant_evidence_index,
    semgrep_evidence_index,
)
from app.triage.assess import assert_finding_conservation, assess_units, verified_definitions
from app.triage.policy import validate_policy
from app.triage.reconcile import RECONCILIATION_VERSION, ReconciledUnit, reconcile_findings
from app.triage.safety_evidence import (
    EVIDENCE_LOCATOR_VERSION,
    EVIDENCE_UNIT_VERSION,
    assess_with_evidence,
)
from app.triage.sinks_javascript import parse_javascript_sink_output
from app.triage.sinks_python import locate_python_sinks
from app.triage.types import SinkRecord
from app.workflows.scans.results import LanguageResult

RunPipeline = Callable[..., PipelineResult]
# Screening tools a language config may add, with the name of their staged configuration.
SCREENING_CONFIGS = {"bandit": bandit.STAGED_CONFIG, "eslint": eslint.STAGED_CONFIG}


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
        sinks: list[SinkRecord] = []
        unparsed = 0
        for path in sorted(sources):
            try:
                sinks.extend(locate_python_sinks(path, sources[path]))
            except (SyntaxError, ValueError, RecursionError):
                # Python 2 code or a deliberately broken file: the standard-library parser
                # rejects it, so no call is located there. Its alerts stay unmatched, and the
                # run counts as partial so that nothing is filtered on an incomplete picture.
                unparsed += 1
        if unparsed:
            return sinks, {
                "status": "partial",
                "raw_findings": len(sinks),
                "error": f"{unparsed} Python file(s) could not be parsed; no call located there",
            }
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


def _codeql_evidence(config: dict[str, Any], result: PipelineResult) -> dict[str, Any] | None:
    """What the adjudication step's evidence queries reported, for `adjudicate`."""
    spec = config.get("adjudication", {}).get("codeql_evidence")
    if spec is None:
        return None
    step = result.steps.get("codeql-evidence")
    return {
        "tool": "codeql-safety-evidence",
        "tool_version": f"CodeQL {config['codeql_version']}, evidence pack {spec['version']}",
        "status": step["status"] if step else "not_run",
        "baseline_rules": spec["baseline_rules"],
        "evidence_rule": spec["evidence_rule"],
        "query_sha256": spec["query_sha256"],
        "locations": codeql_evidence_index(
            [f for f in result.evidence_findings if f["tool"] == "codeql-evidence"],
            baseline_rule=spec["control_rule"],
            evidence_rule=spec["evidence_rule"],
        ),
    }


def _semgrep_evidence(config: dict[str, Any], result: PipelineResult) -> dict[str, Any] | None:
    """What Semgrep's dead-branch evidence rules reported, for `adjudicate`."""
    spec = config.get("adjudication", {}).get("semgrep_evidence")
    if spec is None or "baseline_rule" not in spec:
        return None
    step = result.steps.get("semgrep-evidence")
    found = [f for f in result.evidence_findings if f["tool"] == "semgrep-evidence"]
    return {
        "tool": "semgrep",
        "tool_version": f"Semgrep CE {config['semgrep_version']}, evidence rules {spec['version']}",
        "status": step["status"] if step else "not_run",
        "baseline_rule": spec["baseline_rule"],
        "evidence_rule": spec["evidence_rule"],
        "dead_code_rule": spec["dead_code_rule"],
        "rules_sha256": spec["rules"]["sha256"],
        "locations": semgrep_evidence_index(
            found,
            baseline_rule=spec["baseline_rule"],
            evidence_rule=spec["evidence_rule"],
            dead_code_rule=spec["dead_code_rule"],
        ),
    }


def _constant_evidence(config: dict[str, Any], result: PipelineResult) -> dict[str, Any] | None:
    """What Semgrep's constant-command evidence rule reported, for `adjudicate`."""
    spec = config.get("adjudication", {}).get("semgrep_evidence")
    if spec is None or "constant_rule" not in spec:
        return None
    step = result.steps.get("semgrep-evidence")
    found = [f for f in result.evidence_findings if f["tool"] == "semgrep-evidence"]
    return {
        "tool": "semgrep",
        "tool_version": f"Semgrep CE {config['semgrep_version']}, evidence rules {spec['version']}",
        "status": step["status"] if step else "not_run",
        "evidence_rule": spec["constant_rule"],
        "rules_sha256": spec["rules"]["sha256"],
        "locations": constant_evidence_index(found, rule=spec["constant_rule"]),
    }


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
    screening = [
        {
            "tool": tool,
            "version": config[tool]["version"],
            "rules": config[tool]["rules"],
            "expected_sha256": config[tool]["config"]["sha256"],
            "observed_sha256": digest(output / name) if (output / name).is_file() else None,
        }
        for tool, name in SCREENING_CONFIGS.items()
        if tool in config
    ]
    definitions = verified_definitions(
        language=language,
        semgrep_version=config["semgrep_version"],
        codeql_version=config["codeql_version"],
        semgrep_rules=config["semgrep_rules"],
        staged_rules=staged,
        expected_query_sha256=config["codeql_query_sha256"],
        observed_query_sha256=result.codeql_query_files,
        query_pack_version=pack_version,
        screening=screening,
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
    # Group units of one call into a candidate, then filter only on specific evidence.
    assessments = adjudicate(
        units,
        assessments,
        result.findings,
        complete=result.status == "completed" and locator["status"] == "completed",
        codeql_evidence=_codeql_evidence(config, result),
        semgrep_evidence=_semgrep_evidence(config, result),
        constant_evidence=_constant_evidence(config, result),
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
    evidence = config.get("adjudication", {}).get("codeql_evidence")
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
        bandit=config.get("bandit"),
        eslint=config.get("eslint"),
        codeql_evidence=(
            {
                "query_pack": profile.root / evidence["query_pack"],
                "queries": evidence["queries"],
                "query_sha256": evidence["query_sha256"],
            }
            if evidence is not None
            else None
        ),
        semgrep_evidence=config.get("adjudication", {}).get("semgrep_evidence"),
        semgrep_target_selection=config.get("semgrep_target_selection"),
        invoke_fn=invoke_fn,
    )
    versions = {"semgrep": config["semgrep_version"], "codeql": config["codeql_version"]}
    versions.update({tool: config[tool]["version"] for tool in SCREENING_CONFIGS if tool in config})
    if evidence is not None:
        versions["codeql-evidence"] = config["codeql_version"]
    if config.get("adjudication", {}).get("semgrep_evidence") is not None:
        versions["semgrep-evidence"] = config["semgrep_version"]
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
        if result.status == "completed" and result.steps["sink-locator"]["status"] != "completed":
            result = dataclasses.replace(result, status="partial")
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


def scan_language_evidence(
    language: str,
    *,
    profile: EvidenceProfile,
    settings: Settings,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    run_pipeline_fn: RunPipeline,
    invoke_fn: InvokeCallable,
) -> LanguageResult:
    """Run the baseline and evidence queries from the profile's pack, then rank the baseline."""
    config = profile.configs[language]
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
        javascript_query_pack=profile.query_pack if language == "javascript" else None,
        python_query_pack=profile.query_pack if language == "python" else None,
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
        codeql_ram_mb=2048,
        max_workers=settings.scanner_workers,
        invoke_fn=invoke_fn,
    )
    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    # Ranking needs both queries' results; a partial run could show a kept alert as hidden.
    if result.status == "completed":
        units, assessments = assess_with_evidence(
            result.findings,
            snapshot_sha256=snapshot_sha256,
            baseline_rule=profile.baseline_rule,
            evidence_rule=profile.evidence_rule,
            provenance={
                "policy_id": profile.policy_id,
                "policy_version": profile.policy_version,
                "policy_sha256": profile.policy_sha256,
                "spec_sha256": profile.specification_sha256,
                # Rule claims belong to priority profiles; evidence profiles have none.
                "rule_claims_version": "not-applicable",
                "rule_claims_sha256": "",
                "reconciler_version": EVIDENCE_UNIT_VERSION,
            },
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
    return LanguageResult(
        language,
        result,
        {"codeql": config["codeql_version"]},
        units,
        assessments,
        unit_version=EVIDENCE_UNIT_VERSION,
        locator_version=EVIDENCE_LOCATOR_VERSION,
    )
