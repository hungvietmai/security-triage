"""Detect and keep: rank nothing, filter nothing, hold every alert for a reviewer.

A detection profile runs pinned queries of the standard CodeQL pack for an analysis family
that has no evaluated ranking policy and no evaluated filter condition yet. Each reported
location becomes one unit at the profile's fixed tier, in the review list. No rule of another
family applies, and nothing here can move a unit out of the review list.

An incomplete run keeps the alerts it did report and says that the run was incomplete. An
alert of a rule the profile does not pin is refused: its meaning is not known here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.scanners.process import InvokeCallable
from app.scanners.profile import DetectionProfile
from app.triage.adjudicate import ADJUDICATION_VERSION, REVIEW, RUN_INCOMPLETE
from app.triage.reconcile import (
    MappingStatus,
    ReconciledUnit,
    UnitMapping,
    _canonical_id,
    _region,
)
from app.workflows.scans.analysis import RunPipeline
from app.workflows.scans.results import LanguageResult

DETECTION_UNIT_VERSION = "detection-units-v1"
DETECTION_LOCATOR_VERSION = "codeql-reported-location"
KEPT_DECISION = "K10_DETECTED_KEPT"
# Why a unit of such a family stays in the review list: nothing may filter it yet.
NO_FILTER_CONDITION = "no_filter_condition_for_family"
SINK_KIND = "codeql-reported-sink"
_REASON = (
    "CodeQL báo luồng dữ liệu tới vị trí này. Nhóm phân tích này chưa có chính sách xếp hạng và "
    "chưa có điều kiện gạn nào đã được đo, nên cảnh báo được giữ nguyên ở danh sách rà."
)
_INCOMPLETE = " Lượt chạy truy vấn chưa hoàn tất: có thể còn cảnh báo chưa được báo."

Finding = Mapping[str, Any]
Location = tuple[str | None, tuple[int, int, int, int] | None]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def keep_detected(
    findings: Sequence[Finding],
    *,
    snapshot_sha256: str,
    family: str,
    rules: Mapping[str, Sequence[str]],
    priority: str,
    complete: bool,
    provenance: Mapping[str, str],
) -> tuple[list[ReconciledUnit], list[dict[str, Any]]]:
    """One unit per reported location, every one kept for review at `priority`.

    `rules` maps each pinned rule ID to its mapped CWEs. `complete` is False when the run that
    produced the findings was partial; the units then say so.
    """
    located: dict[Location, list[Finding]] = {}
    spans: dict[Location, Any] = {}
    for finding in findings:
        if finding["rule_id"] not in rules:
            raise ValueError(f"Unexpected rule in a detection scan: {finding['rule_id']!r}")
        span = _region(finding["reported_region"])
        corners = (
            (span["startLine"], span["startColumn"], span["endLine"], span["endColumn"])
            if span
            else None
        )
        location: Location = (finding["reported_path"], corners)
        located.setdefault(location, []).append(finding)
        spans[location] = span

    kept = [NO_FILTER_CONDITION] if complete else [RUN_INCOMPLETE, NO_FILTER_CONDITION]
    reason = _REASON if complete else _REASON + _INCOMPLETE
    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    for location in sorted(located, key=lambda key: (key[0] or "", key[1] or ())):
        path, corners = location
        span = spans[location]
        reported = located[location]
        status: MappingStatus = "mapped" if span else "unmapped"
        # The family is part of the identity: another family may report the same place.
        unit_id = _canonical_id(
            {
                "snapshot_sha256": snapshot_sha256,
                "path": path,
                "span": list(corners) if corners else None,
                "detection_family": family,
            }
        )
        mappings: list[UnitMapping] = [
            {
                "raw_id": finding["raw_id"],
                "tool": finding["tool"],
                "mapping_status": status,
                "mapping_method": "exact_span" if span else None,
            }
            for finding in reported
        ]
        units.append(
            {
                "unit_id": unit_id,
                "snapshot_sha256": snapshot_sha256,
                "path": path,
                "sink_span": span,
                "reported_region": dict(reported[0]["reported_region"].items()),
                "argument_role": None,
                "sink_kind": SINK_KIND,
                "callee": None,
                "mapping_status": status,
                "raw_finding_ids": [finding["raw_id"] for finding in reported],
                "tools": ["codeql"],
                "mappings": mappings,
            }
        )
        assessments.append(
            {
                "unit_id": unit_id,
                "priority": priority,
                "decision_id": KEPT_DECISION,
                "matched_conditions": ["detected", *kept],
                "reason": reason,
                "tools": ["codeql"],
                "predicate_values": {"detected": True, "run_complete": complete},
                "unknown_fields": ["priority_policy", "filter_condition"],
                "candidate": {
                    "key": unit_id,
                    "basis": "single_location",
                    "unit_ids": [unit_id],
                    "tools": ["codeql"],
                    "priority": priority,
                },
                "disposition": REVIEW,
                "adjudication": {
                    "version": ADJUDICATION_VERSION,
                    "status": "kept",
                    "rule": None,
                    "rules": [],
                    "kept_because": kept,
                    "reason": reason,
                    "evidence": [],
                },
                "finding_evidence": [
                    {
                        "raw_id": finding["raw_id"],
                        "rule_id": finding["rule_id"],
                        "query": "detection",
                        "mapped_cwes": list(rules[finding["rule_id"]]),
                        "reported_cwes": list(finding["reported_cwes"]),
                        "message": finding["message"],
                    }
                    for finding in reported
                ],
                **provenance,
            }
        )
    return units, assessments


def scan_language_detection(
    language: str,
    *,
    profile: DetectionProfile,
    family: str,
    settings: Settings,
    source: Path,
    output: Path,
    snapshot_sha256: str,
    run_pipeline_fn: RunPipeline,
    invoke_fn: InvokeCallable,
) -> LanguageResult:
    """Run the profile's pinned queries of the standard pack and keep every alert."""
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
    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    # A failed run that still wrote results is left to the caller, which holds its alerts
    # as not ranked: what a failed analysis reported is not this profile's to describe.
    if result.status != "failed":
        units, assessments = keep_detected(
            result.findings,
            snapshot_sha256=snapshot_sha256,
            family=family,
            rules=profile.rules[language],
            priority=profile.priority,
            complete=result.status == "completed",
            provenance={
                "policy_id": profile.policy_id,
                "policy_version": profile.policy_version,
                "policy_sha256": profile.policy_sha256,
                "spec_sha256": profile.specification_sha256,
                # Rule claims belong to priority profiles; the mapped CWEs are in the manifest.
                "rule_claims_version": "not-applicable",
                "rule_claims_sha256": "",
                "reconciler_version": DETECTION_UNIT_VERSION,
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
        unit_version=DETECTION_UNIT_VERSION,
        locator_version=DETECTION_LOCATOR_VERSION,
    )
