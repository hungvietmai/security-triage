"""Detect and keep: rank nothing, filter nothing, hold every alert for a reviewer.

A detection profile runs pinned queries of the standard CodeQL pack for an analysis family
that has no evaluated ranking policy and no evaluated filter condition yet. Each reported
location becomes one unit at the profile's fixed tier, in the review list. No rule of another
family applies, and nothing here can move a unit out of the review list.

An incomplete run keeps the alerts it did report and says that the run was incomplete. An
alert of a rule the profile does not pin is refused: its meaning is not known here.

A detection profile of schema 2 (`sql-injection-v0.2`) also runs Semgrep and Bandit with its
own pinned rules and merges alerts of several tools, but only where a located SQL execution
call contains every one of them (`sql_sites`); any other alert stays a unit of its own. Units
of such a profile are versioned `detection-units-v2`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from app.core.config import Settings
from app.scanners.acquisition import load_source_texts
from app.scanners.passes import STAGED_RULE_ID
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
from app.workflows.scans.classification import Claim, RuleClaim
from app.workflows.scans.results import LanguageResult
from app.workflows.scans.sql_sites import LOCATOR_VERSION as SQL_SITE_LOCATOR
from app.workflows.scans.sql_sites import SqlSite, locate_all, site_of

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

DETECTION_UNIT_VERSION_V2 = "detection-units-v2"
SITE_SINK_KIND = "sql-execution-call"
LOCATION_SINK_KIND = "reported-location"
_REASON_SITE = (
    "{tools} báo SQL injection tại lời gọi thực thi truy vấn này; các cảnh báo nằm trong cùng một "
    "lời gọi được gộp thành một mục."
)
_REASON_LOCATION = (
    "{tools} báo SQL injection tại vị trí này. Không xác định được một lời gọi thực thi truy vấn "
    "chứa trọn vùng được báo, nên cảnh báo không được gộp với cảnh báo khác."
)
_REASON_COMMON = (
    " Nhóm phân tích này chưa có chính sách xếp hạng và chưa có điều kiện gạn nào đã được đo, "
    "nên cảnh báo được giữ nguyên ở danh sách rà."
)
_INCOMPLETE_V2 = " Một lượt chạy công cụ của nhóm chưa hoàn tất: có thể còn cảnh báo chưa được báo."
_TOOL_NAMES = {"codeql": "CodeQL", "semgrep": "Semgrep", "bandit": "Bandit"}

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


def canonical_rule_id(finding: Finding, config: Mapping[str, Any]) -> str | None:
    """The pinned rule a finding comes from, or None when no pinned definition is known.

    A Semgrep rule ID carries the folder its file was staged in (`r<index>`, see
    `app.scanners.passes`), which names one pinned rule file of the language config; the ID
    after it must be that file's rule ID. Bandit tests and CodeQL queries report their pinned
    IDs as they are.
    """
    rule = finding.get("rule_id")
    if not isinstance(rule, str):
        return None
    if finding.get("tool") != "semgrep":
        return rule
    match = STAGED_RULE_ID.search(rule)
    if match is None:
        return None
    rules = config.get("semgrep_rules") or []
    index = int(match.group(1))
    if index >= len(rules) or rules[index].get("rule_id") != match.group(2):
        return None
    canonical = rules[index].get("canonical_rule_id")
    return canonical if isinstance(canonical, str) else None


def detection_claim(profile: DetectionProfile, language: str) -> Claim:
    """Claims of a schema-2 detection member: its pinned rules, Semgrep IDs canonicalized."""
    rules = profile.rules[language]
    config = profile.configs[language]
    basis = f"pinned_rule_id:{profile.profile_id}"

    def claim(finding: Mapping[str, Any]) -> RuleClaim | None:
        canonical = canonical_rule_id(finding, config)
        if canonical is None or canonical not in rules:
            return None
        return {"verified": True, "mapped_cwes": list(rules[canonical]), "basis": basis}

    return claim


def keep_detected_v2(
    findings: Sequence[Finding],
    *,
    snapshot_sha256: str,
    family: str,
    rules: Mapping[str, Sequence[str]],
    canonical_of: Callable[[Finding], str | None],
    sites: Sequence[SqlSite],
    priority: str,
    complete: bool,
    provenance: Mapping[str, str],
) -> tuple[list[ReconciledUnit], list[dict[str, Any]]]:
    """Units of several tools' alerts, every one kept for review at `priority`.

    Alerts whose reported region lies inside one located SQL execution call (the innermost one
    when calls nest) form one unit for that call. Every other alert forms a unit per reported
    location and tool: without a located call there is no evidence that two tools point to the
    same point of execution. A CodeQL unit keeps the identity a CodeQL-only detection unit has
    there. Nothing is ranked or filtered. `canonical_of` names the pinned rule of a finding;
    `rules` maps pinned rules to their mapped CWEs.
    """
    groups: dict[tuple[Any, ...], list[Finding]] = {}
    places: dict[tuple[Any, ...], tuple[SqlSite | None, Any]] = {}
    canonical: dict[str, str] = {}
    for finding in findings:
        rule = canonical_of(finding)
        if rule is None or rule not in rules:
            raise ValueError(f"Unexpected rule in a detection scan: {finding['rule_id']!r}")
        canonical[finding["raw_id"]] = rule
        region = finding["reported_region"]
        site = site_of(region, finding["reported_path"], sites)
        key: tuple[Any, ...]
        if site is not None:
            span = site["span"]
            corners = (span["startLine"], span["startColumn"], span["endLine"], span["endColumn"])
            key = ("site", site["path"], corners)
            places[key] = (site, span)
        else:
            reported_span = _region(region)
            location = (
                (
                    reported_span["startLine"],
                    reported_span["startColumn"],
                    reported_span["endLine"],
                    reported_span["endColumn"],
                )
                if reported_span
                else None
            )
            # Outside a located call there is no evidence that two tools mean the same point of
            # execution, so each tool keeps its own unit even at an identical region.
            key = ("location", finding["reported_path"], location, finding["tool"])
            places[key] = (None, reported_span)
        groups.setdefault(key, []).append(finding)

    kept = [NO_FILTER_CONDITION] if complete else [RUN_INCOMPLETE, NO_FILTER_CONDITION]
    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda k: (k[1] or "", k[2] or (), k[0], k[3:])):
        site, span = places[key]
        path = key[1]
        reported = groups[key]
        tools = sorted({str(finding["tool"]) for finding in reported})
        named = ", ".join(_TOOL_NAMES.get(tool, tool) for tool in tools)
        status: MappingStatus
        if site is not None:
            identity: dict[str, Any] = {
                "snapshot_sha256": snapshot_sha256,
                "path": path,
                "call": list(key[2]),
                "detection_family": family,
                "locator": SQL_SITE_LOCATOR,
            }
            status, basis = "mapped", "same_call_site"
            method: Literal["containment", "exact_span"] | None = "containment"
            reason = _REASON_SITE.format(tools=named)
        else:
            # A CodeQL unit keeps the identity a CodeQL-only unit has here (detection-units-v1).
            identity = {
                "snapshot_sha256": snapshot_sha256,
                "path": path,
                "span": list(key[2]) if key[2] else None,
                "detection_family": family,
            }
            if key[3] != "codeql":
                identity["tool"] = key[3]
            status, basis = "unmapped", "single_location"
            method = "exact_span" if span else None
            reason = _REASON_LOCATION.format(tools=named)
        reason += _REASON_COMMON + ("" if complete else _INCOMPLETE_V2)
        unit_id = _canonical_id(identity)
        mappings: list[UnitMapping] = [
            {
                "raw_id": finding["raw_id"],
                "tool": finding["tool"],
                "mapping_status": status,
                "mapping_method": method,
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
                "sink_kind": SITE_SINK_KIND if site is not None else LOCATION_SINK_KIND,
                "callee": site["callee"] if site is not None else None,
                "mapping_status": status,
                "raw_finding_ids": [finding["raw_id"] for finding in reported],
                "tools": tools,
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
                "tools": tools,
                "predicate_values": {
                    "detected": True,
                    "run_complete": complete,
                    "located_sql_call": site is not None,
                },
                "unknown_fields": ["priority_policy", "filter_condition"],
                "candidate": {
                    "key": unit_id,
                    "basis": basis,
                    "unit_ids": [unit_id],
                    "tools": tools,
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
                        "tool": finding["tool"],
                        "rule_id": finding["rule_id"],
                        "canonical_rule_id": canonical[finding["raw_id"]],
                        "query": "detection",
                        "mapped_cwes": list(rules[canonical[finding["raw_id"]]]),
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
    files: Sequence[str] = (),
) -> LanguageResult:
    """Run the profile's pinned rules and queries and keep every alert.

    `files` are the snapshot's files; a schema-2 profile reads its Python sources to locate
    SQL execution calls.
    """
    config = profile.configs[language]
    merging = profile.unit_merge == SQL_SITE_LOCATOR
    pack_version = config["codeql_bundle"][f"{language}_query_pack"]
    pack = settings.codeql_home / f"qlpacks/codeql/{language}-queries/{pack_version}"
    extra: dict[str, Any] = {"bandit": config.get("bandit")} if merging else {}
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
        **extra,
    )
    units: list[ReconciledUnit] = []
    assessments: list[dict[str, Any]] = []
    provenance = {
        "policy_id": profile.policy_id,
        "policy_version": profile.policy_version,
        "policy_sha256": profile.policy_sha256,
        "spec_sha256": profile.specification_sha256,
        # Rule claims belong to priority profiles; the mapped CWEs are in the manifest.
        "rule_claims_version": "not-applicable",
        "rule_claims_sha256": "",
    }
    sites: list[SqlSite] = []
    if merging and language == "python":
        sites, unparsed = locate_all(load_source_texts(source, files, language))
        locator: dict[str, Any] = {
            "status": "partial" if unparsed else "completed",
            "raw_findings": len(sites),
        }
        if unparsed:
            locator["error"] = (
                f"{len(unparsed)} Python file(s) could not be parsed; no call located there"
            )
        result.steps["sink-locator"] = locator  # type: ignore[assignment]
    # A failed run that still wrote results is left to the caller, which holds its alerts
    # as not ranked: what a failed analysis reported is not this profile's to describe.
    if merging and result.status != "failed":
        units, assessments = keep_detected_v2(
            result.findings,
            snapshot_sha256=snapshot_sha256,
            family=family,
            rules=profile.rules[language],
            canonical_of=lambda finding: canonical_rule_id(finding, config),
            sites=sites,
            priority=profile.priority,
            complete=result.status == "completed",
            provenance={**provenance, "reconciler_version": DETECTION_UNIT_VERSION_V2},
        )
    elif result.status != "failed":
        units, assessments = keep_detected(
            result.findings,
            snapshot_sha256=snapshot_sha256,
            family=family,
            rules=profile.rules[language],
            priority=profile.priority,
            complete=result.status == "completed",
            provenance={**provenance, "reconciler_version": DETECTION_UNIT_VERSION},
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
    versions = {"codeql": config["codeql_version"]}
    if merging and "semgrep" in config["scanners"]:
        versions["semgrep"] = config["semgrep_version"]
    if merging and "bandit" in config["scanners"]:
        versions["bandit"] = config["bandit"]["version"]
    return LanguageResult(
        language,
        result,
        versions,
        units,
        assessments,
        unit_version=DETECTION_UNIT_VERSION_V2 if merging else DETECTION_UNIT_VERSION,
        locator_version=(
            DETECTION_LOCATOR_VERSION
            if not merging
            else SQL_SITE_LOCATOR
            if language == "python"
            else LOCATION_SINK_KIND
        ),
    )
