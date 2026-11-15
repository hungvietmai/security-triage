"""Composite scan of one language: several analysis families on one tool run.

A composite scan is built from existing pinned profiles ("members"), one per analysis family.
The scanners run once and one CodeQL database is created. Each member's own entry point
(`scan_language` or `scan_language_evidence`) then assesses the findings routed to its family,
with its own pinned rules, policy and filter conditions. Nothing here ranks or filters: the
composition only provides each member with the tool results it would have produced alone.

The rule this module keeps: for the same snapshot and pinned tools, a family's units and
assessments equal what scanning with that member's profile alone produces. The one intended
difference is the raw-ID prefix of a pass that shares the database (see `PASS_PREFIX`).

Routing happens before any merging, so an alert of one family can never be merged into a
unit of another. A finding whose family cannot be named stays "unassigned": its own unit,
priority U, always in the review list, with every label kept.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.core.config import Settings
from app.scanners.codeql import query_pack_for_language, run_codeql_evidence
from app.scanners.pipeline import PipelineResult, PipelineStatus, run_pipeline
from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.profile import AnyProfile, EvidenceProfile, ScanProfile
from app.scanners.sarif import Finding
from app.triage.reconcile import RECONCILIATION_VERSION, ReconciledUnit, reconcile_findings
from app.workflows.scans.analysis import RunPipeline, scan_language, scan_language_evidence
from app.workflows.scans.classification import (
    Claim,
    Classification,
    classify_findings,
    pinned_rules_claim,
    rule_claims_claim,
)
from app.workflows.scans.results import LanguageResult

COMPOSITION_VERSION = "family-composition-v0.1"
UNASSIGNED = "unassigned"
UNRESOLVED_DECISION = "F00_FAMILY_UNRESOLVED"
# The analysis family each pinned profile handles. A profile that is not listed cannot be a
# member: its family, and with it the conditions under which it may filter, is unknown.
FAMILY_OF_PROFILE = {
    "command-injection-v0.1": "command-injection",
    "command-injection-v0.2": "command-injection",
    "command-injection-v0.3": "command-injection",
    "path-traversal-v0.2": "path-traversal",
}
# A member whose queries run on the shared database gets its own analysis pass. Its raw IDs
# start with this prefix and the family, so they stay unique next to the primary CodeQL pass.
PASS_PREFIX = "codeql-"
# Files a member's entry point writes; a composite scan keeps them per family.
MEMBER_FILES = ("run.json", "findings.json", "units.json", "assessments.json")
# What each step of the primary pipeline is, for the cost record.
STEP_KINDS = {
    "semgrep": "detection",
    "bandit": "detection",
    "eslint": "detection",
    "codeql-create": "shared",
    "codeql": "detection",
    "semgrep-evidence": "evidence",
    "codeql-evidence": "evidence",
    "sink-locator": "locator",
}
# Steps of the primary pipeline that every member using CodeQL depends on.
SHARED_STEPS = ("codeql-version", "codeql-create")
FamilyStatus = Literal["completed", "partial", "failed"]
# A member's failure is final for that family only; scanner and profile errors are these.
MEMBER_ERRORS = (KeyError, OSError, RuntimeError, ValueError)
AnalyzePass = Callable[..., tuple[ProcessRecord, list[Finding], bool]]

_UNRESOLVED_REASONS = {
    "rule_not_claimed": "không thành viên nào của lượt quét khai rule này",
    "definition_unverified": "rule được khai nhưng không xác định được một định nghĩa đã ghim",
    "ambiguous_family": "nhiều hơn một nhóm phân tích khai rule này",
}


@dataclass(frozen=True, slots=True)
class Member:
    family: str
    profile: AnyProfile


@dataclass(frozen=True, slots=True)
class FamilyResult:
    family: str
    profile_id: str | None
    status: FamilyStatus
    error: str | None
    # None when the member's entry point raised; its routed findings are still on record.
    result: LanguageResult | None
    raw_finding_ids: list[str]

    @property
    def units(self) -> list[ReconciledUnit]:
        return self.result.units if self.result is not None else []

    @property
    def assessments(self) -> list[dict[str, Any]]:
        return self.result.assessments if self.result is not None else []


@dataclass(frozen=True, slots=True)
class CompositeResult:
    language: str
    status: PipelineStatus
    # Every step of the language run with its kind and the families it serves.
    steps: dict[str, dict[str, Any]]
    # Every detection finding of every pass; evidence-only results are never in here.
    findings: list[Finding]
    classification: list[Classification]
    families: list[FamilyResult]
    unassigned_units: list[ReconciledUnit]
    unassigned_assessments: list[dict[str, Any]]
    conservation: dict[str, Any]


def compose(profiles: Sequence[AnyProfile]) -> list[Member]:
    """The members of a composite scan, one per family, the primary member first.

    Exactly one member runs the screening tools and creates the CodeQL database (a priority
    profile); every other member is a safety-evidence profile whose pack is analyzed on that
    database.
    """
    members = []
    for profile in profiles:
        family = FAMILY_OF_PROFILE.get(profile.profile_id)
        if family is None:
            raise ValueError(f"Profile has no analysis family: {profile.profile_id}")
        members.append(Member(family, profile))
    families = [member.family for member in members]
    if len(set(families)) != len(families):
        raise ValueError("A composite scan takes one member per analysis family")
    primary = [member for member in members if isinstance(member.profile, ScanProfile)]
    if len(primary) != 1:
        raise ValueError("A composite scan needs exactly one member that runs the scanners")
    return primary + [member for member in members if member is not primary[0]]


def pass_name(member: Member) -> str:
    return PASS_PREFIX + member.family


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _overall(statuses: Sequence[str]) -> PipelineStatus:
    if statuses and all(status == "completed" for status in statuses):
        return "completed"
    return "partial" if any(s in {"completed", "partial"} for s in statuses) else "failed"


def _participating(members: Sequence[Member], language: str) -> list[Member]:
    """Members with a configuration for the language, checked to fit one tool run."""
    primary = members[0]
    if not isinstance(primary.profile, ScanProfile) or language not in primary.profile.configs:
        raise ValueError(f"The primary member has no {language} configuration")
    taking_part = [member for member in members if language in member.profile.configs]
    config = primary.profile.configs[language]
    for member in taking_part[1:]:
        if "codeql" not in config["scanners"]:
            raise ValueError("The primary member creates no CodeQL database to share")
        version = member.profile.configs[language]["codeql_version"]
        if version != config["codeql_version"]:
            raise ValueError(
                f"Members pin different CodeQL versions: {config['codeql_version']} and {version}"
            )
    return taking_part


def _claim(member: Member, language: str) -> Claim:
    profile = member.profile
    if isinstance(profile, ScanProfile):
        return rule_claims_claim(profile.rule_claims, language)
    rules = {}
    for rule in (profile.baseline_rule, profile.evidence_rule):
        # The pack's query IDs name their CWE ("st/cwe-22/none"); the manifest pins the IDs.
        match = re.fullmatch(r"st/cwe-(\d+)/[\w-]+", rule)
        rules[rule] = [f"CWE-{int(match.group(1))}"] if match else []
    return pinned_rules_claim(rules, basis=f"pinned_query_id:{profile.profile_id}")


def _unassigned(
    findings: Sequence[Finding], records: Mapping[str, Classification]
) -> tuple[list[ReconciledUnit], list[dict[str, Any]]]:
    """One unit per reported location for findings no family could be named for."""
    if not findings:
        return [], []
    # No sink is offered, so nothing is merged into a call: each location stands alone.
    units = reconcile_findings(findings, [], {})
    tools = {finding["raw_id"]: finding["tool"] for finding in findings}
    assessments = []
    for unit in units:
        evidence = [records[raw_id] for raw_id in unit["raw_finding_ids"]]
        reasons = sorted({str(record["unresolved_reason"]) for record in evidence})
        reason = "Chưa xác định được nhóm phân tích: " + "; ".join(
            _UNRESOLVED_REASONS[code] for code in reasons
        )
        reason += ". Cảnh báo được giữ nguyên nhãn, ở mức U, và không quy tắc gạn nào được áp dụng."
        unit_tools = sorted({tools[raw_id] for raw_id in unit["raw_finding_ids"]})
        assessments.append(
            {
                "unit_id": unit["unit_id"],
                "analysis_family": None,
                "priority": "U",
                "decision_id": UNRESOLVED_DECISION,
                "matched_conditions": ["family_unresolved", *reasons],
                "reason": reason,
                "tools": unit_tools,
                "predicate_values": {"family_unresolved": True},
                "unknown_fields": ["analysis_family"],
                "finding_evidence": evidence,
                "candidate": {
                    "key": unit["unit_id"],
                    "basis": "unmatched_location",
                    "unit_ids": [unit["unit_id"]],
                    "tools": unit_tools,
                    "priority": "U",
                },
                "disposition": "review",
                "adjudication": {
                    "version": COMPOSITION_VERSION,
                    "status": "kept",
                    "rule": None,
                    "rules": [],
                    "kept_because": reasons,
                    "reason": reason,
                    "evidence": [],
                },
                "policy_id": "family-routing",
                "policy_version": COMPOSITION_VERSION,
                "policy_sha256": "",
                "spec_sha256": "",
                "rule_claims_version": "not-applicable",
                "rule_claims_sha256": "",
                "reconciler_version": RECONCILIATION_VERSION,
            }
        )
    return units, assessments


def check_conservation(
    findings: Sequence[Mapping[str, Any]],
    classification: Sequence[Classification],
    families: Sequence[FamilyResult],
    unassigned_units: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Every finding is classified once and sits in one unit of its own family, or is unranked.

    "Unranked" is a family that produced no unit at all for its findings (its run was
    incomplete or its member failed); the findings stay on record. A family that ranked some
    of its findings but not others, or a unit holding another family's finding, is an error.
    """
    raw_ids = [str(finding["raw_id"]) for finding in findings]
    if len(set(raw_ids)) != len(raw_ids):
        duplicated = sorted(raw_id for raw_id, count in Counter(raw_ids).items() if count > 1)
        raise RuntimeError(f"Composite scan produced duplicate raw IDs: {duplicated}")
    if [record["raw_id"] for record in classification] != raw_ids:
        raise RuntimeError("Composite scan did not classify every finding exactly once")
    routed: dict[str | None, list[str]] = {}
    for record in classification:
        routed.setdefault(record["analysis_family"], []).append(record["raw_id"])

    def account(name: str, mine: Sequence[str], units: Sequence[Mapping[str, Any]]) -> Any:
        in_units = Counter(str(raw_id) for unit in units for raw_id in unit["raw_finding_ids"])
        if in_units and in_units != Counter(mine):
            missing = sorted((Counter(mine) - in_units).elements())
            foreign = sorted((in_units - Counter(mine)).elements())
            raise RuntimeError(
                f"Composite conservation failed for {name}: missing={missing}, foreign={foreign}"
            )
        return {
            "routed": len(mine),
            "in_units": sum(in_units.values()),
            "unranked": 0 if in_units else len(mine),
            "units": len(units),
        }

    known = {family.family for family in families}
    stray = sorted(str(family) for family in routed if family is not None and family not in known)
    if stray:
        raise RuntimeError(f"Findings were routed to families without a member: {stray}")
    return {
        "raw_findings": len(raw_ids),
        "families": {
            family.family: account(family.family, routed.get(family.family, []), family.units)
            for family in families
        },
        UNASSIGNED: account(UNASSIGNED, routed.get(None, []), unassigned_units),
    }


def scan_language_families(
    language: str,
    *,
    members: Sequence[Member],
    settings: Settings,
    source: Path,
    files: list[str],
    output: Path,
    snapshot_sha256: str,
    run_pipeline_fn: RunPipeline = run_pipeline,
    invoke_fn: InvokeCallable = invoke,
    analyze_fn: AnalyzePass = run_codeql_evidence,
    pass_members: Mapping[str, Sequence[str]] | None = None,
) -> CompositeResult:
    """Run the scanners once for `language` and let every member assess its family's findings.

    `members` comes from `compose`. `output` receives the tools' files, the CodeQL database,
    the combined `findings.json`, `classification.json` and `run.json`, and one folder per
    family under `families/` with that member's own files. `pass_members` overrides which
    families a tool pass serves; by default every pass serves the member that configured it.
    """
    taking_part = _participating(members, language)
    primary, others = taking_part[0], taking_part[1:]
    assert isinstance(primary.profile, ScanProfile)
    config = primary.profile.configs[language]
    serves: dict[str, Sequence[str]] = {tool: [primary.family] for tool in config["scanners"]}
    serves.update({pass_name(member): [member.family] for member in others})
    serves.update(pass_members or {})
    claims = {member.family: _claim(member, language) for member in taking_part}

    findings: list[Finding] = []
    records: list[Classification] = []
    steps: dict[str, dict[str, Any]] = {}
    # The primary pipeline's own steps object, once it has run.
    primary_steps: list[dict[str, ProcessRecord]] = []

    def classify(found: Sequence[Finding], passes: Mapping[str, str]) -> None:
        findings.extend(found)
        records.extend(classify_findings(found, pass_of=passes, pass_members=serves, claims=claims))

    def routed_to(family: str) -> list[Finding]:
        mine = {record["raw_id"] for record in records if record["analysis_family"] == family}
        return [finding for finding in findings if finding["raw_id"] in mine]

    def primary_pipeline(**kwargs: Any) -> PipelineResult:
        """The real tool run; the member sees only the findings routed to its family."""
        result = run_pipeline_fn(**kwargs)
        classify(result.findings, {f["raw_id"]: f["tool"] for f in result.findings})
        # The same steps object: the member later records its sink locator on it.
        primary_steps.append(result.steps)
        return dataclasses.replace(result, findings=routed_to(primary.family))

    def shared_database_pipeline(member: Member) -> RunPipeline:
        """Serve a safety-evidence member's queries from the database the primary created."""

        def run(**kwargs: Any) -> PipelineResult:
            name = pass_name(member)
            shared = primary_steps[0] if primary_steps else {}
            member_steps: dict[str, ProcessRecord] = {
                step: shared[step] for step in SHARED_STEPS if step in shared
            }
            found: list[Finding] = []
            manifest: str | None = None
            try:
                pack = query_pack_for_language(
                    language,
                    javascript_query_pack=kwargs["javascript_query_pack"],
                    python_query_pack=kwargs["python_query_pack"],
                )
                record, found, _ = analyze_fn(
                    binary=kwargs["codeql_binary"],
                    source=source,
                    output=output,
                    snapshot_sha256=snapshot_sha256,
                    query_pack=pack,
                    queries=kwargs["codeql_queries"],
                    expected_query_sha256=kwargs["codeql_query_sha256"],
                    jobs=kwargs["jobs"],
                    ram_mb=kwargs["codeql_ram_mb"],
                    timeout_seconds=kwargs["timeout_seconds"],
                    invoke_fn=kwargs["invoke_fn"],
                    name=name,
                )
                manifest = (pack / "qlpack.yml").read_text(encoding="utf-8")
            except MEMBER_ERRORS as exc:
                record = {"status": "failed", "error": str(exc)}
            for finding in found:
                # The pass name stays in the raw ID; the tool is CodeQL, as when run alone.
                finding["tool"] = "codeql"
            steps[name] = {**record, "kind": "detection+evidence", "serves": [member.family]}
            classify(found, {finding["raw_id"]: name for finding in found})
            member_steps["codeql"] = record
            status = record["status"]
            return PipelineResult(
                status=status if status in {"completed", "partial"} else "failed",  # type: ignore[arg-type]
                steps=member_steps,
                findings=routed_to(member.family),
                codeql_query_files=dict(kwargs["codeql_query_sha256"])
                if status in {"completed", "partial"}
                else None,
                codeql_pack_manifest=manifest,
            )

        return run

    results: list[FamilyResult] = []

    def run_member(member: Member, call: Callable[[Path], LanguageResult]) -> None:
        folder = output / "families" / member.family
        folder.mkdir(parents=True)
        result: LanguageResult | None = None
        error: str | None = None
        try:
            result = call(folder)
        except MEMBER_ERRORS as exc:
            # As when scanned alone, the member's failure is final; other families go on.
            error = f"{type(exc).__name__}: {exc}"
        results.append(
            FamilyResult(
                family=member.family,
                profile_id=member.profile.profile_id,
                status=result.pipeline.status if result is not None else "failed",
                error=error,
                result=result,
                raw_finding_ids=[finding["raw_id"] for finding in routed_to(member.family)],
            )
        )

    def run_primary(folder: Path) -> LanguageResult:
        assert isinstance(primary.profile, ScanProfile)
        try:
            return scan_language(
                language,
                profile=primary.profile,
                settings=settings,
                source=source,
                files=files,
                output=output,
                snapshot_sha256=snapshot_sha256,
                run_pipeline_fn=primary_pipeline,
                invoke_fn=invoke_fn,
            )
        finally:
            # The member wrote its files next to the tools' output; keep them with its family.
            for name in MEMBER_FILES:
                if (output / name).is_file():
                    shutil.move(output / name, folder / name)

    run_member(primary, run_primary)
    everyone = [member.family for member in taking_part]
    for step, record in (primary_steps[0] if primary_steps else {}).items():
        kind = STEP_KINDS.get(step, "version" if step.endswith("-version") else "other")
        users = everyone if step in SHARED_STEPS else [primary.family]
        steps[step] = {**record, "kind": kind, "serves": users}

    for member in others:
        profile = member.profile
        assert isinstance(profile, EvidenceProfile)

        def run_evidence(
            folder: Path, member: Member = member, profile: EvidenceProfile = profile
        ) -> LanguageResult:
            return scan_language_evidence(
                language,
                profile=profile,
                settings=settings,
                source=source,
                output=folder,
                snapshot_sha256=snapshot_sha256,
                run_pipeline_fn=shared_database_pipeline(member),
                invoke_fn=invoke_fn,
            )

        run_member(member, run_evidence)

    by_raw_id = {record["raw_id"]: record for record in records}
    unresolved = [f for f in findings if by_raw_id[f["raw_id"]]["analysis_family"] is None]
    unassigned_units, unassigned_assessments = _unassigned(unresolved, by_raw_id)
    conservation = check_conservation(findings, records, results, unassigned_units)
    status = _overall([family.status for family in results])

    if unassigned_units:
        folder = output / "families" / UNASSIGNED
        folder.mkdir(parents=True)
        _write_json(folder / "units.json", unassigned_units)
        _write_json(folder / "assessments.json", unassigned_assessments)
    _write_json(output / "findings.json", findings)
    _write_json(output / "classification.json", records)
    _write_json(
        output / "run.json",
        {
            "composition_version": COMPOSITION_VERSION,
            "language": language,
            "status": status,
            "snapshot_sha256": snapshot_sha256,
            "members": [
                {
                    "family": family.family,
                    "profile_id": family.profile_id,
                    "profile_sha256": next(
                        m.profile.manifest_sha256 for m in taking_part if m.family == family.family
                    ),
                    "status": family.status,
                    "error": family.error,
                    "unit_version": family.result.unit_version if family.result else None,
                    "raw_findings": len(family.raw_finding_ids),
                    "units": len(family.units),
                }
                for family in results
            ],
            "steps": steps,
            "conservation": conservation,
        },
    )
    return CompositeResult(
        language=language,
        status=status,
        steps=steps,
        findings=findings,
        classification=records,
        families=results,
        unassigned_units=unassigned_units,
        unassigned_assessments=unassigned_assessments,
        conservation=conservation,
    )
