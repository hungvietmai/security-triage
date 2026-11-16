"""Composite scan of one language: several analysis families on one tool run.

A composite scan is built from existing pinned profiles ("members"), one per analysis family.
The scanners run once and one CodeQL database is created. Each member's own entry point
(`scan_language`, `scan_language_evidence` or `scan_language_detection`) then assesses the
findings routed to its family, with its own pinned rules, policy and filter conditions.
Nothing here ranks or filters: the composition only provides each member with the tool
results it would have produced alone.

The rule this module keeps: for the same snapshot and pinned tools, a family's units and
assessments equal what scanning with that member's profile alone produces. The one intended
difference is the raw-ID prefix of a pass that shares the database (see `PASS_PREFIX`).

Routing happens before any merging, so an alert of one family can never be merged into a
unit of another. Every finding ends in exactly one unit. Two kinds of unit are made here and
not by a member; both sit at priority U in the review list and are never filtered:

  unassigned   the finding's family cannot be named (F00_FAMILY_UNRESOLVED);
  not ranked   the member ranked none of its family's findings, because its run was
               incomplete or its assessment failed (F10_FAMILY_NOT_RANKED).
"""

from __future__ import annotations

import dataclasses
import hashlib
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
from app.scanners.passes import run_member_pass
from app.scanners.pipeline import PipelineResult, PipelineStatus, run_pipeline
from app.scanners.process import InvokeCallable, ProcessRecord, invoke
from app.scanners.profile import (
    AnyProfile,
    CompositeProfile,
    DetectionProfile,
    EvidenceProfile,
    ScanProfile,
)
from app.scanners.sarif import Finding
from app.triage.reconcile import ReconciledUnit, reconcile_findings
from app.workflows.scans.analysis import RunPipeline, scan_language, scan_language_evidence
from app.workflows.scans.classification import (
    Claim,
    Classification,
    classify_findings,
    pinned_rules_claim,
    rule_claims_claim,
)
from app.workflows.scans.detection import detection_claim, scan_language_detection
from app.workflows.scans.results import LanguageResult

COMPOSITION_VERSION = "family-composition-v0.1"
UNASSIGNED = "unassigned"
UNRESOLVED_DECISION = "F00_FAMILY_UNRESOLVED"
NOT_RANKED_DECISION = "F10_FAMILY_NOT_RANKED"
NOT_RANKED = "family_not_ranked"
# How a unit made here was located: at the place the tool reported, with no sink behind it.
HELD_LOCATOR_VERSION = "reported-location"


@dataclass(frozen=True, slots=True)
class Family:
    """An analysis family: the semantic group one member profile handles."""

    name: str
    cwe: str
    label: str
    # The kind of profile whose entry point assesses this family's findings.
    profile_type: type[ScanProfile] | type[EvidenceProfile] | type[DetectionProfile]


# Every family a scan can contain. A new family is added here only with its own member profile
# and, before it may filter anything, its own evaluated evidence.
FAMILIES = {
    "command-injection": Family("command-injection", "CWE-78", "Command injection", ScanProfile),
    "path-traversal": Family("path-traversal", "CWE-22", "Path traversal", EvidenceProfile),
    # Detected and kept only: no ranking policy and no filter condition has been evaluated.
    "sql-injection": Family("sql-injection", "CWE-89", "SQL injection", DetectionProfile),
}
# The analysis family each pinned profile handles. A profile that is not listed cannot be a
# member: its family, and with it the conditions under which it may filter, is unknown.
FAMILY_OF_PROFILE = {
    "command-injection-v0.1": "command-injection",
    "command-injection-v0.2": "command-injection",
    "command-injection-v0.3": "command-injection",
    "path-traversal-v0.2": "path-traversal",
    "sql-injection-v0.1": "sql-injection",
    "sql-injection-v0.2": "sql-injection",
}
# A member whose queries run on the shared database gets its own analysis pass. Its raw IDs
# start with this prefix and the family, so they stay unique next to the primary CodeQL pass.
PASS_PREFIX = "codeql-"
# What a pass on the shared database is, for the cost record: a safety-evidence pack runs its
# detection and its evidence query in one command; a detection member runs detection only.
EVIDENCE_PASS = "detection+evidence"
DETECTION_PASS = "detection"
PASS_KINDS = (EVIDENCE_PASS, DETECTION_PASS)
# Tools a member may run in a pass of its own, and the prefix of that pass's name.
MEMBER_PASS_TOOLS = ("codeql", "semgrep", "bandit")
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
# A member's Semgrep or Bandit pass (`app.scanners.passes.run_member_pass`).
MemberPass = Callable[..., tuple[ProcessRecord, list[Finding], bool]]

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
class HeldUnits:
    """Units made by the composition for findings no member ranked; `family` may be UNASSIGNED."""

    family: str
    units: list[ReconciledUnit]
    assessments: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class CompositeResult:
    language: str
    status: PipelineStatus
    # Every step of the language run with its kind and the families it serves.
    steps: dict[str, dict[str, Any]]
    # Every result a member ranks: the detection alerts of every pass and, for a pass that
    # runs a safety-evidence pack, that pack's evidence-query results too (the member links
    # both to the unit). Results of the primary member's evidence steps are never in here.
    findings: list[Finding]
    classification: list[Classification]
    families: list[FamilyResult]
    # Findings kept outside the members' results: without a family, or of an unranked family.
    held: list[HeldUnits]
    conservation: dict[str, Any]

    def _held(self, family: str) -> HeldUnits | None:
        return next((part for part in self.held if part.family == family), None)

    @property
    def unassigned_units(self) -> list[ReconciledUnit]:
        part = self._held(UNASSIGNED)
        return part.units if part is not None else []

    @property
    def unassigned_assessments(self) -> list[dict[str, Any]]:
        part = self._held(UNASSIGNED)
        return part.assessments if part is not None else []


def _ordered(members: Sequence[Member]) -> list[Member]:
    """One member per family, the member that runs the scanners first."""
    for member in members:
        family = FAMILIES.get(member.family)
        if family is None or FAMILY_OF_PROFILE.get(member.profile.profile_id) != member.family:
            raise ValueError(
                f"Profile {member.profile.profile_id} is not a member of family {member.family!r}"
            )
        if not isinstance(member.profile, family.profile_type):
            raise ValueError(f"Family {member.family} cannot assess {member.profile.profile_id}")
    families = [member.family for member in members]
    if len(set(families)) != len(families):
        raise ValueError("A composite scan takes one member per analysis family")
    primary = [member for member in members if isinstance(member.profile, ScanProfile)]
    if len(primary) != 1:
        raise ValueError("A composite scan needs exactly one member that runs the scanners")
    return primary + [member for member in members if member is not primary[0]]


def compose(profiles: Sequence[AnyProfile]) -> list[Member]:
    """The members of a composite scan, one per family, the primary member first.

    Exactly one member runs the screening tools and creates the CodeQL database (a priority
    profile); every other member is a safety-evidence or a detection profile whose queries
    are analyzed on that database, each in a pass of its own.
    """
    members = []
    for profile in profiles:
        family = FAMILY_OF_PROFILE.get(profile.profile_id)
        if family is None:
            raise ValueError(f"Profile has no analysis family: {profile.profile_id}")
        members.append(Member(family, profile))
    return _ordered(members)


def members_of(profile: CompositeProfile) -> list[Member]:
    """The members a composite profile pins, checked against the families this code handles.

    The manifest names each member's family; a family this code does not know, a profile that
    belongs to another family, or another way of combining members is refused, so a scan never
    runs a handler its manifest did not ask for.
    """
    if profile.composition != COMPOSITION_VERSION:
        raise ValueError(f"Unknown composition version: {profile.composition}")
    return _ordered([Member(family, member) for family, member in profile.members])


def pass_name(member: Member, tool: str = "codeql") -> str:
    """The name of a member's pass of `tool`: `codeql-<family>`, `semgrep-<family>`..."""
    return f"{tool}-{member.family}"


def pass_tool(name: str) -> str:
    """The tool of a member pass, from its name."""
    return name.split("-", 1)[0]


def member_passes(member: Member, language: str) -> list[tuple[str, str]]:
    """(tool, pass name) of every pass a non-primary member runs for `language`, in order."""
    scanners = member.profile.configs[language]["scanners"]
    return [(tool, pass_name(member, tool)) for tool in scanners if tool in MEMBER_PASS_TOOLS]


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
        theirs = member.profile.configs[language]
        version = theirs["codeql_version"]
        if version != config["codeql_version"]:
            raise ValueError(
                f"Members pin different CodeQL versions: {config['codeql_version']} and {version}"
            )
        # A member's own Semgrep or Bandit pass runs the tool the worker checked for the primary.
        if (
            "semgrep" in theirs["scanners"]
            and theirs["semgrep_version"] != config["semgrep_version"]
        ):
            raise ValueError("Members pin different Semgrep versions")
        if (
            "bandit" in theirs["scanners"]
            and theirs["bandit"]["version"] != (config.get("bandit") or theirs["bandit"])["version"]
        ):
            raise ValueError("Members pin different Bandit versions")
    return taking_part


def _claim(member: Member, language: str) -> Claim:
    profile = member.profile
    if isinstance(profile, ScanProfile):
        return rule_claims_claim(profile.rule_claims, language)
    if isinstance(profile, DetectionProfile) and profile.unit_merge is not None:
        return detection_claim(profile, language)
    if isinstance(profile, DetectionProfile):
        # The manifest pins each rule's mapped CWEs; nothing is read from the rule's name.
        return pinned_rules_claim(
            profile.rules[language], basis=f"pinned_rule_id:{profile.profile_id}"
        )
    rules = {}
    for rule in (profile.baseline_rule, profile.evidence_rule):
        # The pack's query IDs name their CWE ("st/cwe-22/none"); the manifest pins the IDs.
        match = re.fullmatch(r"st/cwe-(\d+)/[\w-]+", rule)
        rules[rule] = [f"CWE-{int(match.group(1))}"] if match else []
    return pinned_rules_claim(rules, basis=f"pinned_query_id:{profile.profile_id}")


def _held_units(
    findings: Sequence[Finding],
    records: Mapping[str, Mapping[str, Any]],
    *,
    family: str,
    decision: str,
    codes: Sequence[str] | None,
    reason: str,
) -> HeldUnits:
    """One unit per reported location for findings of `family` that no member ranked.

    `codes` are the reasons the units are kept; None takes each finding's own reason for
    having no family. The reason text ends with what always holds for such a unit.
    """
    # No sink is offered, so nothing is merged into a call: each location stands alone.
    units = reconcile_findings(findings, [], {})
    tools = {finding["raw_id"]: finding["tool"] for finding in findings}
    assessments = []
    for unit in units:
        # The same location may be held for another family too; the family is part of the ID.
        identity = f"{COMPOSITION_VERSION}\n{family}\n{unit['unit_id']}"
        unit["unit_id"] = hashlib.sha256(identity.encode()).hexdigest()
        evidence = [records[raw_id] for raw_id in unit["raw_finding_ids"]]
        kept = (
            list(codes)
            if codes is not None
            else sorted({str(record["unresolved_reason"]) for record in evidence})
        )
        text = reason
        if codes is None:
            text += ": " + "; ".join(_UNRESOLVED_REASONS[code] for code in kept)
        text += ". Cảnh báo được giữ nguyên nhãn, ở mức U, và không quy tắc gạn nào được áp dụng."
        unit_tools = sorted({tools[raw_id] for raw_id in unit["raw_finding_ids"]})
        assessments.append(
            {
                "unit_id": unit["unit_id"],
                "analysis_family": None if family == UNASSIGNED else family,
                "priority": "U",
                "decision_id": decision,
                "matched_conditions": [decision.split("_", 1)[1].lower(), *kept],
                "reason": text,
                "tools": unit_tools,
                "predicate_values": {"held_by_composition": True},
                "unknown_fields": ["analysis_family"] if family == UNASSIGNED else ["assessment"],
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
                    "kept_because": kept,
                    "reason": text,
                    "evidence": [],
                },
                "policy_id": "family-composition",
                "policy_version": COMPOSITION_VERSION,
                "policy_sha256": "",
                "spec_sha256": "",
                "rule_claims_version": "not-applicable",
                "rule_claims_sha256": "",
                "reconciler_version": COMPOSITION_VERSION,
            }
        )
    return HeldUnits(family, units, assessments)


def hold_unranked(result: LanguageResult, *, family: str) -> LanguageResult:
    """A single-profile run whose member ranked nothing: its alerts as units held for review.

    Scanned alone, a safety-evidence profile makes no unit when its run is incomplete, because
    ranking needs both queries' complete results. Its alerts were then stored without a unit
    and so never reached the review list. They are held here exactly as a composite scan holds
    the alerts of a family that ranked nothing: one unit per reported location, priority U,
    in the review list, never filtered. A run that ranked its alerts, or has none, is
    returned unchanged.
    """
    findings = result.pipeline.findings
    if not findings or result.units:
        return result
    records = {
        finding["raw_id"]: {
            "raw_id": finding["raw_id"],
            "tool": finding["tool"],
            "rule_id": finding["rule_id"],
            "message": finding["message"],
        }
        for finding in findings
    }
    state = "chạy dở" if result.pipeline.status == "partial" else "thất bại"
    held = _held_units(
        findings,
        records,
        family=family,
        decision=NOT_RANKED_DECISION,
        codes=[NOT_RANKED],
        reason=f"Lượt quét nhóm {family} {state} nên chưa xếp hạng cảnh báo này",
    )
    return dataclasses.replace(
        result,
        units=held.units,
        assessments=held.assessments,
        unit_version=COMPOSITION_VERSION,
        locator_version=HELD_LOCATOR_VERSION,
    )


def check_conservation(
    findings: Sequence[Mapping[str, Any]],
    classification: Sequence[Classification],
    families: Sequence[FamilyResult],
    held: Sequence[HeldUnits],
) -> dict[str, Any]:
    """Every finding is classified once and sits in exactly one unit of its own family.

    A family's findings are either all in the member's units or all in units held for it
    ("not ranked"). A family that ranked some findings but not others, a finding in two units,
    a finding in no unit, or a unit holding another family's finding is an error.
    """
    raw_ids = [str(finding["raw_id"]) for finding in findings]
    if len(set(raw_ids)) != len(raw_ids):
        duplicated = sorted(raw_id for raw_id, count in Counter(raw_ids).items() if count > 1)
        raise RuntimeError(f"Composite scan produced duplicate raw IDs: {duplicated}")
    if [record["raw_id"] for record in classification] != raw_ids:
        raise RuntimeError("Composite scan did not classify every finding exactly once")
    routed: dict[str, list[str]] = {}
    for record in classification:
        routed.setdefault(record["analysis_family"] or UNASSIGNED, []).append(record["raw_id"])
    held_by = {part.family: part.units for part in held}

    def count(units: Sequence[Mapping[str, Any]]) -> Counter[str]:
        return Counter(str(raw_id) for unit in units for raw_id in unit["raw_finding_ids"])

    def account(name: str, units: Sequence[Mapping[str, Any]]) -> dict[str, int]:
        mine = Counter(routed.get(name, []))
        ranked, kept = count(units), count(held_by.get(name, []))
        if ranked + kept != mine or (ranked and kept):
            missing = sorted((mine - ranked - kept).elements())
            foreign = sorted((ranked + kept - mine).elements())
            raise RuntimeError(
                f"Composite conservation failed for {name}: missing={missing}, foreign={foreign}"
            )
        return {
            "routed": sum(mine.values()),
            "in_units": sum(ranked.values()),
            "not_ranked": sum(kept.values()),
            "units": len(units),
            "held_units": len(held_by.get(name, [])),
        }

    known = {family.family for family in families} | {UNASSIGNED}
    stray = sorted(family for family in {*routed, *held_by} if family not in known)
    if stray:
        raise RuntimeError(f"Findings were routed to families without a member: {stray}")
    unassigned = account(UNASSIGNED, [])
    return {
        "raw_findings": len(raw_ids),
        "families": {family.family: account(family.family, family.units) for family in families},
        UNASSIGNED: {"routed": unassigned["routed"], "units": unassigned["held_units"]},
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
    pass_fn: MemberPass = run_member_pass,
) -> CompositeResult:
    """Run the scanners once for `language` and let every member assess its family's findings.

    `members` comes from `compose` or `members_of`. `output` receives the tools' files, the
    CodeQL database, the combined `findings.json`, `classification.json` and `run.json`, one
    folder per family under `families/` with that member's own files, and one folder per
    family under `held/` for units made here. `pass_members` overrides which families a tool
    pass serves; by default every pass serves the member that configured it.
    """
    taking_part = _participating(members, language)
    primary, others = taking_part[0], taking_part[1:]
    assert isinstance(primary.profile, ScanProfile)
    config = primary.profile.configs[language]
    serves: dict[str, Sequence[str]] = {tool: [primary.family] for tool in config["scanners"]}
    serves.update(
        {name: [member.family] for member in others for _, name in member_passes(member, language)}
    )
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
        wanted = None if family == UNASSIGNED else family
        mine = {record["raw_id"] for record in records if record["analysis_family"] == wanted}
        return [finding for finding in findings if finding["raw_id"] in mine]

    def primary_pipeline(**kwargs: Any) -> PipelineResult:
        """The real tool run; the member sees only the findings routed to its family."""
        result = run_pipeline_fn(**kwargs)
        classify(result.findings, {f["raw_id"]: f["tool"] for f in result.findings})
        # The same steps object: the member later records its sink locator on it.
        primary_steps.append(result.steps)
        return dataclasses.replace(result, findings=routed_to(primary.family))

    def screening_pass(member: Member, tool: str, kwargs: Mapping[str, Any]) -> ProcessRecord:
        """A member's own Semgrep or Bandit pass, recorded under its own name."""
        name = pass_name(member, tool)
        found: list[Finding] = []
        try:
            record, found, _ = pass_fn(
                tool,
                name=name,
                config=member.profile.configs[language],
                source=source,
                output=output,
                snapshot_sha256=snapshot_sha256,
                repository_root=member.profile.root,
                invoke_fn=kwargs["invoke_fn"],
            )
        except MEMBER_ERRORS as exc:
            record = {"status": "failed", "error": str(exc)}
        steps[name] = {**record, "kind": DETECTION_PASS, "serves": [member.family]}
        classify(found, {finding["raw_id"]: name for finding in found})
        return record

    def shared_database_pipeline(member: Member) -> RunPipeline:
        """Serve a member's queries from the database the primary created.

        A detection member may also run Semgrep and Bandit with its own pinned rules, each in a
        pass of its own; its run is complete only when every one of its passes is.
        """

        def run(**kwargs: Any) -> PipelineResult:
            name = pass_name(member)
            shared = primary_steps[0] if primary_steps else {}
            member_steps: dict[str, ProcessRecord] = {
                step: shared[step] for step in SHARED_STEPS if step in shared
            }
            scanners = list(kwargs["scanners"])
            for tool in scanners:
                if tool in ("semgrep", "bandit"):
                    member_steps[tool] = screening_pass(member, tool, kwargs)
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
            kind = EVIDENCE_PASS if isinstance(member.profile, EvidenceProfile) else DETECTION_PASS
            steps[name] = {**record, "kind": kind, "serves": [member.family]}
            classify(found, {finding["raw_id"]: name for finding in found})
            member_steps["codeql"] = record
            status = record["status"]
            usable = status in {"completed", "partial"}
            statuses = [member_steps[tool]["status"] for tool in scanners if tool in member_steps]
            overall = (
                "completed"
                if statuses and all(s == "completed" for s in statuses)
                else "partial"
                if any(s in {"completed", "partial"} for s in statuses)
                else "failed"
            )
            return PipelineResult(
                status=overall,  # type: ignore[arg-type]
                steps=member_steps,
                findings=routed_to(member.family),
                codeql_query_files=dict(kwargs["codeql_query_sha256"]) if usable else None,
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

        def run_on_shared_database(folder: Path, member: Member = member) -> LanguageResult:
            profile = member.profile
            if isinstance(profile, DetectionProfile):
                return scan_language_detection(
                    language,
                    profile=profile,
                    family=member.family,
                    settings=settings,
                    source=source,
                    output=folder,
                    snapshot_sha256=snapshot_sha256,
                    run_pipeline_fn=shared_database_pipeline(member),
                    invoke_fn=invoke_fn,
                    files=files,
                )
            assert isinstance(profile, EvidenceProfile)
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

        run_member(member, run_on_shared_database)
        located = results[-1].result
        if located is not None and "sink-locator" in located.pipeline.steps:
            # A member's own locator, kept with the language's steps for the cost record.
            steps[f"sink-locator-{member.family}"] = {
                **located.pipeline.steps["sink-locator"],
                "kind": "locator",
                "serves": [member.family],
            }

    by_raw_id = {record["raw_id"]: record for record in records}
    held: list[HeldUnits] = []
    unresolved = routed_to(UNASSIGNED)
    if unresolved:
        held.append(
            _held_units(
                unresolved,
                by_raw_id,
                family=UNASSIGNED,
                decision=UNRESOLVED_DECISION,
                codes=None,
                reason="Chưa xác định được nhóm phân tích",
            )
        )
    for family in results:
        mine = routed_to(family.family)
        if mine and not family.units:
            # The member ranked nothing (as it would alone); the alerts still need a reviewer.
            state = "chạy dở" if family.status == "partial" else "thất bại"
            detail = f" ({family.error})" if family.error else ""
            held.append(
                _held_units(
                    mine,
                    by_raw_id,
                    family=family.family,
                    decision=NOT_RANKED_DECISION,
                    codes=[NOT_RANKED],
                    reason=f"Nhóm {family.family} {state}{detail} nên chưa xếp hạng cảnh báo này",
                )
            )
    conservation = check_conservation(findings, records, results, held)
    status = _overall([family.status for family in results])

    for part in held:
        folder = output / "held" / part.family
        folder.mkdir(parents=True)
        _write_json(folder / "units.json", part.units)
        _write_json(folder / "assessments.json", part.assessments)
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
                    # The hashes of the query files this member's CodeQL run was checked
                    # against, as its own run record states them. Only this file is stored
                    # with the scan; the files under families/ stay in the work directory.
                    "codeql_query_files": (
                        family.result.pipeline.codeql_query_files if family.result else None
                    ),
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
        held=held,
        conservation=conservation,
    )


def family_summaries(result: CompositeResult, members: Sequence[Member]) -> list[dict[str, Any]]:
    """What each family of one language run did, for the scan's provenance record."""
    profiles = {member.family: member.profile for member in members}
    held = {part.family: len(part.units) for part in result.held}
    summaries = []
    for family in result.families:
        profile = profiles[family.family]
        summaries.append(
            {
                "family": family.family,
                "cwe": FAMILIES[family.family].cwe,
                "profile_id": profile.profile_id,
                "profile_sha256": profile.manifest_sha256,
                "status": family.status,
                "error": family.error,
                "unit_version": family.result.unit_version if family.result else None,
                "policy_versions": sorted({a["policy_version"] for a in family.assessments}),
                "raw_findings": len(family.raw_finding_ids),
                "units": len(family.units),
                "held_units": held.get(family.family, 0),
                # The steps whose results are this family's evidence, with their state.
                "evidence_steps": {
                    name: step["status"]
                    for name, step in result.steps.items()
                    if family.family in step["serves"] and "evidence" in step["kind"]
                },
            }
        )
    if UNASSIGNED in held:
        summaries.append(
            {
                "family": UNASSIGNED,
                "cwe": None,
                "profile_id": None,
                "profile_sha256": None,
                "status": "completed",
                "error": None,
                "unit_version": COMPOSITION_VERSION,
                "policy_versions": [COMPOSITION_VERSION],
                "raw_findings": result.conservation[UNASSIGNED]["routed"],
                "units": 0,
                "held_units": held[UNASSIGNED],
                "evidence_steps": {},
            }
        )
    return summaries


def to_language_result(result: CompositeResult) -> LanguageResult:
    """A composite run in the shape persistence takes: one language, one part per family.

    The tool runs and findings belong to the language; the units and assessments belong to
    the family that produced them, each with its own unit and locator version.
    """
    versions: dict[str, str] = {}
    parts: list[LanguageResult] = []
    for family in result.families:
        if family.result is None:
            continue
        versions.update(family.result.tool_versions)
        if family.units:
            parts.append(dataclasses.replace(family.result, family=family.family))
    passes = tuple(
        name
        for name, step in result.steps.items()
        # A member's pass is named "<tool>-<family>"; the primary's own steps are named by tool.
        if step["kind"] in PASS_KINDS and "-" in name and pass_tool(name) in MEMBER_PASS_TOOLS
    )
    for name in passes:
        versions[name] = versions.get(pass_tool(name), "")
    steps: dict[str, ProcessRecord] = {
        name: step  # type: ignore[misc]
        for name, step in result.steps.items()
    }
    pipeline = PipelineResult(
        status=result.status,
        steps=steps,
        findings=result.findings,
        codeql_query_files=None,
        codeql_pack_manifest=None,
    )
    for part in result.held:
        parts.append(
            LanguageResult(
                result.language,
                pipeline,
                versions,
                part.units,
                part.assessments,
                unit_version=COMPOSITION_VERSION,
                locator_version=HELD_LOCATOR_VERSION,
                family=part.family,
            )
        )
    return LanguageResult(
        result.language,
        pipeline,
        versions,
        [unit for part in parts for unit in part.units],
        [assessment for part in parts for assessment in part.assessments],
        unit_version=COMPOSITION_VERSION,
        parts=tuple(parts),
        passes=passes,
        finding_pass={record["raw_id"]: record["tool_pass"] for record in result.classification},
        classification={record["raw_id"]: dict(record) for record in result.classification},
    )
