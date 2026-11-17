"""Scan API models. Sources are named, never given as URLs: the server builds every URL."""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.pagination import Page
from app.core.schemas import InputSchema, ReadSchema
from app.scanners.sources import validate_github, validate_npm

Tier = Literal["P1", "P2", "U", "P3", "P4"]
TIERS: tuple[Tier, ...] = ("P1", "P2", "U", "P3", "P4")  # queue order, for display only
Tool = Literal["semgrep", "bandit", "eslint", "codeql"]
# "filtered": the candidate met a filter condition of its family, so it left the main review
# list and is kept on file. It is evidence against the alert, not a verified false positive.
Disposition = Literal["review", "filtered"]
# An analysis family of a scan; "unassigned" holds findings whose family could not be named.
FamilyName = Literal[
    "command-injection",
    "path-traversal",
    "sql-injection",
    "cross-site-scripting",
    "ssrf",
    "unassigned",
]
# What the evidence says about a unit. This is not the scan's status and not the filter
# decision (`disposition`): only "refuted" ever leads to "filtered".
#   refuted         a tool's evidence shows the alerts are false;
#   not_refuted     evidence was examined and does not refute the alerts, or contradicts it;
#   insufficient    no evidence, or evidence without the confirmation a filter rule needs;
#   unavailable     the run or an evidence step was incomplete, so nothing could be checked;
#   not_applicable  the unit has no analysis family, so no filter condition applies;
#   not_assessed    a scan written before filtering existed.
EvidenceState = Literal[
    "refuted", "not_refuted", "insufficient", "unavailable", "not_applicable", "not_assessed"
]


class NpmSource(InputSchema):
    kind: Literal["npm"]
    package: str = Field(max_length=214, examples=["curling"])
    version: str = Field(max_length=256, description="Exact SemVer version", examples=["0.2.0"])

    @model_validator(mode="after")
    def valid_coordinates(self) -> Self:
        validate_npm(self.package, self.version)
        return self


class GitHubSource(InputSchema):
    kind: Literal["github"]
    owner: str = Field(max_length=39)
    repo: str = Field(max_length=100)
    commit: str = Field(min_length=40, max_length=40, description="Full commit SHA-1")

    @model_validator(mode="after")
    def valid_coordinates(self) -> Self:
        validate_github(self.owner, self.repo, self.commit)
        return self


class ScanCreate(InputSchema):
    source: Annotated[NpmSource | GitHubSource, Field(discriminator="kind")]
    profile: Literal[
        "command-injection-v0.1",
        "command-injection-v0.2",
        "command-injection-v0.3",
        "path-traversal-v0.2",
        "multi-cwe-v0.1",
        "multi-cwe-v0.2",
        "multi-cwe-v0.3",
        "multi-cwe-v0.4",
        "multi-cwe-v0.5",
        "multi-cwe-v0.6",
    ] = Field(
        default="command-injection-v0.1",
        description="command-injection-v0.1: CWE-78, JavaScript and Python, Semgrep and "
        "CodeQL, priority policy v0.1. command-injection-v0.2: the same with Bandit "
        "(Python) and eslint-plugin-security (JavaScript/TypeScript) added to the "
        "screening step, priority policy v0.2. command-injection-v0.3: v0.2 with the "
        "JavaScript sink locator v1, a Semgrep target selection the scanned source cannot "
        "change, and a constant-command filter rule for JavaScript/TypeScript. "
        "path-traversal-v0.2: CWE-22, Python, CodeQL safety evidence. multi-cwe-v0.1: "
        "command-injection-v0.3 and path-traversal-v0.2 in one scan on one CodeQL database; "
        "each alert is routed to one analysis family and assessed by that member profile. "
        "multi-cwe-v0.2: the same two members plus sql-injection-v0.1 (CWE-89, Python and "
        "JavaScript/TypeScript, CodeQL only), whose alerts are detected and kept for review: "
        "nothing ranks or filters them. multi-cwe-v0.3: the same three families, with "
        "sql-injection-v0.2 running Semgrep (unchanged upstream rules), Bandit (Python) and "
        "CodeQL for CWE-89; their alerts are merged only inside one located SQL execution "
        "call and are all kept for review. multi-cwe-v0.4 (experimental): as multi-cwe-v0.3, "
        "with sql-injection-v0.3, which also joins a Bandit B608 alert on the statement that "
        "builds a SQL string to the CodeQL or Semgrep alert at the one execution call that runs "
        "it (Python). multi-cwe-v0.5 (experimental): the three families of multi-cwe-v0.4 plus "
        "cross-site-scripting-v0.1 (CWE-79, JavaScript/TypeScript), the seven standard CodeQL "
        "queries under Security/CWE-079 run on the same database; their alerts are detected and "
        "kept for review: nothing ranks or filters them. multi-cwe-v0.6 (experimental): the four "
        "families of multi-cwe-v0.5 plus ssrf-v0.1 (CWE-918, server-side request forgery, Python "
        "and JavaScript/TypeScript), the standard CodeQL queries py/full-ssrf, py/partial-ssrf "
        "and js/request-forgery run on the same databases; their alerts are detected and kept "
        "for review: nothing ranks or filters them.",
    )


class ScanAccepted(BaseModel):
    scan_id: uuid.UUID
    snapshot_id: uuid.UUID
    status: str


class SnapshotRead(ReadSchema):
    id: uuid.UUID
    status: str
    source_kind: str | None
    source_coordinate: str | None
    sha256: str | None
    provenance_kind: str | None
    error_message: str | None


class ToolRunRead(ReadSchema):
    tool: str
    language: str
    status: str
    tool_version: str | None
    exit_code: int | None
    error_message: str | None


class FamilyRun(BaseModel):
    """What one family did in one language of a composite scan."""

    language: str
    status: str = Field(description="State of the family's own run: completed, partial, failed")
    error: str | None
    raw_findings: int
    evidence_steps: dict[str, str] = Field(
        description="State of each step whose results are this family's evidence"
    )


class FamilyRead(BaseModel):
    """One analysis family of a scan: who assessed it and how its units are disposed."""

    family: FamilyName
    cwe: str | None = Field(description="The family's CWE; none for unassigned findings")
    label: str
    profile_id: str | None = Field(description="The pinned member profile that assessed it")
    profile_sha256: str | None
    runs: list[FamilyRun] = Field(description="Per language; empty for a single-profile scan")
    units: int
    review: int
    filtered: int
    held: int = Field(
        description="Units kept for review because no family could be named or the family "
        "ranked nothing"
    )


class ScanRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: str
    profile: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    reconciler_version: str | None
    policy_version: str | None
    snapshot: SnapshotRead
    tool_runs: list[ToolRunRead]
    unit_counts: dict[Tier, int]
    disposition_counts: dict[Disposition, int] = Field(
        description="Units in the main review list and units filtered on evidence"
    )
    families: list[FamilyRead] = Field(
        description="Analysis families of the scan; one for a single-profile scan"
    )


class UnitSummary(BaseModel):
    id: uuid.UUID
    unit_key: str = Field(description="Canonical unit ID, comparable with the experiment CLI")
    path: str | None
    start_line: int | None
    end_line: int | None
    start_column: int | None
    end_column: int | None
    sink_kind: str | None
    argument_role: str | None
    mapping_status: str
    priority: Tier
    decision_id: str
    reason: str
    tools: list[str]
    disposition: Disposition
    candidate_key: str | None = Field(description="Shared by units of the same call")
    filter_rule: str | None = Field(description="Rule that filtered the candidate, if any")
    analysis_family: FamilyName | None = Field(
        description="The family that assessed the unit; follows from the profile for a "
        "single-profile scan"
    )
    cwe: str | None = Field(description="The family's CWE")
    evidence_state: EvidenceState
    kept_because: list[str] = Field(description="Why the unit stays in the review list")


class UnitPage(Page[UnitSummary]):
    """One page of a scan's location units in queue order."""


class FindingRead(BaseModel):
    id: uuid.UUID
    tool: str
    language: str
    raw_id: str | None
    rule_id: str
    raw_rule_id: str | None
    file_path: str | None
    start_line: int | None
    end_line: int | None
    start_column: int | None
    end_column: int | None
    message: str
    cwe_ids: list[str] = Field(description="CWEs the tool reported, exactly as it wrote them")
    mapped_cwes: list[str] | None = Field(
        description="CWEs of the pinned rule definition; null when the scan did not classify"
    )
    analysis_family: str | None
    family_status: str | None = Field(description="resolved or unresolved")
    family_basis: str | None = Field(description="pass_provenance or pinned_rule_set")
    unresolved_reason: str | None
    tool_pass: str | None = Field(description="The tool pass that produced the finding")
    raw_result: dict[str, Any]


class UnitDetail(UnitSummary):
    matched_conditions: list[str]
    predicate_values: dict[str, bool]
    unknown_fields: list[str]
    source_types: list[str]
    shell_state: str | None
    blocker_proof: dict[str, Any] | None
    finding_evidence: list[dict[str, Any]]
    candidate: dict[str, Any] | None = Field(
        description="Key, match basis, member units, tools and best priority"
    )
    adjudication: dict[str, Any] | None = Field(
        description="Filter decision: rule, reason, evidence, or why the unit was kept"
    )
    policy_id: str
    policy_version: str
    policy_sha256: str
    spec_sha256: str
    rule_claims_version: str
    rule_claims_sha256: str
    reconciler_version: str
    findings: list[FindingRead]


class ReportCandidate(BaseModel):
    candidate_key: str
    basis: str = Field(description="same_call_site, single_location or unmatched_location")
    path: str | None
    start_line: int | None
    sink_kind: str | None
    tools: list[str]
    priority: Tier
    disposition: Disposition
    filter_rule: str | None
    filter_rules: list[str] = Field(description="Every rule whose evidence filtered it")
    reason: str
    unit_ids: list[uuid.UUID]
    raw_alerts: int
    analysis_family: FamilyName | None
    cwe: str | None
    evidence_state: EvidenceState


class ReportFamily(BaseModel):
    """The before/after counts of one analysis family."""

    family: FamilyName
    cwe: str | None
    label: str
    raw_alerts: int = Field(description="Every stored result of the family's units")
    evidence_results: int = Field(
        description="Of those, results of a safety-evidence query stored with a unit"
    )
    detection_alerts: int = Field(description="raw_alerts without evidence_results")
    units: int
    candidates: int
    main_list: int
    filtered: int
    main_list_by_priority: dict[Tier, int]
    filtered_by_rule: dict[str, int]
    evidence_states: dict[EvidenceState, int] = Field(description="Candidates per state")


class ReportStages(BaseModel):
    raw_alerts: int = Field(description="Every stored result of every tool pass")
    evidence_results: int = Field(
        description="Of those, results of a safety-evidence query that its member stores with "
        "the unit they belong to; they are not alerts of their own"
    )
    detection_alerts: int = Field(
        description="raw_alerts without evidence_results: the alerts the detection tools reported"
    )
    unranked_alerts: int = Field(
        description="Results in no unit, because an incomplete single-profile run ranked "
        "nothing. Not in the review list; counted here and exported in SARIF"
    )
    units: int = Field(description="Alerts merged by call and argument role")
    candidates: int = Field(description="Units merged by call: one review item each")
    main_list: int = Field(description="Candidates left after filtering")
    filtered: int = Field(
        description="Candidates that met a filter condition of their family; kept on file"
    )
    demoted: int = Field(description="Main-list candidates ranked P3 or P4, not filtered")


class SourceContribution(BaseModel):
    candidates: int
    only: int = Field(description="Candidates no other tool reported")


class ScanReport(BaseModel):
    """Before/after report of one scan: detection, merging, filtering, timing."""

    scan_id: uuid.UUID
    status: str
    profile: str | None
    profile_sha256: str | None = Field(description="Hash of the pinned profile manifest")
    policy_version: str | None
    reconciler_version: str | None
    snapshot: SnapshotRead
    started_at: datetime | None
    finished_at: datetime | None
    tool_versions: dict[str, str]
    steps: dict[str, dict[str, dict[str, Any]]] = Field(
        description="Per language and step: status, seconds, alert count"
    )
    raw_alerts: dict[str, int]
    stages: ReportStages
    sources: dict[str, SourceContribution]
    main_list_by_priority: dict[Tier, int]
    filtered_by_rule: dict[str, int] = Field(
        description="Filtered candidates per rule; one candidate can satisfy several rules"
    )
    families: list[ReportFamily] = Field(description="The same counts per analysis family")
    composition: dict[str, Any] | None = Field(
        description="For a composite scan: composition version and the pinned member profiles"
    )
    candidates: list[ReportCandidate]


class SarifLog(BaseModel):
    """SARIF 2.1.0 log of every original alert, annotated with candidate and disposition."""

    model_config = ConfigDict(populate_by_name=True)

    schema_uri: str = Field(alias="$schema")
    version: str
    runs: list[dict[str, Any]]
