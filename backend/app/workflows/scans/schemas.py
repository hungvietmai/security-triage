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
# "filtered": a tool proved the candidate false; it left the main review list, kept on file.
Disposition = Literal["review", "filtered"]


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
    ] = Field(
        default="command-injection-v0.1",
        description="command-injection-v0.1: CWE-78, JavaScript and Python, Semgrep and "
        "CodeQL, priority policy v0.1. command-injection-v0.2: the same with Bandit "
        "(Python) and eslint-plugin-security (JavaScript/TypeScript) added to the "
        "screening step, priority policy v0.2. command-injection-v0.3: v0.2 with the "
        "JavaScript sink locator v1, a Semgrep target selection the scanned source cannot "
        "change, and a constant-command filter rule for JavaScript/TypeScript. "
        "path-traversal-v0.2: CWE-22, Python, CodeQL safety evidence.",
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
    cwe_ids: list[str]
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


class ReportStages(BaseModel):
    raw_alerts: int = Field(description="Alerts of every detection tool, before merging")
    units: int = Field(description="Alerts merged by call and argument role")
    candidates: int = Field(description="Units merged by call: one review item each")
    main_list: int = Field(description="Candidates left after filtering")
    filtered: int = Field(description="Candidates a tool proved false; kept on file")
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
    candidates: list[ReportCandidate]


class SarifLog(BaseModel):
    """SARIF 2.1.0 log of every original alert, annotated with candidate and disposition."""

    model_config = ConfigDict(populate_by_name=True)

    schema_uri: str = Field(alias="$schema")
    version: str
    runs: list[dict[str, Any]]
