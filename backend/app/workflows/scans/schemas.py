"""Scan API models. Sources are named, never given as URLs: the server builds every URL."""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, Field, model_validator

from app.core.pagination import Page
from app.core.schemas import InputSchema, ReadSchema
from app.scanners.sources import validate_github, validate_npm

Tier = Literal["P1", "P2", "U", "P3", "P4"]
TIERS: tuple[Tier, ...] = ("P1", "P2", "U", "P3", "P4")  # queue order, for display only
Tool = Literal["semgrep", "codeql"]


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
    profile: Literal["command-injection-v0.1"] = "command-injection-v0.1"


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
    blocker_proof: dict[str, Any] | None
    finding_evidence: list[dict[str, Any]]
    policy_id: str
    policy_version: str
    policy_sha256: str
    spec_sha256: str
    rule_claims_version: str
    rule_claims_sha256: str
    reconciler_version: str
    findings: list[FindingRead]
