"""Results passed from scan execution to transactional persistence."""

from dataclasses import dataclass, field
from typing import Any

from app.scanners.pipeline import PipelineResult, PipelineStatus
from app.triage.reconcile import RECONCILIATION_VERSION, ReconciledUnit

LOCATOR_VERSION = "sink-locator-v0"


@dataclass(frozen=True, slots=True)
class LanguageResult:
    language: str
    pipeline: PipelineResult
    tool_versions: dict[str, str]
    units: list[ReconciledUnit]
    assessments: list[dict[str, Any]]
    # How the units were built; reads select a scan's units by unit_version.
    unit_version: str = RECONCILIATION_VERSION
    locator_version: str = LOCATOR_VERSION
    # The fields below are set only by a composite scan (app.workflows.scans.families).
    # The analysis family of this result's units.
    family: str | None = None
    # One result per family: the units and assessments are written part by part, each with
    # its own unit and locator version, while tool runs and findings belong to the language.
    parts: tuple["LanguageResult", ...] = ()
    # Analysis passes on the shared database that have their own SARIF, log and tool run.
    passes: tuple[str, ...] = ()
    # raw ID -> the tool pass that produced the finding, when it is not the finding's tool.
    finding_pass: dict[str, str] = field(default_factory=dict)
    # raw ID -> classification record (reported CWEs, mapped CWEs, analysis family).
    classification: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: PipelineStatus
    error: str | None
    languages: list[LanguageResult]
    # Uploaded objects by name ("python/codeql.sarif"): {"key", "sha256", "size"}.
    artifacts: dict[str, dict[str, Any]]
    provenance: dict[str, Any]
    source_file_count: int
