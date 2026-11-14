"""Results passed from scan execution to transactional persistence."""

from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: PipelineStatus
    error: str | None
    languages: list[LanguageResult]
    # Uploaded objects by name ("python/codeql.sarif"): {"key", "sha256", "size"}.
    artifacts: dict[str, dict[str, Any]]
    provenance: dict[str, Any]
    source_file_count: int
