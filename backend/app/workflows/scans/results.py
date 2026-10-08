"""Results passed from scan execution to transactional persistence."""

from dataclasses import dataclass
from typing import Any

from app.scanners.pipeline import PipelineResult, PipelineStatus
from app.triage.reconcile import ReconciledUnit


@dataclass(frozen=True, slots=True)
class LanguageResult:
    language: str
    pipeline: PipelineResult
    tool_versions: dict[str, str]
    units: list[ReconciledUnit]
    assessments: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: PipelineStatus
    error: str | None
    languages: list[LanguageResult]
    # Uploaded objects by name ("python/codeql.sarif"): {"key", "sha256", "size"}.
    artifacts: dict[str, dict[str, Any]]
    provenance: dict[str, Any]
    source_file_count: int
