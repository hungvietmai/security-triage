"""Model registry: importing this module registers every table on Base.metadata.

Alembic autogenerate and the test schema setup rely on it. Add each new
feature's models module here.
"""

from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding

__all__ = [
    "Finding",
    "LocationUnit",
    "Project",
    "Scan",
    "SourceSnapshot",
    "ToolRun",
    "UnitAssessment",
    "UnitFinding",
]
