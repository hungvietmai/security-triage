"""Model registry: importing this module registers every table on Base.metadata.

Alembic autogenerate and the test schema setup rely on it. Add each new
feature's models module here.
"""

from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot

__all__ = ["Finding", "Project", "Scan", "SourceSnapshot", "ToolRun"]
