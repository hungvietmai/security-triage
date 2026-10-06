"""Persistence models for reconciled location units and policy assessments."""

import uuid
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.models import JSON_VALUE, Identity


class LocationUnit(Identity, Base):
    """One versioned canonical reconciliation unit within a scan."""

    __tablename__ = "location_units"
    __table_args__ = (
        UniqueConstraint("scan_id", "unit_key", name="uq_location_unit_key"),
        CheckConstraint("start_line >= 1", name="ck_location_unit_start_line"),
        CheckConstraint("end_line >= start_line", name="ck_location_unit_end_line"),
        CheckConstraint("start_column >= 1", name="ck_location_unit_start_column"),
        CheckConstraint("end_column >= 1", name="ck_location_unit_end_column"),
        CheckConstraint(
            "end_line > start_line OR end_column >= start_column",
            name="ck_location_unit_end_column_order",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    unit_key: Mapped[str] = mapped_column(String(160))
    path: Mapped[str | None] = mapped_column(Text)
    start_line: Mapped[int | None]
    end_line: Mapped[int | None]
    start_column: Mapped[int | None]
    end_column: Mapped[int | None]
    sink_kind: Mapped[str | None] = mapped_column(String(160))
    argument_role: Mapped[str | None] = mapped_column(String(32))
    mapping_status: Mapped[str] = mapped_column(String(48))
    reconciler_version: Mapped[str] = mapped_column(String(80))
    locator_version: Mapped[str] = mapped_column(String(80))


class UnitFinding(Identity, Base):
    """One raw finding linked to one versioned reconciliation unit."""

    __tablename__ = "unit_findings"
    __table_args__ = (
        UniqueConstraint("unit_id", "finding_id", name="uq_unit_finding"),
    )

    unit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("location_units.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    match_rule: Mapped[str | None] = mapped_column(String(48))


class UnitAssessment(Identity, Base):
    """One priority-policy assessment for a versioned reconciliation unit."""

    __tablename__ = "unit_assessments"
    __table_args__ = (
        UniqueConstraint("unit_id", "policy_version", name="uq_unit_assessment_policy"),
        CheckConstraint(
            "priority IN ('P1', 'P2', 'U', 'P3', 'P4')",
            name="ck_unit_assessment_priority",
        ),
    )

    unit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("location_units.id", ondelete="CASCADE"), index=True
    )
    semgrep_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    codeql_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_claims: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    priority: Mapped[str] = mapped_column(String(4))
    reason: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(String(80))
