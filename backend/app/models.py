"""Foundation schema. Scan execution and adjudication are subsequent milestones."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

JSON_VALUE = JSON().with_variant(JSONB(), "postgresql")


class Identity:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Project(Identity, Base):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(Text)


class SourceSnapshot(Identity, Base):
    __tablename__ = "source_snapshots"
    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="ck_snapshot_size"),
        CheckConstraint("file_count >= 0", name="ck_snapshot_file_count"),
        CheckConstraint(
            "status IN ('uploading', 'validating', 'ready', 'failed')",
            name="ck_snapshot_status",
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    bucket: Mapped[str] = mapped_column(String(255))
    object_key: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    file_count: Mapped[int | None]
    manifest_key: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), default="uploading")
    error_message: Mapped[str | None] = mapped_column(Text)


class Scan(Identity, Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')",
            name="ck_scan_status",
        ),
    )

    snapshot_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("source_snapshots.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    config: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)


class ToolRun(Identity, Base):
    __tablename__ = "tool_runs"
    __table_args__ = (
        UniqueConstraint("scan_id", "tool", "language", "attempt", name="uq_tool_run_attempt"),
        CheckConstraint("attempt > 0", name="ck_tool_run_attempt"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')",
            name="ck_tool_run_status",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    tool: Mapped[str] = mapped_column(String(32))
    language: Mapped[str] = mapped_column(String(32))
    attempt: Mapped[int] = mapped_column(default=1)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    tool_version: Mapped[str | None] = mapped_column(String(80))
    config: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    result_key: Mapped[str | None] = mapped_column(Text)
    log_key: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None]
    error_message: Mapped[str | None] = mapped_column(Text)


class Finding(Identity, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tool_run_id", "result_index", name="uq_finding_result"),
        CheckConstraint("result_index >= 0", name="ck_finding_result_index"),
        CheckConstraint("start_line >= 1", name="ck_finding_start_line"),
        CheckConstraint("end_line >= start_line", name="ck_finding_end_line"),
        CheckConstraint("start_column >= 1", name="ck_finding_start_column"),
        CheckConstraint("end_column >= 1", name="ck_finding_end_column"),
    )

    tool_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tool_runs.id"), index=True)
    result_index: Mapped[int]
    rule_id: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    start_line: Mapped[int | None]
    end_line: Mapped[int | None]
    start_column: Mapped[int | None]
    end_column: Mapped[int | None]
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(32))
    cwe_ids: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    rule_help_url: Mapped[str | None] = mapped_column(Text)
    classification_source: Mapped[str | None] = mapped_column(String(32))
    mapping_version: Mapped[str | None] = mapped_column(String(80))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
