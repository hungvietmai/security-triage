import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.models import JSON_VALUE, Identity


class Scan(Identity, Base):
    """One analysis request over a snapshot. Execution is not implemented yet."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')",
            name="ck_scan_status",
        ),
    )

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_snapshots.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(24), default="queued")
    config: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)


class ToolRun(Identity, Base):
    """One Semgrep or CodeQL invocation within a scan; retries get a new attempt."""

    __tablename__ = "tool_runs"
    __table_args__ = (
        UniqueConstraint("scan_id", "tool", "language", "attempt", name="uq_tool_run_attempt"),
        CheckConstraint("attempt > 0", name="ck_tool_run_attempt"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')",
            name="ck_tool_run_status",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
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
