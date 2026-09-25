import uuid
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.models import JSON_VALUE, Identity


class Finding(Identity, Base):
    """One normalized SARIF result. Locations are nullable: not every result has one."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tool_run_id", "result_index", name="uq_finding_result"),
        CheckConstraint("result_index >= 0", name="ck_finding_result_index"),
        CheckConstraint("start_line >= 1", name="ck_finding_start_line"),
        CheckConstraint("end_line >= start_line", name="ck_finding_end_line"),
        CheckConstraint("start_column >= 1", name="ck_finding_start_column"),
        CheckConstraint("end_column >= 1", name="ck_finding_end_column"),
        CheckConstraint(
            "end_line > start_line OR end_column >= start_column",
            name="ck_finding_end_column_order",
        ),
    )

    tool_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tool_runs.id", ondelete="CASCADE"), index=True
    )
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
