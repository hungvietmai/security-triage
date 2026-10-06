import uuid
from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.models import Identity


class SourceSnapshot(Identity, Base):
    """An immutable source archive in object storage. Upload is not implemented yet."""

    __tablename__ = "source_snapshots"
    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="ck_snapshot_size"),
        CheckConstraint("file_count >= 0", name="ck_snapshot_file_count"),
        CheckConstraint(
            "status IN ('uploading', 'validating', 'ready', 'failed')",
            name="ck_snapshot_status",
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    bucket: Mapped[str] = mapped_column(String(255))
    object_key: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    file_count: Mapped[int | None]
    manifest_key: Mapped[str | None] = mapped_column(Text)
    source_kind: Mapped[str | None] = mapped_column(String(32))
    repository_url: Mapped[str | None] = mapped_column(Text)
    resolved_commit: Mapped[str | None] = mapped_column(String(128))
    ecosystem: Mapped[str | None] = mapped_column(String(32))
    package_name: Mapped[str | None] = mapped_column(Text)
    package_version: Mapped[str | None] = mapped_column(String(128))
    artifact_url: Mapped[str | None] = mapped_column(Text)
    source_subdirectory: Mapped[str | None] = mapped_column(Text)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64))
    provenance_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="uploading")
    error_message: Mapped[str | None] = mapped_column(Text)
