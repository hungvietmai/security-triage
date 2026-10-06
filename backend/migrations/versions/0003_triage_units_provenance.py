"""Persist versioned triage units, assessments, and source provenance."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

PROVENANCE_COLUMNS = [
    ("source_kind", sa.String(length=32)),
    ("repository_url", sa.Text()),
    ("resolved_commit", sa.String(length=128)),
    ("ecosystem", sa.String(length=32)),
    ("package_name", sa.Text()),
    ("package_version", sa.String(length=128)),
    ("artifact_url", sa.Text()),
    ("source_subdirectory", sa.Text()),
    ("manifest_sha256", sa.String(length=64)),
    ("provenance_verified_at", sa.DateTime(timezone=True)),
]


def _json_value() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    for name, column_type in PROVENANCE_COLUMNS:
        op.add_column("source_snapshots", sa.Column(name, column_type, nullable=True))

    op.create_table(
        "location_units",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("unit_key", sa.String(length=160), nullable=False),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("start_column", sa.Integer(), nullable=True),
        sa.Column("end_column", sa.Integer(), nullable=True),
        sa.Column("sink_kind", sa.String(length=160), nullable=True),
        sa.Column("argument_role", sa.String(length=32), nullable=True),
        sa.Column("mapping_status", sa.String(length=48), nullable=False),
        sa.Column("reconciler_version", sa.String(length=80), nullable=False),
        sa.Column("locator_version", sa.String(length=80), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("start_line >= 1", name="ck_location_unit_start_line"),
        sa.CheckConstraint("end_line >= start_line", name="ck_location_unit_end_line"),
        sa.CheckConstraint("start_column >= 1", name="ck_location_unit_start_column"),
        sa.CheckConstraint("end_column >= 1", name="ck_location_unit_end_column"),
        sa.CheckConstraint(
            "end_line > start_line OR end_column >= start_column",
            name="ck_location_unit_end_column_order",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "unit_key", name="uq_location_unit_key"),
    )
    op.create_index(op.f("ix_location_units_scan_id"), "location_units", ["scan_id"], unique=False)

    op.create_table(
        "unit_findings",
        sa.Column("unit_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("match_rule", sa.String(length=48), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["unit_id"], ["location_units.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("unit_id", "finding_id", name="uq_unit_finding"),
    )
    op.create_index(
        op.f("ix_unit_findings_finding_id"),
        "unit_findings",
        ["finding_id"],
        unique=False,
    )
    op.create_index(op.f("ix_unit_findings_unit_id"), "unit_findings", ["unit_id"], unique=False)

    op.create_table(
        "unit_assessments",
        sa.Column("unit_id", sa.Uuid(), nullable=False),
        sa.Column("semgrep_flag", sa.Boolean(), nullable=False),
        sa.Column("codeql_flag", sa.Boolean(), nullable=False),
        sa.Column("rule_claims", _json_value(), nullable=False),
        sa.Column("evidence", _json_value(), nullable=False),
        sa.Column("priority", sa.String(length=4), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.String(length=80), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "priority IN ('P1', 'P2', 'U', 'P3', 'P4')",
            name="ck_unit_assessment_priority",
        ),
        sa.ForeignKeyConstraint(["unit_id"], ["location_units.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("unit_id", "policy_version", name="uq_unit_assessment_policy"),
    )
    op.create_index(
        op.f("ix_unit_assessments_unit_id"),
        "unit_assessments",
        ["unit_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_unit_assessments_unit_id"), table_name="unit_assessments")
    op.drop_table("unit_assessments")
    op.drop_index(op.f("ix_unit_findings_unit_id"), table_name="unit_findings")
    op.drop_index(op.f("ix_unit_findings_finding_id"), table_name="unit_findings")
    op.drop_table("unit_findings")
    op.drop_index(op.f("ix_location_units_scan_id"), table_name="location_units")
    op.drop_table("location_units")

    for name, _ in reversed(PROVENANCE_COLUMNS):
        op.drop_column("source_snapshots", name)
