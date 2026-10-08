"""Name snapshots by source coordinate with a provenance kind; record scan result versions."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("source_snapshots", sa.Column("provenance_kind", sa.String(32), nullable=True))
    op.add_column("source_snapshots", sa.Column("source_coordinate", sa.Text(), nullable=True))
    op.create_check_constraint(
        "ck_snapshot_provenance_kind",
        "source_snapshots",
        "provenance_kind IS NULL OR "
        "provenance_kind IN ('publisher_verified', 'pinned_manifest', 'tofu')",
    )
    op.create_unique_constraint(
        "uq_snapshot_coordinate", "source_snapshots", ["project_id", "source_coordinate"]
    )
    op.add_column("scans", sa.Column("reconciler_version", sa.String(80), nullable=True))
    op.add_column("scans", sa.Column("policy_version", sa.String(80), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "policy_version")
    op.drop_column("scans", "reconciler_version")
    op.drop_constraint("uq_snapshot_coordinate", "source_snapshots", type_="unique")
    op.drop_constraint("ck_snapshot_provenance_kind", "source_snapshots", type_="check")
    op.drop_column("source_snapshots", "source_coordinate")
    op.drop_column("source_snapshots", "provenance_kind")
