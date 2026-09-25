"""Cascade deletes down the snapshot hierarchy, add updated_at and a column-order check."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = ["projects", "source_snapshots", "scans", "tool_runs", "findings"]
# (child table, column, parent table); 0001 used PostgreSQL's default <table>_<column>_fkey names.
FOREIGN_KEYS = [
    ("source_snapshots", "project_id", "projects"),
    ("scans", "snapshot_id", "source_snapshots"),
    ("tool_runs", "scan_id", "scans"),
    ("findings", "tool_run_id", "tool_runs"),
]


def _replace_foreign_keys(ondelete: str | None) -> None:
    for table, column, parent in FOREIGN_KEYS:
        name = f"{table}_{column}_fkey"
        op.drop_constraint(name, table, type_="foreignkey")
        op.create_foreign_key(name, table, parent, [column], ["id"], ondelete=ondelete)


def upgrade() -> None:
    for table in TABLES:
        op.add_column(
            table,
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
    _replace_foreign_keys("CASCADE")
    op.create_check_constraint(
        "ck_finding_end_column_order",
        "findings",
        "end_line > start_line OR end_column >= start_column",
    )


def downgrade() -> None:
    op.drop_constraint("ck_finding_end_column_order", "findings", type_="check")
    _replace_foreign_keys(None)
    for table in reversed(TABLES):
        op.drop_column(table, "updated_at")
