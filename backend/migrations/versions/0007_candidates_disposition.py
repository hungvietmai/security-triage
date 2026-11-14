"""Record review candidates and the disposition of each unit assessment."""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("location_units", sa.Column("candidate_key", sa.String(160), nullable=True))
    op.create_index("ix_location_units_candidate_key", "location_units", ["candidate_key"])
    op.add_column(
        "unit_assessments",
        sa.Column("disposition", sa.String(16), nullable=False, server_default="review"),
    )
    op.create_check_constraint(
        "ck_unit_assessment_disposition",
        "unit_assessments",
        "disposition IN ('review', 'filtered')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_unit_assessment_disposition", "unit_assessments", type_="check")
    op.drop_column("unit_assessments", "disposition")
    op.drop_index("ix_location_units_candidate_key", table_name="location_units")
    op.drop_column("location_units", "candidate_key")
