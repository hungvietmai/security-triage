"""Record the analysis family of each unit written by a composite (multi-CWE) scan.

Existing rows keep NULL: a scan with a single profile has one family, which follows from the
profile recorded on the scan, so no stored row is rewritten.
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("location_units", sa.Column("analysis_family", sa.String(48), nullable=True))
    op.create_index("ix_location_units_analysis_family", "location_units", ["analysis_family"])


def downgrade() -> None:
    op.drop_index("ix_location_units_analysis_family", table_name="location_units")
    op.drop_column("location_units", "analysis_family")
