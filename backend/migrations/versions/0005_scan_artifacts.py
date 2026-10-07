"""Record each scan's object-storage artifacts and their SHA-256 on the scan."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "artifacts",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
            # Existing scans have no artifacts; the model supplies {} for new rows.
            server_default=sa.text("'{}'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "artifacts")
