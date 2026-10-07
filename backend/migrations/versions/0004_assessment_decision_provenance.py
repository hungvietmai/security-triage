"""Store the winning decision and exact policy/rule-claims provenance per assessment.

Replaces 0003's tool flags and free-form rule_claims, which the evidence record already
carries. No writer has used unit_assessments yet, so no rows need migrating.
"""

from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

STRING_COLUMNS = [
    ("decision_id", 48),
    ("policy_id", 80),
    ("policy_sha256", 64),
    ("spec_sha256", 64),
    ("rule_claims_version", 80),
    ("rule_claims_sha256", 64),
]


def _json_value() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.drop_column("unit_assessments", "semgrep_flag")
    op.drop_column("unit_assessments", "codeql_flag")
    op.drop_column("unit_assessments", "rule_claims")
    for name, length in STRING_COLUMNS:
        op.add_column("unit_assessments", sa.Column(name, sa.String(length), nullable=False))
    op.add_column(
        "unit_assessments", sa.Column("matched_conditions", _json_value(), nullable=False)
    )


def downgrade() -> None:
    op.drop_column("unit_assessments", "matched_conditions")
    for name, _ in reversed(STRING_COLUMNS):
        op.drop_column("unit_assessments", name)
    # Existing rows (written by the scan worker) get placeholder values, then the defaults go,
    # leaving 0003's schema exactly. Downgrading is lossy: the decision provenance is dropped.
    restored: list[tuple[str, sa.types.TypeEngine[Any], str]] = [
        ("rule_claims", _json_value(), "'{}'"),
        ("codeql_flag", sa.Boolean(), "false"),
        ("semgrep_flag", sa.Boolean(), "false"),
    ]
    for name, column_type, placeholder in restored:
        op.add_column(
            "unit_assessments",
            sa.Column(name, column_type, nullable=False, server_default=sa.text(placeholder)),
        )
        op.alter_column("unit_assessments", name, server_default=None)
