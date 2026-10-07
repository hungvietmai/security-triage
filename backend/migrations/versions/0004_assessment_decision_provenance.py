"""Store the winning decision and exact policy/rule-claims provenance per assessment.

Replaces 0003's tool flags and free-form rule_claims, which the evidence record already
carries. No writer has used unit_assessments yet, so no rows need migrating.
"""

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
    op.add_column("unit_assessments", sa.Column("rule_claims", _json_value(), nullable=False))
    op.add_column("unit_assessments", sa.Column("codeql_flag", sa.Boolean(), nullable=False))
    op.add_column("unit_assessments", sa.Column("semgrep_flag", sa.Boolean(), nullable=False))
