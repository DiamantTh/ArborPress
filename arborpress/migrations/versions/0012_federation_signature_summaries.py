"""Persist bounded federation signature-failure aggregates.

Revision ID: 0012_federation_signature_summaries
Revises: 0011_federation_operations
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_federation_signature_summaries"
down_revision: str | None = "0011_federation_operations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "federation_signature_failure_daily",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("date_bucket", sa.Date(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("failure_count", sa.Integer(), server_default="0", nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "date_bucket", "category", name="uq_fed_signature_failure_day_class"
        ),
    )
    op.create_index(
        "ix_fed_signature_failure_date", "federation_signature_failure_daily", ["date_bucket"]
    )


def downgrade() -> None:
    op.drop_index("ix_fed_signature_failure_date", table_name="federation_signature_failure_daily")
    op.drop_table("federation_signature_failure_daily")
