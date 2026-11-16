"""Persist portable package import idempotency receipts.

Revision ID: 0019_portable_import_receipts
Revises: 0018_webauthn_user_handles
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_portable_import_receipts"
down_revision: str | None = "0018_webauthn_user_handles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "portable_import_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bundle_id", sa.String(36), nullable=False, unique=True),
        sa.Column("bundle_hash", sa.String(64), nullable=False),
        sa.Column("source_build_sha", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column(
            "imported_by_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("summary", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("imported_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_portable_import_bundle_hash", "portable_import_receipts", ["bundle_hash"])


def downgrade() -> None:
    op.drop_index("ix_portable_import_bundle_hash", table_name="portable_import_receipts")
    op.drop_table("portable_import_receipts")
