"""Add bounded idempotency receipts for OAuth resource writes.

Revision ID: 0016_oauth_resource_idempotency
Revises: 0015_oauth_oidc_authorization_server
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_oauth_resource_idempotency"
down_revision: str | None = "0015_oauth_oidc_authorization_server"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oauth_idempotency_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "client_id",
            sa.String(96),
            sa.ForeignKey("oauth_clients.client_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(24), nullable=False),
        sa.Column("resource_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "client_id", "user_id", "key_hash", name="uq_oauth_idempotency_scope"
        ),
    )
    op.create_index("ix_oauth_idempotency_keys_client_id", "oauth_idempotency_keys", ["client_id"])
    op.create_index("ix_oauth_idempotency_keys_user_id", "oauth_idempotency_keys", ["user_id"])
    op.create_index(
        "ix_oauth_idempotency_keys_expires_at", "oauth_idempotency_keys", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_oauth_idempotency_keys_expires_at", table_name="oauth_idempotency_keys")
    op.drop_index("ix_oauth_idempotency_keys_user_id", table_name="oauth_idempotency_keys")
    op.drop_index("ix_oauth_idempotency_keys_client_id", table_name="oauth_idempotency_keys")
    op.drop_table("oauth_idempotency_keys")
