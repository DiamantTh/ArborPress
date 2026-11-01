"""Persist managed OIDC providers and bounded failure aggregates.

Revision ID: 0014_oidc_provider_lifecycle
Revises: 0013_oidc_external_identities
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_oidc_provider_lifecycle"
down_revision: str | None = "0013_oidc_external_identities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("discovery_url", sa.String(1024), nullable=True),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("client_secret_enc", sa.LargeBinary(), nullable=True),
        sa.Column("scopes", sa.Text(), nullable=False, server_default='["openid"]'),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto_create", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("discovery_status", sa.String(24), nullable=False, server_default="unknown"),
        sa.Column("jwks_status", sa.String(24), nullable=False, server_default="unknown"),
        sa.Column("last_check_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error_class", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "oidc_failure_daily",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("failure_class", sa.String(40), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("day", "provider_id", "failure_class", name="uq_oidc_failure_daily"),
    )
    op.create_index("ix_oidc_failure_daily_day", "oidc_failure_daily", ["day"])


def downgrade() -> None:
    op.drop_index("ix_oidc_failure_daily_day", table_name="oidc_failure_daily")
    op.drop_table("oidc_failure_daily")
    op.drop_table("oidc_providers")
