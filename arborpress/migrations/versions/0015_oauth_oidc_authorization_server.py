"""Add OAuth authorization server, OIDC subjects and signing keys.

Revision ID: 0015_oauth_oidc_authorization_server
Revises: 0014_oidc_provider_lifecycle
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_oauth_oidc_authorization_server"
down_revision: str | None = "0014_oidc_provider_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_server_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "oauth_clients",
        sa.Column("client_id", sa.String(96), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("client_type", sa.String(16), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=True),
        sa.Column("redirect_uris", sa.Text(), nullable=False),
        sa.Column("allowed_scopes", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "client_type IN ('public', 'confidential')", name="ck_oauth_client_type"
        ),
    )
    op.create_table(
        "oauth_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "client_id",
            sa.String(96),
            sa.ForeignKey("oauth_clients.client_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("granted_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("user_id", "client_id", name="uq_oauth_grant_user_client"),
    )
    op.create_index("ix_oauth_grants_user_id", "oauth_grants", ["user_id"])
    op.create_index("ix_oauth_grants_client_id", "oauth_grants", ["client_id"])
    op.create_table(
        "oauth_authorization_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "client_id",
            sa.String(96),
            sa.ForeignKey("oauth_clients.client_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("oauth_grants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("redirect_uri", sa.String(2048), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(256), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_oauth_authorization_codes_client_id", "oauth_authorization_codes", ["client_id"]
    )
    op.create_index(
        "ix_oauth_authorization_codes_grant_id", "oauth_authorization_codes", ["grant_id"]
    )
    op.create_index(
        "ix_oauth_authorization_codes_user_id", "oauth_authorization_codes", ["user_id"]
    )
    op.create_index(
        "ix_oauth_authorization_codes_expires_at", "oauth_authorization_codes", ["expires_at"]
    )
    op.create_table(
        "oauth_token_families",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("oauth_grants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "client_id",
            sa.String(96),
            sa.ForeignKey("oauth_clients.client_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_oauth_token_families_grant_id", "oauth_token_families", ["grant_id"])
    op.create_index("ix_oauth_token_families_client_id", "oauth_token_families", ["client_id"])
    op.create_index("ix_oauth_token_families_user_id", "oauth_token_families", ["user_id"])
    op.create_index("ix_oauth_token_families_expires_at", "oauth_token_families", ["expires_at"])
    op.create_table(
        "oauth_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("token_type", sa.String(16), nullable=False),
        sa.Column(
            "family_id",
            sa.String(36),
            sa.ForeignKey("oauth_token_families.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_oauth_tokens_family_id", "oauth_tokens", ["family_id"])
    op.create_index("ix_oauth_tokens_expires_at", "oauth_tokens", ["expires_at"])
    op.create_table(
        "oidc_subjects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("subject", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", name="uq_oidc_subject_user"),
    )
    op.create_table(
        "oidc_signing_keys",
        sa.Column("kid", sa.String(64), primary_key=True),
        sa.Column("private_key_enc", sa.LargeBinary(), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("retire_after", sa.DateTime(), nullable=True),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_oidc_signing_keys_is_current", "oidc_signing_keys", ["is_current"])


def downgrade() -> None:
    op.drop_index("ix_oidc_signing_keys_is_current", table_name="oidc_signing_keys")
    op.drop_table("oidc_signing_keys")
    op.drop_table("oidc_subjects")
    op.drop_index("ix_oauth_tokens_expires_at", table_name="oauth_tokens")
    op.drop_index("ix_oauth_tokens_family_id", table_name="oauth_tokens")
    op.drop_table("oauth_tokens")
    op.drop_index("ix_oauth_token_families_user_id", table_name="oauth_token_families")
    op.drop_index("ix_oauth_token_families_expires_at", table_name="oauth_token_families")
    op.drop_index("ix_oauth_token_families_client_id", table_name="oauth_token_families")
    op.drop_index("ix_oauth_token_families_grant_id", table_name="oauth_token_families")
    op.drop_table("oauth_token_families")
    op.drop_index("ix_oauth_authorization_codes_expires_at", table_name="oauth_authorization_codes")
    op.drop_index("ix_oauth_authorization_codes_user_id", table_name="oauth_authorization_codes")
    op.drop_index("ix_oauth_authorization_codes_grant_id", table_name="oauth_authorization_codes")
    op.drop_index("ix_oauth_authorization_codes_client_id", table_name="oauth_authorization_codes")
    op.drop_table("oauth_authorization_codes")
    op.drop_index("ix_oauth_grants_client_id", table_name="oauth_grants")
    op.drop_index("ix_oauth_grants_user_id", table_name="oauth_grants")
    op.drop_table("oauth_grants")
    op.drop_table("oauth_clients")
    op.drop_table("oidc_server_settings")
