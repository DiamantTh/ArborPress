"""Add independent opaque user handles for WebAuthn credentials.

Revision ID: 0018_webauthn_user_handles
Revises: 0017_search_indexes
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_webauthn_user_handles"
down_revision: str | None = "0017_search_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("webauthn_user_handle", sa.LargeBinary(64), nullable=True),
    )

    bind = op.get_bind()
    user_ids = bind.execute(sa.text("SELECT id FROM users")).scalars().all()
    for user_id in user_ids:
        bind.execute(
            sa.text("UPDATE users SET webauthn_user_handle = :handle WHERE id = :user_id"),
            {"handle": secrets.token_bytes(64), "user_id": user_id},
        )

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("users") as batch:
            batch.alter_column(
                "webauthn_user_handle",
                existing_type=sa.LargeBinary(64),
                nullable=False,
            )
            batch.create_unique_constraint(
                "uq_users_webauthn_user_handle", ["webauthn_user_handle"]
            )
            batch.create_check_constraint(
                "ck_users_webauthn_user_handle_length",
                "length(webauthn_user_handle) = 64",
            )
    else:
        op.alter_column(
            "users",
            "webauthn_user_handle",
            existing_type=sa.LargeBinary(64),
            nullable=False,
        )
        op.create_unique_constraint(
            "uq_users_webauthn_user_handle", "users", ["webauthn_user_handle"]
        )
        op.create_check_constraint(
            "ck_users_webauthn_user_handle_length",
            "users",
            "length(webauthn_user_handle) = 64",
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("users") as batch:
            batch.drop_constraint(
                "ck_users_webauthn_user_handle_length", type_="check"
            )
            batch.drop_constraint("uq_users_webauthn_user_handle", type_="unique")
            batch.drop_column("webauthn_user_handle")
    else:
        op.drop_constraint(
            "ck_users_webauthn_user_handle_length", "users", type_="check"
        )
        op.drop_constraint("uq_users_webauthn_user_handle", "users", type_="unique")
        op.drop_column("users", "webauthn_user_handle")
