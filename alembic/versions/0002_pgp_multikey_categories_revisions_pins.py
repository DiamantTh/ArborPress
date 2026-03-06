"""Multi-PGP, Kategorien, Revisionen, Pins, Featured, Zugangstokens.

Revision ID: 0002
Revises:     0001
Create Date: 2026-03-06

Änderungen:
  users:
    + bio TEXT NULL
    + website VARCHAR(512) NULL
    ─ pgp_public_key  (Daten werden nach user_pgp_keys migriert)
    ─ pgp_encrypt_mail
  user_pgp_keys: neue Tabelle (mehrere OpenPGP-Schlüssel pro Nutzer)
  posts:
    + is_pinned         BOOL DEFAULT FALSE
    + is_featured       BOOL DEFAULT FALSE
    + noindex           BOOL DEFAULT FALSE
    + reading_time_min  INT  DEFAULT 1
  categories: neue Tabelle (hierarchisch)
  post_categories: neue Pivot-Tabelle
  post_revisions: neue Tabelle (Versionsverlauf + Diff)
  post_access_tokens: neue Tabelle (mehrere Passwörter pro Post)
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    # ------------------------------------------------------------------
    # users: bio + website
    # ------------------------------------------------------------------
    op.add_column("users", sa.Column("bio", sa.Text, nullable=True))
    op.add_column("users", sa.Column("website", sa.String(512), nullable=True))

    # ------------------------------------------------------------------
    # user_pgp_keys – neue Tabelle
    # ------------------------------------------------------------------
    op.create_table(
        "user_pgp_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(128), nullable=False, server_default="Mein Schlüssel"),
        sa.Column("public_key_armored", sa.Text, nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("use_for_signing", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("use_for_encryption", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("is_primary_signing", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("user_id", "fingerprint", name="uq_user_pgp_fingerprint"),
    )
    op.create_index("ix_user_pgp_keys_user_id", "user_pgp_keys", ["user_id"])

    # pgp_public_key -> user_pgp_keys migrieren
    # (Vorhandene Schlüssel werden mit Platzhalter-Fingerprint übernommen)
    connection = bind
    users_with_pgp = connection.execute(
        sa.text(
            "SELECT id, pgp_public_key, pgp_encrypt_mail "
            "FROM users WHERE pgp_public_key IS NOT NULL"
        )
    ).fetchall()

    import uuid as _uuid
    for row in users_with_pgp:
        user_id = row[0]
        key_data = row[1]
        # Schlüsseldaten ggf. als Bytes oder String vorhanden
        if isinstance(key_data, bytes):
            try:
                armored = key_data.decode("utf-8", errors="replace")
            except Exception:
                armored = repr(key_data)
        else:
            armored = str(key_data) if key_data else ""

        if armored.strip():
            connection.execute(
                sa.text(
                    "INSERT INTO user_pgp_keys "
                    "(id, user_id, label, public_key_armored, fingerprint, "
                    " use_for_signing, use_for_encryption, is_primary_signing) "
                    "VALUES (:id, :uid, :label, :key, :fp, 1, 1, 1)"
                ),
                {
                    "id": str(_uuid.uuid4()),
                    "uid": user_id,
                    "label": "Migrierter Schlüssel",
                    "key": armored,
                    # Fingerprint kann nicht ohne GPG-Lib berechnet werden;
                    # Platzhalter – Admin soll Fingerprint manuell verifizieren
                    "fp": f"MIGRATED-{user_id[:16].upper()}",
                },
            )

    # Alte Spalten droppen
    op.drop_column("users", "pgp_public_key")
    op.drop_column("users", "pgp_encrypt_mail")

    # ------------------------------------------------------------------
    # posts: Sichtbarkeits- und Metadaten-Spalten
    # ------------------------------------------------------------------
    op.add_column("posts", sa.Column(
        "is_pinned", sa.Boolean, nullable=False, server_default="0"))
    op.add_column("posts", sa.Column(
        "is_featured", sa.Boolean, nullable=False, server_default="0"))
    op.add_column("posts", sa.Column(
        "noindex", sa.Boolean, nullable=False, server_default="0"))
    op.add_column("posts", sa.Column(
        "reading_time_min", sa.Integer, nullable=False, server_default="1"))

    # ------------------------------------------------------------------
    # categories – neue Tabelle (hierarchisch via parent_id)
    # ------------------------------------------------------------------
    op.create_table(
        "categories",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(128), unique=True, nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("parent_id", sa.Integer,
                  sa.ForeignKey("categories.id", ondelete="SET NULL"), nullable=True),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("lang", sa.String(8), nullable=True),
    )

    # ------------------------------------------------------------------
    # post_categories – Pivot posts ↔ categories
    # ------------------------------------------------------------------
    op.create_table(
        "post_categories",
        sa.Column("post_id", sa.String(36),
                  sa.ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("category_id", sa.Integer,
                  sa.ForeignKey("categories.id", ondelete="CASCADE"), primary_key=True),
    )

    # ------------------------------------------------------------------
    # post_revisions – Versionsverlauf
    # ------------------------------------------------------------------
    op.create_table(
        "post_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("post_id", sa.String(36),
                  sa.ForeignKey("posts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rev_number", sa.Integer, nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("body_md", sa.Text, nullable=False),
        sa.Column("diff_to_prev", sa.Text, nullable=True),
        sa.Column("changed_by_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("change_summary", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_post_revisions_post_id_rev",
        "post_revisions", ["post_id", "rev_number"],
    )

    # Initialrevision für alle bestehenden Posts anlegen (rev_number=1, kein Diff)
    existing_posts = connection.execute(
        sa.text("SELECT id, title, body_md FROM posts")
    ).fetchall()
    for post in existing_posts:
        connection.execute(
            sa.text(
                "INSERT INTO post_revisions "
                "(id, post_id, rev_number, title, body_md, diff_to_prev, change_summary) "
                "VALUES (:id, :pid, 1, :title, :body, NULL, 'Initiale Migration')"
            ),
            {
                "id": str(_uuid.uuid4()),
                "pid": post[0],
                "title": post[1],
                "body": post[2] or "",
            },
        )

    # ------------------------------------------------------------------
    # post_access_tokens – mehrere Passwörter pro Post
    # ------------------------------------------------------------------
    op.create_table(
        "post_access_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("post_id", sa.String(36),
                  sa.ForeignKey("posts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("token_hash", sa.String(256), nullable=False),
        sa.Column("max_uses", sa.Integer, nullable=True),
        sa.Column("use_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_post_access_tokens_post_id", "post_access_tokens", ["post_id"])


def downgrade() -> None:
    op.drop_table("post_access_tokens")
    op.drop_index("ix_post_revisions_post_id_rev", "post_revisions")
    op.drop_table("post_revisions")
    op.drop_table("post_categories")
    op.drop_table("categories")

    op.drop_column("posts", "reading_time_min")
    op.drop_column("posts", "noindex")
    op.drop_column("posts", "is_featured")
    op.drop_column("posts", "is_pinned")

    # users: Spalten wiederherstellen (Daten gehen verloren)
    op.drop_index("ix_user_pgp_keys_user_id", "user_pgp_keys")
    op.drop_table("user_pgp_keys")

    op.add_column("users", sa.Column("pgp_public_key", sa.LargeBinary, nullable=True))
    op.add_column("users", sa.Column("pgp_encrypt_mail", sa.Boolean,
                                     nullable=False, server_default="0"))
    op.drop_column("users", "website")
    op.drop_column("users", "bio")
