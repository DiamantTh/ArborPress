"""SiteSetting – runtime-mutable settings stored in the database.

Stores all non-infrastructure configuration values.
Each section (mail, comments, captcha, theme, …) is one row:
  key  = "captcha"
  value = '{"default_type": "custom", "custom_questions": [...]}'

Infrastructure settings (DB URL, HTTP port, secret key, auth TTL, logging)
remain in config.toml – they are required before the DB connection is made.
"""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from arborpress.core.db import Base


class SiteSetting(Base):
    """A settings section (JSON blob)."""

    __tablename__ = "site_settings"

    # e.g. "mail", "captcha", "comments", "theme", "federation", "general"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)

    # JSON-encoded dict with the settings for this section
    value: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class PortableImportReceipt(Base):
    """Idempotency record for an accepted portable content package."""

    __tablename__ = "portable_import_receipts"
    __table_args__ = (Index("ix_portable_import_bundle_hash", "bundle_hash"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    bundle_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    bundle_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_build_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    imported_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    imported_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
