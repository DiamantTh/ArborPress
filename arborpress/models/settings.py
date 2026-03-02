"""SiteSetting – laufzeitveränderliche Einstellungen in der Datenbank.

Speichert alle nicht-infrastrukturellen Konfigurationswerte.
Jede Sektion (mail, comments, captcha, theme, …) ist eine Zeile:
  key  = "captcha"
  value = '{"default_type": "custom", "custom_questions": [...]}'

Infrastruktur-Einstellungen (DB-URL, HTTP-Port, Secret-Key, Auth-TTL, Logging)
verbleiben in config.toml – sie werden vor DB-Verbindung benötigt.
"""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from arborpress.core.db import Base


class SiteSetting(Base):
    """Eine Einstellungssektion (JSON-Blob)."""

    __tablename__ = "site_settings"

    # z.B. "mail", "captcha", "comments", "theme", "federation", "general"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)

    # JSON-kodiertes dict mit den Einstellungen dieser Sektion
    value: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
