"""Persistent OIDC provider operations and privacy-minimal diagnostics."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from arborpress.core.db import Base


class OIDCProvider(Base):
    """Operator-managed OIDC provider; client secrets are encrypted at rest."""

    __tablename__ = "oidc_providers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    discovery_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    client_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default='["openid"]')
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    auto_create: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    discovery_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    jwks_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error_class: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class OIDCFailureDaily(Base):
    """Daily count by provider and bounded failure class; contains no request identity."""

    __tablename__ = "oidc_failure_daily"
    __table_args__ = (
        UniqueConstraint("day", "provider_id", "failure_class", name="uq_oidc_failure_daily"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    failure_class: Mapped[str] = mapped_column(String(40), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
