"""Persistent OIDC provider operations and privacy-minimal diagnostics."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
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


class OIDCServerSettings(Base):
    """Single canonical issuer identity and server enable switch."""

    __tablename__ = "oidc_server_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class OAuthClient(Base):
    """Locally registered OAuth client with exact redirect and scope allowlists."""

    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    client_type: Mapped[str] = mapped_column(String(16), nullable=False)
    secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_scopes: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class OAuthGrant(Base):
    """User consent for one client and its current scope set."""

    __tablename__ = "oauth_grants"
    __table_args__ = (UniqueConstraint("user_id", "client_id", name="uq_oauth_grant_user_client"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    scopes: Mapped[str] = mapped_column(Text, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class OAuthAuthorizationCode(Base):
    """Hashed, one-time authorization code bound to client, redirect and PKCE."""

    __tablename__ = "oauth_authorization_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id", ondelete="CASCADE"), nullable=False, index=True
    )
    grant_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_grants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[str | None] = mapped_column(String(256), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class OAuthTokenFamily(Base):
    __tablename__ = "oauth_token_families"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    grant_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_grants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC).replace(tzinfo=None) + timedelta(days=90),
        index=True,
    )


class OAuthToken(Base):
    """Opaque access/refresh token metadata; only a SHA-256 digest is stored."""

    __tablename__ = "oauth_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    token_type: Mapped[str] = mapped_column(String(16), nullable=False)
    family_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_token_families.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scopes: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class OIDCSubject(Base):
    """Immutable pairwise-independent local OIDC subject identifier."""

    __tablename__ = "oidc_subjects"
    __table_args__ = (UniqueConstraint("user_id", name="uq_oidc_subject_user"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    subject: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class OIDCSigningKey(Base):
    """OIDC-only encrypted signing key; separate from ActivityPub actor keys."""

    __tablename__ = "oidc_signing_keys"

    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    private_key_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    retire_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)


class OAuthIdempotencyKey(Base):
    """Short-lived idempotency receipt for retried OAuth resource writes."""

    __tablename__ = "oauth_idempotency_keys"
    __table_args__ = (
        UniqueConstraint("client_id", "user_id", "key_hash", name="uq_oauth_idempotency_scope"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        ForeignKey("oauth_clients.client_id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(24), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
