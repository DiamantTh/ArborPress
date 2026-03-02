"""Benutzer- und Credential-Modelle (§2, §4)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from arborpress.core.db import Base


class AccountType(str, enum.Enum):
    """§4 – zwei klar getrennte Identitätstypen."""

    PUBLIC = "public"       # Federated / Public Account (WebFinger, ActivityPub)
    OPERATIONAL = "operational"  # Admin/Moderation – nicht extern auffindbar


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    AUTHOR = "author"
    MODERATOR = "moderator"
    VIEWER = "viewer"


class User(Base):
    """Benutzer-Konto.

    §4: PUBLIC-Konten dürfen ActivityPub-Endpunkte haben.
        OPERATIONAL-Konten haben keinen WebFinger-Eintrag.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(254), unique=True, nullable=True)
    account_type: Mapped[AccountType] = mapped_column(
        Enum(AccountType), nullable=False, default=AccountType.PUBLIC
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), nullable=False, default=UserRole.VIEWER
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # §2 Break-Glass – nur wenn explizit aktiviert
    legacy_password_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    legacy_password_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # §4 Rol-Policy-Flags
    require_uv: Mapped[bool] = mapped_column(Boolean, default=False)
    require_stepup: Mapped[bool] = mapped_column(Boolean, default=False)
    sso_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # OpenPGP §13
    pgp_public_key: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    pgp_encrypt_mail: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    credentials: Mapped[list["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    mfa_devices: Mapped[list["MFADevice"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    backup_codes: Mapped[list["BackupCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_operational(self) -> bool:
        return self.account_type == AccountType.OPERATIONAL

    def __repr__(self) -> str:
        return f"<User {self.username!r} [{self.account_type.value}/{self.role.value}]>"


class CredentialTransport(str, enum.Enum):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"


class WebAuthnCredential(Base):
    """WebAuthn-Credential eines Benutzers (§2 – multiple credentials per account)."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Label vom Benutzer vergeben – §2
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="My Key")
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    # Metadata §2
    transport: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    is_platform: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    uv_capable: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="credentials")

    __table_args__ = (UniqueConstraint("user_id", "label", name="uq_user_credential_label"),)


class MFADeviceType(str, enum.Enum):
    TOTP = "totp"
    HOTP = "hotp"
    PLUGIN = "plugin"


class MFADevice(Base):
    """MFA-Gerät (TOTP/HOTP/Plugin-Provider §3)."""

    __tablename__ = "mfa_devices"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_type: Mapped[MFADeviceType] = mapped_column(Enum(MFADeviceType), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # Encrypted secret (never bare in DB)
    secret_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Plugin-Provider-ID (wenn device_type == PLUGIN)
    plugin_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="mfa_devices")


class BackupCode(Base):
    """Einmaliger Backup-Code §2 / §3."""

    __tablename__ = "backup_codes"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="backup_codes")
