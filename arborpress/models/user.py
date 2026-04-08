"""Benutzer- und Credential-Modelle (§2, §4)."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

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


class AccountType(enum.StrEnum):
    """§4 – two clearly separated identity types."""

    PUBLIC = "public"       # Federated / Public Account (WebFinger, ActivityPub)
    OPERATIONAL = "operational"  # Admin/Moderation – nicht extern auffindbar


class UserRole(enum.StrEnum):
    ADMIN = "admin"
    EDITOR = "editor"
    AUTHOR = "author"
    MODERATOR = "moderator"
    VIEWER = "viewer"


class User(Base):
    """User account.

    §4: PUBLIC accounts may have ActivityPub endpoints.
        OPERATIONAL accounts have no WebFinger entry.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str | None] = mapped_column(String(254), unique=True, nullable=True)
    account_type: Mapped[AccountType] = mapped_column(
        Enum(AccountType), nullable=False, default=AccountType.PUBLIC
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), nullable=False, default=UserRole.VIEWER
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # §2 Break-Glass – only when explicitly enabled
    legacy_password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    legacy_password_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # §4 Role-policy flags
    require_uv: Mapped[bool] = mapped_column(Boolean, default=False)
    require_stepup: Mapped[bool] = mapped_column(Boolean, default=False)
    sso_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # §5 Federation – opt-out pro Account (auch wenn Instanz federiert)
    federation_opt_out: Mapped[bool] = mapped_column(Boolean, default=False)
    # §2 Account lockout (credential-stuffing protection)
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Public profile (§4 PUBLIC accounts, optional)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    website: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    credentials: Mapped[list[WebAuthnCredential]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    mfa_devices: Mapped[list[MFADevice]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    backup_codes: Mapped[list[BackupCode]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # OpenPGP §13 – multiple keys per user possible
    pgp_keys: Mapped[list[UserPGPKey]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # §5 Federation – keypair for HTTP signatures, max. 1 per user
    actor_keypair: Mapped[ActorKeypair | None] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    # §5 Federation – follower/following relationships
    followers: Mapped[list[Follower]] = relationship(
        "Follower",
        primaryjoin="and_(Follower.local_user_id == User.id, Follower.direction == 'inbound')",
        back_populates="local_user",
        cascade="all, delete-orphan",
        overlaps="following",
    )
    following: Mapped[list[Follower]] = relationship(
        "Follower",
        primaryjoin="and_(Follower.local_user_id == User.id, Follower.direction == 'outbound')",
        back_populates="local_user",
        cascade="all, delete-orphan",
        overlaps="followers",
    )
    # §2 DB-backed sessions
    sessions: Mapped[list[UserSession]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_operational(self) -> bool:
        return self.account_type == AccountType.OPERATIONAL

    def __repr__(self) -> str:
        return f"<User {self.username!r} [{self.account_type.value}/{self.role.value}]>"


class CredentialTransport(enum.StrEnum):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"


class WebAuthnCredential(Base):
    """WebAuthn credential for a user (§2 – multiple credentials per account)."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Label assigned by the user – §2
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="My Key")
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    # Metadata §2
    transport: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_platform: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uv_capable: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="credentials")

    __table_args__ = (UniqueConstraint("user_id", "label", name="uq_user_credential_label"),)


class MFADeviceType(enum.StrEnum):
    TOTP = "totp"
    HOTP = "hotp"
    PLUGIN = "plugin"


class MFADevice(Base):
    """MFA device (TOTP/HOTP/plugin provider §3)."""

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
    # Plugin provider ID (if device_type == PLUGIN)
    plugin_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="mfa_devices")

    # Each label must be unique per user
    __table_args__ = (UniqueConstraint("user_id", "label", name="uq_user_mfa_label"),)


class BackupCode(Base):
    """One-time backup code §2 / §3."""

    __tablename__ = "backup_codes"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped[User] = relationship(back_populates="backup_codes")


class UserPGPKey(Base):
    """OpenPGP key for a user (§13 – multiple keys possible).

    A user can register multiple OpenPGP keypairs, e.g.:
      - private keypair (for personal mail)
      - professional keypair (for press contact)

    Roles (non-exclusive – one key can have both roles):
      use_for_signing      → outgoing mails for this user are signed with it
      use_for_encryption   → incoming mails to this user are encrypted with it

    Primary signing key (is_primary_signing=True):
      → There can always be only one; when setting a new primary, the old
        one is automatically set to False (application-layer logic).
    """

    __tablename__ = "user_pgp_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Human-readable label (e.g. "Private", "Press", "Work")
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="My Key")
    # ASCII-armored public key (BEGIN PGP PUBLIC KEY BLOCK)
    public_key_armored: Mapped[str] = mapped_column(Text, nullable=False)
    # Fingerprint for fast comparison / display (e.g. 40-char HEX)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    # Roles
    use_for_signing: Mapped[bool] = mapped_column(Boolean, default=True)
    use_for_encryption: Mapped[bool] = mapped_column(Boolean, default=True)
    # Only one key per user can be the primary signing key
    is_primary_signing: Mapped[bool] = mapped_column(Boolean, default=False)
    # Expiry date (read from the key – optional)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="pgp_keys")

    __table_args__ = (
        # A fingerprint may only appear once per user
        UniqueConstraint("user_id", "fingerprint", name="uq_user_pgp_fingerprint"),
    )


# ---------------------------------------------------------------------------
# §5 Federation – Actor keypair (HTTP signatures)
# ---------------------------------------------------------------------------


class ActorKeypair(Base):
    """Ed25519 keypair for ActivityPub HTTP signatures (§5) – per account.

    Only relevant when allow_per_account_federation is enabled. Generated
    automatically by the web app on demand – no manual intervention needed.
    Algorithm: Ed25519 (default) or rsa-sha256 (legacy via admin UI).
    Encrypted with Fernet, KEK from auth.actor_key_enc_key.
    Rotation: arborpress federation keygen (generates a new keypair)
    """

    __tablename__ = "actor_keypairs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    # Key ID URL (e.g. https://example.com/ap/actor/alice#main-key)
    key_id_url: Mapped[str] = mapped_column(String(512), nullable=False)
    # PEM-encoded public key (RSA ≥ 2048 or Ed25519)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    # Encrypted private key (bytes, Fernet-encrypted)
    private_key_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Algorithm: "ed25519" (default, widely supported) or "rsa-sha256" (legacy)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="ed25519")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="actor_keypair")


class InstanceKeypair(Base):
    """Ed25519 keypair for the blog actor (§5 – instance level).

    The ArborPress instance itself is the primary ActivityPub actor
    (comparable to the WordPress ActivityPub plugin). This key is located
    at `https://<base>/ap/actor#main-key`.

    Singleton table (id = 1 always). Per-account keys → ActorKeypair.
    Encryption: Fernet, KEK from auth.actor_key_enc_key.
    Rotation: arborpress federation keygen --force
    """

    __tablename__ = "instance_keypair"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    # Key ID URL e.g. https://example.com/ap/actor#main-key
    key_id_url: Mapped[str] = mapped_column(String(512), nullable=False)
    # PEM-encoded public key
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    # Fernet-encrypted private key
    private_key_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # "ed25519" (default) or "rsa-sha256" (legacy)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="ed25519")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# §5 Federation – Follower / Following
# ---------------------------------------------------------------------------


class FollowerDirection(enum.StrEnum):
    INBOUND  = "inbound"   # Someone follows this account (follower)
    OUTBOUND = "outbound"  # This account follows someone (following)


class FollowerState(enum.StrEnum):
    PENDING  = "pending"   # Follow request not yet confirmed
    ACCEPTED = "accepted"  # Follow active
    REJECTED = "rejected"  # Declined / blocked
    UNDONE   = "undone"    # Unfollow – historical entry retained


class Follower(Base):
    """ActivityPub Follow relationship (§5).

    Stores both inbound (someone follows us) and outbound
    (we follow someone) follow relationships.

    For inbound:  local_user_id = the followed local account
                  remote_actor_uri = URI of the follower
    For outbound: local_user_id = the following local account
                  remote_actor_uri = URI of the followed account
    """

    __tablename__ = "ap_followers"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    local_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Full URI of the remote actor (e.g. https://mastodon.social/users/bob)
    remote_actor_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Display name (optional, cached from actor document)
    remote_display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Inbox URI of the remote actor (for sends)
    remote_inbox_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    direction: Mapped[FollowerDirection] = mapped_column(
        Enum(FollowerDirection), nullable=False
    )
    state: Mapped[FollowerState] = mapped_column(
        Enum(FollowerState), nullable=False, default=FollowerState.PENDING
    )

    # ID of the Follow activity (for Undo/Accept reference)
    activity_id: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    local_user: Mapped[User] = relationship(
        "User",
        primaryjoin="Follower.local_user_id == User.id",
        overlaps="followers,following",
    )

    __table_args__ = (
        # A remote actor can follow a local account only once per direction
        UniqueConstraint(
            "local_user_id", "remote_actor_uri", "direction",
            name="uq_follower_local_remote_dir",
        ),
    )


# ---------------------------------------------------------------------------
# §2 DB-backed Sessions
# ---------------------------------------------------------------------------


class UserSession(Base):
    """Server-side session – supplements the signed Quart cookie.

    The cookie only contains the ``session_id`` (UUID). All metadata
    (IP, user agent, TLS, expiry) is stored here.
    Invalidation: ``is_valid = False`` + clear session cookie.
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # TLS-Status: True wenn X-Forwarded-Proto == "https" oder direktes HTTPS
    is_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # CLI-Sitzung: gesetzt wenn via arborpress-CLI angelegt
    is_cli: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Kann durch Admin oder Nutzer widerrufen werden
    is_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at.replace(
            tzinfo=UTC if self.expires_at.tzinfo is None else self.expires_at.tzinfo
        )

