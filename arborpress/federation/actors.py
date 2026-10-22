"""Local ActivityPub actor identity and key lifecycle primitives."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.federation.policy import canonical_origin
from arborpress.models.federation import FederationInstanceIdentity, LocalFederationActor
from arborpress.models.user import AccountType, ActorKeypair, User


def _fernet() -> Fernet:
    secret = get_settings().auth.actor_key_enc_key
    if secret is None:
        raise RuntimeError("actor_key_encryption_not_configured")
    return Fernet(secret.get_secret_value().encode())


def generate_rsa_keypair(*, key_size: int = 3072) -> tuple[str, bytes]:
    if key_size < 2048:
        raise ValueError("RSA keys must be at least 2048 bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_pem = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return public_pem, _fernet().encrypt(private_pem)


async def enable_local_actor(db: AsyncSession, user: User) -> LocalFederationActor:
    """Create an explicitly enabled actor once; preserve its URI across renames."""
    if user.account_type != AccountType.PUBLIC or not user.is_active or user.federation_opt_out:
        raise ValueError("user_not_eligible_for_federation")
    origin = canonical_origin()
    identity_result = await db.execute(
        select(FederationInstanceIdentity).where(FederationInstanceIdentity.id == 1)
    )
    identity = identity_result.scalar_one_or_none()
    if identity is not None and identity.canonical_origin != origin:
        raise RuntimeError("canonical_origin_change_requires_explicit_migration")
    if identity is None:
        db.add(FederationInstanceIdentity(id=1, canonical_origin=origin))
        await db.flush()
    existing_result = await db.execute(
        select(LocalFederationActor).where(LocalFederationActor.user_id == str(user.id))
    )
    existing = existing_result.scalar_one_or_none()
    if existing is not None and existing.preferred_username != user.username:
        # A handle change is an identity migration, not a side effect of a
        # routine enable/re-enable operation. Keep the stable actor mapping.
        raise RuntimeError("preferred_username_change_requires_explicit_migration")
    actor_uri = existing.actor_uri if existing else f"{origin}/ap/actor/{user.username}"
    key_result = await db.execute(select(ActorKeypair).where(ActorKeypair.user_id == str(user.id)))
    keypair = key_result.scalar_one_or_none()
    reusable_key = False
    if keypair is not None and keypair.algorithm == "rsa-sha256":
        try:
            existing_public_key = serialization.load_pem_public_key(
                keypair.public_key_pem.encode("ascii")
            )
            reusable_key = (
                isinstance(existing_public_key, rsa.RSAPublicKey)
                and existing_public_key.key_size >= 2048
            )
        except ValueError, TypeError, UnicodeEncodeError:
            reusable_key = False
    if not reusable_key:
        public_pem, encrypted_private = generate_rsa_keypair()
        if keypair is None:
            keypair = ActorKeypair(
                user_id=str(user.id),
                key_id_url="",
                public_key_pem="",
                private_key_enc=b"",
                algorithm="rsa-sha256",
            )
            db.add(keypair)
        keypair.algorithm = "rsa-sha256"
        keypair.public_key_pem = public_pem
        keypair.private_key_enc = encrypted_private
    assert keypair is not None
    keypair.key_id_url = f"{actor_uri}#main-key"
    await db.flush()
    if existing:
        existing.enabled = True
        existing.current_keypair_id = keypair.id
        await db.flush()
        return existing
    actor = LocalFederationActor(
        user_id=str(user.id),
        actor_uri=actor_uri,
        preferred_username=user.username,
        enabled=True,
        current_keypair_id=keypair.id,
    )
    db.add(actor)
    await db.flush()
    return actor


async def disable_local_actor(db: AsyncSession, actor: LocalFederationActor) -> None:
    actor.enabled = False
    actor.updated_at = datetime.now(UTC).replace(tzinfo=None)
    await db.flush()


async def rotate_local_actor_key(
    db: AsyncSession, actor_id: str
) -> tuple[LocalFederationActor, datetime]:
    """Atomically replace an actor's current key and retain only retired public metadata.

    The key ID remains the actor's stable ``#main-key`` identifier. Remote caches
    must refresh the actor document after a verification failure; ArborPress
    never signs with the retired key after this transaction commits.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from arborpress.models.federation import FederationActorKeyHistory
    from arborpress.models.user import ActorKeypair

    actor = (
        await db.execute(
            select(LocalFederationActor)
            .where(LocalFederationActor.id == actor_id, LocalFederationActor.enabled.is_(True))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if actor is None or actor.current_keypair_id is None:
        raise ValueError("enabled_actor_with_current_key_required")
    current = (
        await db.execute(
            select(ActorKeypair)
            .where(ActorKeypair.id == actor.current_keypair_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if current is None or current.algorithm != "rsa-sha256":
        raise ValueError("current_actor_rsa_key_required")

    old_public = serialization.load_pem_public_key(current.public_key_pem.encode("ascii"))
    fingerprint = hashlib.sha256(
        old_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    now = datetime.now(UTC).replace(tzinfo=None)
    created_at = current.rotated_at or current.created_at or now
    db.add(
        FederationActorKeyHistory(
            actor_id=actor.id,
            key_id=current.key_id_url,
            public_key_pem=current.public_key_pem,
            fingerprint_sha256=fingerprint,
            created_at=created_at,
            retired_at=now,
        )
    )
    public_pem, encrypted_private = generate_rsa_keypair()
    current.public_key_pem = public_pem
    current.private_key_enc = encrypted_private
    current.rotated_at = now
    actor.updated_at = now
    await db.flush()
    return actor, now
