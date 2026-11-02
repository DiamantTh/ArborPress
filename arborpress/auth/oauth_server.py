"""OAuth 2.0/OIDC provider primitives and opaque-token lifecycle.

OAuth protocol cryptography and JWT serialization use Authlib's JOSE stack
(joserfc); this module owns ArborPress persistence and policy only.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import import_key
from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.models.oidc import (
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthGrant,
    OAuthToken,
    OAuthTokenFamily,
    OIDCServerSettings,
    OIDCSigningKey,
    OIDCSubject,
)

SUPPORTED_SCOPES = frozenset(
    {
        "openid",
        "profile",
        "posts:read",
        "posts:write",
        "comments:read",
        "comments:write",
        "media:read",
        "media:write",
    }
)
ACCESS_TTL = timedelta(minutes=8)
REFRESH_TTL = timedelta(days=30)
REFRESH_FAMILY_TTL = timedelta(days=90)
CODE_TTL = timedelta(minutes=3)
TOKEN_ACCESS = "access"  # noqa: S105 - stored token class, never credential material
TOKEN_REFRESH = "refresh"  # noqa: S105 - stored token class, never credential material


class OAuthError(ValueError):
    """A safe, client-visible OAuth error code."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fernet() -> Fernet:
    root = get_settings().web.secret_key.get_secret_value().encode()
    key = hashlib.sha256(b"arborpress-oidc-provider-signing-key-v1\0" + root).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def configured_issuer() -> str:
    """The OP issuer is explicit infrastructure config, never request-derived."""
    issuer = get_settings().web.base_url.strip().rstrip("/")
    parts = urlsplit(issuer)
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise OAuthError("server_error")
    return issuer


async def server_state(db: AsyncSession, *, require_enabled: bool = True) -> OIDCServerSettings:
    row = await db.get(OIDCServerSettings, 1)
    issuer = configured_issuer()
    if row is None:
        if require_enabled:
            raise OAuthError("server_error")
        row = OIDCServerSettings(id=1, issuer=issuer, enabled=False)
        db.add(row)
        await db.flush()
    if row.issuer != issuer:
        # Issuer is an identity boundary; fail closed instead of silently moving IDs.
        raise OAuthError("server_error")
    if require_enabled and not row.enabled:
        raise OAuthError("server_error")
    return row


def validate_redirects(raw: list[str]) -> list[str]:
    if not raw or len(raw) > 20:
        raise OAuthError("invalid_redirect_uri")
    result: list[str] = []
    for item in raw:
        value = item.strip()
        parts = urlsplit(value)
        if (
            not value
            or "*" in value
            or not parts.scheme
            or not parts.netloc
            or parts.username
            or parts.password
            or parts.fragment
        ):
            raise OAuthError("invalid_redirect_uri")
        local = parts.hostname in {"localhost", "127.0.0.1", "::1"}
        if parts.scheme != "https" and not local:
            raise OAuthError("invalid_redirect_uri")
        if len(value) > 2048 or value in result:
            raise OAuthError("invalid_redirect_uri")
        result.append(value)
    return result


async def create_signing_key(db: AsyncSession, *, rotate: bool = False) -> OIDCSigningKey:
    now = _now()
    current = (
        (
            await db.execute(
                select(OIDCSigningKey).where(OIDCSigningKey.is_current.is_(True)).with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if current and not rotate:
        return current[0]
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    for item in current:
        item.is_current = False
        item.retire_after = now + timedelta(days=1)
        # Retain only the public verification material during the overlap.
        item.private_key_enc = b""
    row = OIDCSigningKey(
        kid=secrets.token_urlsafe(18),
        private_key_enc=_fernet().encrypt(private_pem),
        public_key_pem=public_pem,
        is_current=True,
    )
    db.add(row)
    await db.flush()
    return row


def private_key(row: OIDCSigningKey) -> bytes:
    try:
        return _fernet().decrypt(row.private_key_enc)
    except InvalidToken as exc:
        raise OAuthError("server_error") from exc


async def make_id_token(
    db: AsyncSession,
    *,
    user_id: str,
    client_id: str,
    scopes: str,
    nonce: str | None,
) -> str:
    key = await current_key(db)
    subject = await stable_subject(db, user_id)
    from arborpress.models.user import User

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise OAuthError("invalid_grant")
    now = int(datetime.now(UTC).timestamp())
    payload = {
        "iss": (await server_state(db)).issuer,
        "sub": subject,
        "aud": client_id,
        "iat": now,
        "exp": now + 300,
        "auth_time": now,
    }
    if nonce:
        payload["nonce"] = nonce
    if "profile" in scopes.split():
        payload.update(name=user.display_name, preferred_username=user.username)
    return jwt.encode(
        {"alg": "RS256", "kid": key.kid, "typ": "JWT"},
        payload,
        import_key(private_key(key), key_type="RSA"),
    )


async def current_key(db: AsyncSession) -> OIDCSigningKey:
    row = await db.scalar(
        select(OIDCSigningKey).where(OIDCSigningKey.is_current.is_(True)).limit(1)
    )
    if row is None:
        row = await create_signing_key(db)
    return row


async def jwks(db: AsyncSession) -> dict[str, Any]:
    from joserfc.jwk import import_key

    rows = (
        (
            await db.execute(
                select(OIDCSigningKey).where(
                    (OIDCSigningKey.is_current.is_(True)) | (OIDCSigningKey.retire_after > _now())
                )
            )
        )
        .scalars()
        .all()
    )
    keys = []
    for row in rows:
        key = import_key(row.public_key_pem, key_type="RSA")
        data = key.as_dict(private=False)
        data.update(kid=row.kid, use="sig", alg="RS256")
        keys.append(data)
    return {"keys": keys}


async def stable_subject(db: AsyncSession, user_id: str) -> str:
    row = await db.scalar(select(OIDCSubject).where(OIDCSubject.user_id == user_id))
    if row is None:
        row = OIDCSubject(id=str(uuid.uuid4()), user_id=user_id, subject=secrets.token_urlsafe(24))
        db.add(row)
        await db.flush()
    return row.subject


async def issue_code(
    db: AsyncSession,
    *,
    client: OAuthClient,
    grant: OAuthGrant,
    user_id: str,
    redirect_uri: str,
    scopes: list[str],
    challenge: str,
    nonce: str | None,
) -> str:
    code = secrets.token_urlsafe(40)
    db.add(
        OAuthAuthorizationCode(
            id=str(uuid.uuid4()),
            code_hash=digest(code),
            client_id=client.client_id,
            grant_id=grant.id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scopes=" ".join(scopes),
            code_challenge=challenge,
            nonce=nonce,
            expires_at=_now() + CODE_TTL,
        )
    )
    await db.flush()
    return code


async def _save_token(
    db: AsyncSession, family: OAuthTokenFamily, kind: str, scopes: str, ttl: timedelta
) -> str:
    token = secrets.token_urlsafe(40)
    db.add(
        OAuthToken(
            id=str(uuid.uuid4()),
            token_hash=digest(token),
            token_type=kind,
            family_id=family.id,
            scopes=scopes,
            expires_at=_now() + ttl,
        )
    )
    await db.flush()
    return token


async def token_response(
    db: AsyncSession,
    *,
    user_id: str,
    client_id: str,
    grant: OAuthGrant,
    scopes: str,
    nonce: str | None = None,
) -> dict[str, Any]:
    family = OAuthTokenFamily(
        id=str(uuid.uuid4()),
        grant_id=grant.id,
        client_id=client_id,
        user_id=user_id,
        expires_at=_now() + REFRESH_FAMILY_TTL,
    )
    db.add(family)
    await db.flush()
    access = await _save_token(db, family, TOKEN_ACCESS, scopes, ACCESS_TTL)
    refresh = await _save_token(db, family, TOKEN_REFRESH, scopes, REFRESH_TTL)
    response = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
        "refresh_token": refresh,
        "scope": scopes,
    }
    if "openid" in scopes.split():
        response["id_token"] = await make_id_token(
            db, user_id=user_id, client_id=client_id, scopes=scopes, nonce=nonce
        )
    return response


async def consume_bearer(
    db: AsyncSession, token: str
) -> tuple[OAuthToken, OAuthTokenFamily, OAuthGrant] | None:
    row = await db.scalar(
        select(OAuthToken).where(
            OAuthToken.token_hash == digest(token),
            OAuthToken.token_type == TOKEN_ACCESS,
            OAuthToken.revoked_at.is_(None),
            OAuthToken.expires_at > _now(),
        )
    )
    if row is None:
        return None
    family = await db.get(OAuthTokenFamily, row.family_id)
    if family is None or family.revoked_at is not None:
        return None
    grant = await db.get(OAuthGrant, family.grant_id)
    client = await db.get(OAuthClient, family.client_id)
    from arborpress.models.user import User

    user = await db.get(User, family.user_id)
    if (
        grant is None
        or grant.revoked_at is not None
        or client is None
        or not client.enabled
        or user is None
        or not user.is_active
        or not set(row.scopes.split()) <= set(grant.scopes.split())
    ):
        return None
    return row, family, grant


async def rotate_refresh(
    db: AsyncSession,
    raw: str,
    client_id: str,
    requested_scopes: list[str] | None = None,
) -> dict[str, Any]:
    token_hash = digest(raw)
    row = await db.scalar(
        select(OAuthToken)
        .where(OAuthToken.token_hash == token_hash, OAuthToken.token_type == TOKEN_REFRESH)
        .with_for_update()
    )
    if row is None:
        raise OAuthError("invalid_grant")
    family = await db.get(OAuthTokenFamily, row.family_id, with_for_update=True)
    grant = await db.get(OAuthGrant, family.grant_id, with_for_update=True) if family else None
    client = await db.get(OAuthClient, client_id)
    if family is None or grant is None or client is None or family.client_id != client_id:
        raise OAuthError("invalid_grant")
    if row.consumed_at is not None:
        family.revoked_at = _now()
        await db.execute(
            update(OAuthToken).where(OAuthToken.family_id == family.id).values(revoked_at=_now())
        )
        await db.commit()
        raise OAuthError("invalid_grant")
    if (
        row.revoked_at is not None
        or row.expires_at <= _now()
        or family.expires_at <= _now()
        or family.revoked_at is not None
        or grant.revoked_at is not None
        or not client.enabled
    ):
        raise OAuthError("invalid_grant")
    user = await db.get(
        __import__("arborpress.models.user", fromlist=["User"]).User, family.user_id
    )
    if user is None or not user.is_active:
        raise OAuthError("invalid_grant")
    token_scopes = set(row.scopes.split())
    if not token_scopes <= set(grant.scopes.split()):
        raise OAuthError("invalid_grant")
    selected_scopes = token_scopes if requested_scopes is None else set(requested_scopes)
    if not selected_scopes or not selected_scopes <= token_scopes:
        raise OAuthError("invalid_scope")
    now = _now()
    claimed = cast(
        CursorResult[Any],
        await db.execute(
            update(OAuthToken)
            .where(
                OAuthToken.id == row.id,
                OAuthToken.consumed_at.is_(None),
                OAuthToken.revoked_at.is_(None),
            )
            .values(consumed_at=now)
        ),
    )
    if claimed.rowcount != 1:
        family.revoked_at = now
        await db.execute(
            update(OAuthToken).where(OAuthToken.family_id == family.id).values(revoked_at=now)
        )
        await db.commit()
        raise OAuthError("invalid_grant")
    scopes_value = " ".join(sorted(selected_scopes))
    access = await _save_token(db, family, TOKEN_ACCESS, scopes_value, ACCESS_TTL)
    refresh = await _save_token(db, family, TOKEN_REFRESH, scopes_value, REFRESH_TTL)
    response = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
        "refresh_token": refresh,
        "scope": scopes_value,
    }
    if "openid" in selected_scopes:
        response["id_token"] = await make_id_token(
            db, user_id=family.user_id, client_id=client_id, scopes=scopes_value, nonce=None
        )
    return response


def verify_pkce(verifier: str, challenge: str) -> bool:
    if not (43 <= len(verifier) <= 128) or any(
        ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        for ch in verifier
    ):
        return False
    actual = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return secrets.compare_digest(actual, challenge)
