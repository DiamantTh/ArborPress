"""Persistence and secret protection for SMTP transport profiles."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.models.mail import SMTPProfile

_PROFILE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class SMTPProfileError(ValueError):
    """An SMTP profile is invalid or its stored secret cannot be read."""


def _fernet() -> Fernet:
    root = get_settings().web.secret_key.get_secret_value().encode()
    key = hashlib.sha256(b"arborpress:smtp-profile-secret:v1\0" + root).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def validate_profile_data(data: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(data.get("id", "transactional"))
    if not _PROFILE_ID.fullmatch(profile_id):
        raise SMTPProfileError("Invalid SMTP profile id.")
    transport = str(data.get("transport", "implicit_tls"))
    if transport not in {"implicit_tls", "starttls"}:
        raise SMTPProfileError("SMTP transport must be implicit_tls or starttls.")
    host = str(data.get("host", "")).strip()
    from_address = str(data.get("from_address", "")).strip()
    if not host or any(ch in host for ch in "\r\n/\\@") or "://" in host:
        raise SMTPProfileError("SMTP host must be a hostname or IP address, not a URL/path.")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        try:
            import idna

            host = idna.encode(host.rstrip("."), uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise SMTPProfileError("SMTP host is not a valid IDNA hostname.") from exc
    from arborpress.mail.smtp import validate_address

    try:
        from_address = validate_address(from_address)
        if data.get("reply_to"):
            validate_address(str(data["reply_to"]))
    except ValueError as exc:
        raise SMTPProfileError(str(exc)) from exc
    port = int(data.get("port", 465 if transport == "implicit_tls" else 587))
    timeout = int(data.get("timeout_seconds", 20))
    if not 1 <= port <= 65535 or not 1 <= timeout <= 120:
        raise SMTPProfileError("SMTP port or timeout is out of range.")
    for field in ("display_name", "from_name", "reply_to"):
        value = data.get(field)
        if value is not None and any(ch in str(value) for ch in "\r\n"):
            raise SMTPProfileError(f"{field} must not contain line breaks.")
    return {
        "id": profile_id,
        "display_name": str(data.get("display_name") or profile_id)[:128],
        "host": host,
        "port": port,
        "transport": transport,
        "username": (str(data.get("username") or "").strip() or None),
        "secret": data.get("secret") or None,
        "from_address": from_address,
        "from_name": (str(data.get("from_name") or "").strip() or None),
        "envelope_domain": _validate_domain(data.get("envelope_domain")),
        "reply_to": (str(data.get("reply_to") or "").strip() or None),
        "enabled": bool(data.get("enabled", True)),
        "timeout_seconds": timeout,
        "max_connections": max(1, min(20, int(data.get("max_connections", 1)))),
    }


def _validate_domain(value: object) -> str | None:
    domain = str(value or "").strip().rstrip(".")
    if not domain:
        return None
    if any(ch in domain for ch in "\r\n/@\\"):
        raise SMTPProfileError("Envelope sender domain is invalid.")
    try:
        import idna

        return idna.encode(domain, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise SMTPProfileError("Envelope sender domain is invalid.") from exc


async def save_profile(session: AsyncSession, data: dict[str, Any]) -> SMTPProfile:
    values = validate_profile_data(data)
    secret = values.pop("secret")
    result = await session.execute(select(SMTPProfile).where(SMTPProfile.id == values["id"]))
    row = result.scalar_one_or_none()
    if row is None:
        row = SMTPProfile(**values)
        session.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
    if secret is not None:
        row.secret_enc = _fernet().encrypt(str(secret).encode())
    await session.flush()
    return row


def profile_transport_data(row: SMTPProfile) -> dict[str, Any]:
    secret: str | None = None
    if row.secret_enc:
        try:
            secret = _fernet().decrypt(row.secret_enc).decode()
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise SMTPProfileError("SMTP profile secret cannot be decrypted.") from exc
    return {
        "id": row.id,
        "display_name": row.display_name,
        "host": row.host,
        "port": row.port,
        "transport": row.transport,
        "username": row.username,
        "password": secret,
        "from_address": row.from_address,
        "from_name": row.from_name,
        "envelope_domain": row.envelope_domain,
        "reply_to": row.reply_to,
        "enabled": row.enabled,
        "timeout_seconds": row.timeout_seconds,
    }


def safe_profile_data(row: SMTPProfile) -> dict[str, Any]:
    return {
        "id": row.id,
        "display_name": row.display_name,
        "host": row.host,
        "port": row.port,
        "transport": row.transport,
        "auth_configured": row.username is not None,
        "has_secret": row.secret_enc is not None,
        "from_address": row.from_address,
        "from_name": row.from_name,
        "envelope_domain": row.envelope_domain,
        "reply_to": row.reply_to,
        "enabled": row.enabled,
        "timeout_seconds": row.timeout_seconds,
    }
