"""VERP envelope generation and minimal delivery-status updates."""

from __future__ import annotations

import secrets
import string

from sqlalchemy import select

_TOKEN_CHARS = string.ascii_letters + string.digits


def new_verp_token() -> str:
    """Generate an opaque delivery token; it contains no recipient/user data."""
    return "".join(secrets.choice(_TOKEN_CHARS) for _ in range(32))


def verp_address(token: str, domain: str) -> str:
    if len(token) != 32 or any(ch not in _TOKEN_CHARS for ch in token):
        raise ValueError("Invalid VERP token.")
    normalized = domain.strip().rstrip(".").encode("idna").decode("ascii")
    if not normalized or any(ch in normalized for ch in "\r\n@"):
        raise ValueError("Invalid VERP domain.")
    return f"bounce+{token}@{normalized}"


async def apply_dsn(
    session: object,
    *,
    token: str,
    status: str,
    enhanced_code: str | None = None,
) -> bool:
    """Record only normalized DSN status metadata; callers must not persist raw DSN."""
    from arborpress.models.mail import MailQueue

    if status not in {"delivered", "delayed", "bounced"}:
        raise ValueError("Unsupported delivery status.")
    if enhanced_code is not None and (len(enhanced_code) > 32 or "\n" in enhanced_code):
        raise ValueError("Invalid enhanced status code.")
    row = (
        await session.execute(  # type: ignore[attr-defined]
            select(MailQueue).where(MailQueue.verp_token == token)
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    row.dsn_status = status
    row.dsn_enhanced_code = enhanced_code
    await session.flush()  # type: ignore[attr-defined]
    return True
