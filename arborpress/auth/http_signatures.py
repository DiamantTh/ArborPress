"""Strict legacy ActivityPub HTTP Signatures and local signing primitives.

This module intentionally supports the widely deployed Cavage-style
``rsa-sha256`` format. RFC 9421 inputs are rejected explicitly until an
established structured-fields implementation is added; they are never
misinterpreted as a weaker legacy signature.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.federation.remote import resolve_remote_key

_SKEW_SECONDS = 300
_PARAM_RE = re.compile(r'\s*([A-Za-z][A-Za-z0-9_-]*)="([^"\r\n]*)"\s*')
_HEADER_NAME_RE = re.compile(r"^[a-z0-9-]+$")


@dataclass(frozen=True)
class SignatureResult:
    valid: bool
    reason: str
    actor_uri: str | None = None
    key_id: str | None = None


def _parse_signature_header(value: str) -> dict[str, str] | None:
    fields: dict[str, str] = {}
    for item in value.split(","):
        match = _PARAM_RE.fullmatch(item)
        if not match:
            return None
        name, content = match.groups()
        name = name.lower()
        if name in fields:
            return None
        fields[name] = content
    return fields


def _build_legacy_base(
    names: list[str], headers: dict[str, str], method: str, path: str
) -> bytes | None:
    lines: list[str] = []
    for name in names:
        if name == "(request-target)":
            lines.append(f"(request-target): {method.lower()} {path}")
        elif name in headers:
            lines.append(f"{name}: {headers[name].strip()}")
        else:
            return None
    return "\n".join(lines).encode("utf-8")


def verify_legacy_signature_with_pem(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    pem: str,
    now: float | None = None,
) -> tuple[bool, str]:
    """Verify the cryptographic and request/body binding of a legacy signature."""
    normalized = {key.lower(): value for key, value in headers.items()}
    raw_header = normalized.get("signature")
    if not raw_header:
        return False, "missing_signature"
    params = _parse_signature_header(raw_header)
    if not params:
        return False, "malformed_signature"
    if params.get("algorithm", "").lower() != "rsa-sha256":
        return False, "unsupported_signature_algorithm"
    key_id = params.get("keyid", "")
    signature_text = params.get("signature", "")
    names = [name.lower() for name in params.get("headers", "").split()]
    if not key_id or not signature_text or not names or len(names) != len(set(names)):
        return False, "malformed_signature"
    if any(name != "(request-target)" and not _HEADER_NAME_RE.fullmatch(name) for name in names):
        return False, "invalid_signed_header_name"
    required = {"(request-target)", "host", "date"}
    if method.upper() == "POST" or body:
        required.add("digest")
    if not required.issubset(names):
        return False, "required_component_not_covered"
    if not normalized.get("host") or not normalized.get("date"):
        return False, "required_header_missing"
    try:
        timestamp = parsedate_to_datetime(normalized["date"]).timestamp()
    except TypeError, ValueError, OverflowError:
        return False, "invalid_date"
    if abs((time.time() if now is None else now) - timestamp) > _SKEW_SECONDS:
        return False, "stale_date"

    if "digest" in required:
        match = re.fullmatch(r"SHA-256=([A-Za-z0-9+/]+={0,2})", normalized.get("digest", ""))
        if not match:
            return False, "invalid_digest"
        expected = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        if not __import__("hmac").compare_digest(match.group(1), expected):
            return False, "digest_mismatch"

    base = _build_legacy_base(names, normalized, method, path)
    if base is None:
        return False, "signed_header_missing"
    try:
        signature = base64.b64decode(signature_text, validate=True)
        public_key = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            return False, "unsafe_public_key"
        public_key.verify(signature, base, padding.PKCS1v15(), hashes.SHA256())
    except Exception:  # malformed key/signature and invalid signature are equivalent to caller
        return False, "signature_invalid"
    return True, "ok"


async def verify_request_signature(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    db: AsyncSession,
    federation_settings: dict[str, Any],
) -> SignatureResult:
    normalized = {key.lower(): value for key, value in headers.items()}
    if (
        normalized.get("signature-input")
        or normalized.get("signature")
        and normalized["signature"].startswith("sig1=")
    ):
        return SignatureResult(False, "rfc9421_not_supported")
    parsed = _parse_signature_header(normalized.get("signature", ""))
    if not parsed:
        return SignatureResult(False, "missing_or_malformed_signature")
    key_id = parsed.get("keyid", "")
    from arborpress.federation.security import validate_remote_url_syntax

    try:
        validate_remote_url_syntax(key_id)
    except ValueError:
        return SignatureResult(False, "invalid_key_id")
    resolved = await resolve_remote_key(db, key_id, federation_settings)
    if resolved is None:
        return SignatureResult(False, "remote_key_unavailable", key_id=key_id)
    owner, pem = resolved
    valid, reason = verify_legacy_signature_with_pem(
        method=method, path=path, headers=normalized, body=body, pem=pem
    )
    if not valid and reason == "signature_invalid":
        # A remote actor may have rotated the key behind a stable key ID. Make
        # exactly one guarded refresh and retry; never accept a mismatched owner.
        refreshed = await resolve_remote_key(db, key_id, federation_settings, force_refresh=True)
        if refreshed is not None and refreshed[0] == owner and refreshed[1] != pem:
            owner, pem = refreshed
            valid, reason = verify_legacy_signature_with_pem(
                method=method, path=path, headers=normalized, body=body, pem=pem
            )
    return SignatureResult(valid, reason, owner if valid else None, key_id)


async def verify_http_signature(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    *,
    db: AsyncSession | None = None,
    federation_settings: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Compatibility wrapper around the strict verifier (no unsafe network fallback)."""
    if db is None or federation_settings is None:
        return False, "verification_context_required"
    result = await verify_request_signature(
        method=method,
        path=path,
        headers=headers,
        body=body,
        db=db,
        federation_settings=federation_settings,
    )
    return result.valid, result.reason


async def sign_legacy_request(
    db: AsyncSession,
    actor_id: str,
    *,
    method: str,
    path: str,
    host: str,
    body: bytes = b"",
    date: str | None = None,
) -> dict[str, str]:
    """Create signed request headers without exposing the local private key."""
    from cryptography.fernet import Fernet, InvalidToken
    from sqlalchemy import select

    from arborpress.core.config import get_settings
    from arborpress.models.federation import LocalFederationActor
    from arborpress.models.user import ActorKeypair

    actor_result = await db.execute(
        select(LocalFederationActor).where(
            LocalFederationActor.id == actor_id, LocalFederationActor.enabled.is_(True)
        )
    )
    actor = actor_result.scalar_one_or_none()
    if actor is None or actor.current_keypair_id is None:
        raise ValueError("local_signing_actor_unavailable")
    key_result = await db.execute(
        select(ActorKeypair).where(ActorKeypair.id == actor.current_keypair_id)
    )
    key = key_result.scalar_one_or_none()
    config_key = get_settings().auth.actor_key_enc_key
    if key is None or config_key is None or key.algorithm != "rsa-sha256":
        raise ValueError("local_signing_key_unavailable")
    try:
        private_pem = Fernet(config_key.get_secret_value().encode()).decrypt(key.private_key_enc)
        private_key = serialization.load_pem_private_key(private_pem, password=None)
    except (InvalidToken, ValueError, TypeError) as exc:
        raise ValueError("local_signing_key_unavailable") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
        raise ValueError("local_signing_key_unsafe")
    from email.utils import formatdate

    date_value = date or formatdate(usegmt=True)
    values = {"(request-target)": f"{method.lower()} {path}", "host": host, "date": date_value}
    signed_names = ["(request-target)", "host", "date"]
    if method.upper() == "POST" or body:
        digest_value = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        values["digest"] = f"SHA-256={digest_value}"
        signed_names.append("digest")
    signing_base = "\n".join(f"{name}: {values[name]}" for name in signed_names).encode()
    signature = private_key.sign(signing_base, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.b64encode(signature).decode("ascii")
    sig = (
        f'keyId="{key.key_id_url}",algorithm="rsa-sha256",'
        f'headers="{" ".join(signed_names)}",signature="{signature_b64}"'
    )
    result = {"Host": host, "Date": date_value, "Signature": sig}
    if "digest" in values:
        result["Digest"] = values["digest"]
    return result
