"""Bounded OIDC discovery, provider metadata and ID-token verification."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import socket
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

from arborpress.core.network import response_peer_address
from arborpress.models.user import ExternalIdentity

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 64 * 1024
TIMEOUT = httpx.Timeout(connect=5, read=10, write=5, pool=5)


class OIDCError(ValueError):
    """OIDC provider data or authentication failed closed."""


def _https_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise OIDCError("invalid_provider_url") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise OIDCError("https_provider_url_required")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return url
    if not address.is_global:
        raise OIDCError("blocked_provider_address")
    return url


async def validate_provider_url(url: str) -> tuple[str, ...]:
    """Require public HTTPS DNS results for each server-side provider request."""
    _https_url(url)
    parsed = urlsplit(url)
    try:
        literal = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        try:
            async with asyncio.timeout(5):
                rows = await asyncio.get_running_loop().getaddrinfo(
                    parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
                )
        except (OSError, TimeoutError) as exc:
            raise OIDCError("provider_dns_failed") from exc
        addresses = tuple(dict.fromkeys(row[4][0] for row in rows))
    else:
        addresses = (str(literal),)
    if not addresses:
        raise OIDCError("provider_dns_empty")
    for item in addresses:
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            raise OIDCError("provider_dns_invalid") from exc
        if not address.is_global:
            raise OIDCError("blocked_provider_address")
    return addresses


async def request_json(
    url: str,
    *,
    method: str = "GET",
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    auth: httpx.Auth | tuple[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Fetch one bounded JSON response; redirects are rejected to prevent SSRF hops."""
    await validate_provider_url(url)
    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
            headers={"User-Agent": "ArborPress-OIDC/1", "Accept": "application/json"},
        ) as client:
            async with client.stream(
                method, url, data=data, headers=headers, auth=auth
            ) as response:
                if 300 <= response.status_code < 400:
                    raise OIDCError("provider_redirect_rejected")
                response.raise_for_status()
                peer = response_peer_address(response)
                if peer:
                    address = ipaddress.ip_address(peer)
                    if not address.is_global:
                        raise OIDCError("blocked_provider_peer")
                if "json" not in response.headers.get("content-type", "").lower():
                    raise OIDCError("provider_json_required")
                length = response.headers.get("content-length")
                if length and int(length) > MAX_RESPONSE_BYTES:
                    raise OIDCError("provider_response_too_large")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise OIDCError("provider_response_too_large")
        result = json.loads(body)
    except OIDCError:
        raise
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        raise OIDCError("provider_request_failed") from exc
    if not isinstance(result, dict):
        raise OIDCError("provider_json_invalid")
    return result


async def discover(
    provider: dict[str, Any], *, transport: httpx.AsyncBaseTransport | None = None
) -> dict[str, Any]:
    issuer = str(provider.get("issuer", "")).rstrip("/")
    if not issuer:
        raise OIDCError("provider_issuer_required")
    _https_url(issuer)
    discovery_url = provider.get("discovery_url") or f"{issuer}/.well-known/openid-configuration"
    metadata = await request_json(str(discovery_url), transport=transport)
    if metadata.get("issuer") != provider.get("issuer"):
        raise OIDCError("issuer_mismatch")
    required = ("authorization_endpoint", "token_endpoint", "jwks_uri")
    if any(not isinstance(metadata.get(key), str) for key in required):
        raise OIDCError("provider_metadata_incomplete")
    if not metadata.get("userinfo_endpoint") and provider.get("require_userinfo", False):
        raise OIDCError("userinfo_endpoint_missing")
    for key in required + (("userinfo_endpoint",) if metadata.get("userinfo_endpoint") else ()):
        await validate_provider_url(str(metadata[key]))
    response_types = metadata.get("response_types_supported")
    if response_types is not None and (
        not isinstance(response_types, list) or "code" not in response_types
    ):
        raise OIDCError("authorization_code_unsupported")
    algorithms = metadata.get("id_token_signing_alg_values_supported")
    if algorithms is not None and (
        not isinstance(algorithms, list) or "RS256" not in algorithms
    ):
        raise OIDCError("rs256_unsupported")
    auth_methods = metadata.get("token_endpoint_auth_methods_supported")
    if auth_methods is not None and (
        not isinstance(auth_methods, list)
        or any(not isinstance(method, str) for method in auth_methods)
    ):
        raise OIDCError("token_auth_metadata_invalid")
    return metadata


def verify_id_token(
    token: str,
    *,
    metadata: dict[str, Any],
    issuer: str,
    client_id: str,
    nonce: str,
    jwks: dict[str, Any],
    now: float | None = None,
) -> dict[str, Any]:
    """Verify an RS256 ID token against only the supplied trusted provider JWKS."""
    if not isinstance(token, str) or len(token.encode()) > MAX_TOKEN_BYTES:
        raise OIDCError("id_token_invalid")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OIDCError("id_token_header_invalid") from exc
    if (
        header.get("alg") != "RS256"
        or not isinstance(header.get("kid"), str)
        or not header["kid"]
        or len(header["kid"]) > 256
        or header.get("crit")
        or header.get("b64") is False
    ):
        raise OIDCError("id_token_algorithm_rejected")
    # jku/x5u are deliberately ignored: keys only come from configured discovery.
    keys = jwks.get("keys")
    if not isinstance(keys, list) or len(keys) > 100:
        raise OIDCError("jwks_invalid")
    matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == header["kid"]]
    if len(matches) != 1 or matches[0].get("kty") != "RSA" or matches[0].get("use", "sig") != "sig":
        raise OIDCError("signing_key_not_found")
    try:
        key = RSAAlgorithm.from_jwk(json.dumps(matches[0]))
        if not isinstance(key, RSAPublicKey):
            raise OIDCError("signing_key_type_rejected")
        if key.key_size < 2048:
            raise OIDCError("signing_key_too_weak")
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
            leeway=60,
            options={"require": ["iss", "sub", "aud", "exp", "iat"]},
        )
    except jwt.PyJWTError as exc:
        raise OIDCError("id_token_verification_failed") from exc
    audiences = claims.get("aud")
    if isinstance(audiences, list) and len(audiences) > 1 and claims.get("azp") != client_id:
        raise OIDCError("authorized_party_mismatch")
    if "azp" in claims and claims["azp"] != client_id:
        raise OIDCError("authorized_party_mismatch")
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or len(claims["sub"]) > 255:
        raise OIDCError("subject_invalid")
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(
        claims["nonce"], nonce
    ):
        raise OIDCError("nonce_mismatch")
    return claims


async def verify_id_token_from_provider(
    token: str,
    *,
    metadata: dict[str, Any],
    issuer: str,
    client_id: str,
    nonce: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Fetch trusted JWKS and perform at most one refresh for an unknown kid."""
    jwks_url = endpoint_url(metadata, "jwks_uri")
    jwks = await request_json(jwks_url, transport=transport)
    try:
        return verify_id_token(
            token, metadata=metadata, issuer=issuer, client_id=client_id,
            nonce=nonce, jwks=jwks,
        )
    except OIDCError as exc:
        if str(exc) != "signing_key_not_found":
            raise
    refreshed = await request_json(jwks_url, transport=transport)
    return verify_id_token(
        token, metadata=metadata, issuer=issuer, client_id=client_id,
        nonce=nonce, jwks=refreshed,
    )


def endpoint_url(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str):
        raise OIDCError("provider_endpoint_missing")
    return _https_url(urljoin(str(metadata.get("issuer", "")) + "/", value))


def merge_userinfo(
    id_token_claims: dict[str, Any], userinfo: dict[str, Any]
) -> dict[str, Any]:
    """Use UserInfo only as a bounded profile supplement to verified ID claims."""
    if userinfo.get("sub") != id_token_claims.get("sub"):
        raise OIDCError("userinfo_subject_mismatch")
    result = dict(id_token_claims)
    for name in ("email", "email_verified", "name", "preferred_username", "nickname"):
        if name in userinfo:
            result[name] = userinfo[name]
    return result


async def mark_identity_login(db: Any, identity_id: str, user_id: str) -> None:
    """Record only a completed login, and only against its owning local user."""
    identity = (await db.execute(select(ExternalIdentity).where(
        ExternalIdentity.id == identity_id,
        ExternalIdentity.user_id == user_id,
    ))).scalar_one_or_none()
    if identity is not None:
        identity.last_login_at = datetime.now(UTC).replace(tzinfo=None)
