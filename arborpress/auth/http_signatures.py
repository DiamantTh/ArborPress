"""HTTP Signature verification for incoming ActivityPub requests (§5).

Implements cavage-http-signatures (draft-cavage-http-signatures-12),
which is the de-facto standard used by Mastodon, Pleroma, Misskey, etc.

Supported algorithms:
  - rsa-sha256  (RSA + PKCS#1v15 + SHA-256) – legacy, most common
  - ed25519     (Ed25519) – modern, growing adoption

Flow for each incoming AP inbox request:
  1. Parse `Signature:` header into its components (keyId, algorithm,
     headers list, base64 signature).
  2. Verify the `Date:` header is within ±30 s of server time
     (replay-attack protection).
  3. Verify the `Digest:` header matches SHA-256(body)
     (body-integrity check).
  4. Fetch the remote actor's public key PEM from `keyId` URL,
     using SSRF-guard from `arborpress.core.validators`.
     Results are cached for 1 hour (TTL is reset on each cache hit).
  5. Reconstruct the signed string from the listed headers.
  6. Verify the signature with the fetched public key.

Public API:
  verify_http_signature(method, path, headers, body)
    → (ok: bool, reason: str)

  invalidate_key_cache(key_id=None)
    → clears one or all cached public keys
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import time

log = logging.getLogger("arborpress.http_signatures")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SKEW_SECONDS: int = 30        # max allowed Date header drift
_CACHE_TTL:    int = 3600      # public-key cache TTL (seconds)
_FETCH_TIMEOUT: float = 6.0    # HTTP timeout for key fetching

# keyId → (expire_monotonic, pem_str)
_KEY_CACHE: dict[str, tuple[float, str]] = {}

_SIG_RE = re.compile(r'(\w+)="([^"]*)"')

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def invalidate_key_cache(key_id: str | None = None) -> None:
    """Clear the in-memory public-key cache."""
    if key_id:
        _KEY_CACHE.pop(key_id, None)
    else:
        _KEY_CACHE.clear()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_sig_header(header: str) -> dict[str, str]:
    """Parse `Signature: keyId="...", algorithm="...", ...` into a dict."""
    return {k: v for k, v in _SIG_RE.findall(header)}


async def _fetch_public_key_pem(key_id: str) -> str | None:
    """Fetch the PEM-encoded public key for *key_id*.

    *key_id* is typically a URL like
    ``https://mastodon.social/users/alice#main-key``.
    The actor document is fetched from the base URL (without the fragment),
    then ``publicKey.publicKeyPem`` is extracted.

    Results are cached for _CACHE_TTL seconds.
    SSRF-guard: delegates to :func:`arborpress.core.validators.is_safe_external_url`.
    """
    cached = _KEY_CACHE.get(key_id)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    # SSRF guard
    from arborpress.core.validators import is_safe_external_url
    if not await is_safe_external_url(key_id):
        log.warning("AP sig: blocked SSRF attempt for key_id=%s", key_id)
        return None

    # Actor document URL (strip fragment)
    actor_url = key_id.split("#")[0]
    try:
        import httpx  # already in deps (§5 / §11)
        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(
                actor_url,
                headers={"Accept": "application/activity+json, application/ld+json"},
            )
        if r.status_code != 200:
            log.debug("AP sig: actor fetch returned %d for %s", r.status_code, actor_url)
            return None
        data: dict = r.json()
    except Exception as exc:
        log.warning("AP sig: key fetch failed for %s: %s", key_id, exc)
        return None

    # Extract publicKey block
    pub_key_block = data.get("publicKey", {})
    # Some implementations return a list
    if isinstance(pub_key_block, list):
        pub_key_block = next(
            (k for k in pub_key_block if isinstance(k, dict) and k.get("id") == key_id),
            {},
        )

    pem: str = pub_key_block.get("publicKeyPem", "") if isinstance(pub_key_block, dict) else ""
    if not pem:
        log.debug("AP sig: no publicKeyPem found for keyId=%s", key_id)
        return None

    _KEY_CACHE[key_id] = (time.monotonic() + _CACHE_TTL, pem)
    return pem


def _build_signed_string(
    headers_list: list[str],
    request_headers: dict[str, str],
    method: str,
    path: str,
) -> str:
    """Reconstruct the string that was signed by the remote server.

    ``(request-target)`` is a pseudo-header: ``<method> <path>``.
    All header names are lower-cased per the spec.
    """
    parts: list[str] = []
    for h in headers_list:
        if h == "(request-target)":
            parts.append(f"(request-target): {method.lower()} {path}")
        else:
            val = request_headers.get(h.lower(), "")
            parts.append(f"{h.lower()}: {val}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def verify_http_signature(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> tuple[bool, str]:
    """Verify an HTTP Signature on an incoming ActivityPub request.

    Args:
        method:  HTTP method (e.g. ``"POST"``).
        path:    Request path including query string (e.g. ``"/ap/inbox/alice"``).
        headers: Lower-cased request headers dict.
        body:    Raw request body bytes.

    Returns:
        ``(True, "ok")`` on success.
        ``(False, reason)`` with a human-readable reason on failure.
    """
    # Normalise header keys to lower-case
    lc_headers = {k.lower(): v for k, v in headers.items()}

    sig_header = lc_headers.get("signature", "")
    if not sig_header:
        return False, "Missing Signature header"

    params = _parse_sig_header(sig_header)
    key_id    = params.get("keyId", "")
    algorithm = params.get("algorithm", "rsa-sha256").lower()
    headers_param = params.get("headers", "date").split()
    sig_b64   = params.get("signature", "")

    if not key_id or not sig_b64:
        return False, "Malformed Signature header: missing keyId or signature"

    # 1. Date header replay-attack protection
    if "date" in headers_param:
        from email.utils import parsedate_to_datetime
        date_val = lc_headers.get("date", "")
        try:
            req_ts = parsedate_to_datetime(date_val).timestamp()
            skew = abs(time.time() - req_ts)
            if skew > _SKEW_SECONDS:
                return False, f"Date header out of acceptable window ({skew:.0f}s > {_SKEW_SECONDS}s)"
        except Exception:
            return False, f"Unparseable Date header: {date_val!r}"

    # 2. Digest header body-integrity check
    if "digest" in headers_param:
        digest_val = lc_headers.get("digest", "")
        if digest_val.startswith("SHA-256="):
            expected = base64.b64encode(hashlib.sha256(body).digest()).decode()
            actual   = digest_val[8:]
            if expected != actual:
                return False, "Digest header mismatch – body integrity check failed"

    # 3. Fetch public key
    pem = await _fetch_public_key_pem(key_id)
    if pem is None:
        return False, f"Could not fetch public key for keyId={key_id!r}"

    # 4. Reconstruct signed string
    signed_string = _build_signed_string(headers_param, lc_headers, method, path)

    # 5. Verify signature
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        pub_key = load_pem_public_key(pem.encode())
        sig_bytes    = base64.b64decode(sig_b64)
        signed_bytes = signed_string.encode()

        if isinstance(pub_key, Ed25519PublicKey):
            pub_key.verify(sig_bytes, signed_bytes)
        elif isinstance(pub_key, RSAPublicKey):
            pub_key.verify(
                sig_bytes,
                signed_bytes,
                asym_padding.PKCS1v15(),
                hashes.SHA256(),
            )
        else:
            return False, f"Unsupported public key type: {type(pub_key).__name__}"

    except Exception as exc:
        return False, f"Signature verification failed: {exc}"

    log.debug("AP sig: verified OK | keyId=%s algorithm=%s", key_id, algorithm)
    return True, "ok"
