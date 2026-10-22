"""Federation-specific URL, domain and bounded remote-fetch policy.

The HTTP client is centralized here: callers must not fetch ActivityPub URLs
directly. DNS is checked before every hop and the connected peer is checked
when the HTTP transport exposes it. HTTPX does not provide portable DNS
pinning, so a narrow DNS rebinding TOCTOU window remains documented.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from arborpress.core.validators import _ip_is_blocked

MAX_REMOTE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
REMOTE_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
ACTIVITY_MEDIA_TYPES = frozenset(
    {
        "application/activity+json",
        "application/ld+json",
        "application/jrd+json",
    }
)
_FETCH_SEMAPHORE = asyncio.Semaphore(8)


class FederationFetchError(ValueError):
    """A remote fetch was rejected or failed a federation safety check."""


@dataclass(frozen=True)
class RemoteResponse:
    url: str
    status_code: int
    content_type: str
    body: bytes
    headers: httpx.Headers


def normalize_domain(domain: str) -> str:
    value = domain.rstrip(".").strip().lower()
    if not value or len(value) > 253 or ":" in value or "/" in value:
        raise FederationFetchError("invalid_domain")
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise FederationFetchError("invalid_domain") from exc
    if not ascii_domain or any(not label or len(label) > 63 for label in ascii_domain.split(".")):
        raise FederationFetchError("invalid_domain")
    return ascii_domain


def validate_remote_url_syntax(url: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise FederationFetchError("invalid_url") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise FederationFetchError("https_url_required")
    if parsed.fragment or (port is not None and not 1 <= port <= 65535):
        raise FederationFetchError("invalid_url")
    host = normalize_domain(parsed.hostname) if not _is_ip(parsed.hostname) else parsed.hostname
    if _is_ip(host):
        address = ipaddress.ip_address(host)
        if _ip_is_blocked(str(address)) or not address.is_global:
            raise FederationFetchError("blocked_address")
    return host, parsed.path or "/"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def validate_remote_url(url: str) -> tuple[str, ...]:
    """Require HTTPS and resolve every address to globally routable IP space."""
    host, _ = validate_remote_url_syntax(url)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(5.0):
                infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except TimeoutError as exc:
            raise FederationFetchError("dns_timeout") from exc
        addresses = tuple(dict.fromkeys(item[4][0] for item in infos))
    else:
        addresses = (str(literal),)
    if not addresses:
        raise FederationFetchError("dns_empty")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
            if _ip_is_blocked(str(ip)) or not ip.is_global:
                raise FederationFetchError("blocked_address")
        except ValueError as exc:
            if isinstance(exc, FederationFetchError):
                raise
            raise FederationFetchError("invalid_dns_address") from exc
    return addresses


async def fetch_remote(
    url: str,
    *,
    accept: str = 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
    max_bytes: int = MAX_REMOTE_BYTES,
    allowed_types: frozenset[str] = ACTIVITY_MEDIA_TYPES,
    transport: httpx.AsyncBaseTransport | None = None,
) -> RemoteResponse:
    """Fetch a bounded ActivityPub document, rechecking each redirect hop."""
    current = url
    async with _FETCH_SEMAPHORE:
        async with httpx.AsyncClient(
            timeout=REMOTE_TIMEOUT,
            follow_redirects=False,
            verify=True,
            transport=transport,
            headers={"Accept": accept, "User-Agent": "ArborPress-Federation/1"},
        ) as client:
            for redirect_count in range(MAX_REDIRECTS + 1):
                await validate_remote_url(current)
                try:
                    async with client.stream("GET", current) as response:
                        peer = _peer_address(response)
                        if peer is not None:
                            ip = ipaddress.ip_address(peer)
                            if _ip_is_blocked(str(ip)) or not ip.is_global:
                                raise FederationFetchError("blocked_peer")
                        if response.is_redirect:
                            if redirect_count >= MAX_REDIRECTS:
                                raise FederationFetchError("redirect_limit")
                            location = response.headers.get("location")
                            if not location:
                                raise FederationFetchError("redirect_without_location")
                            current = urljoin(current, location)
                            continue
                        if response.status_code != 200:
                            raise FederationFetchError(f"http_status_{response.status_code}")
                        content_type = (
                            response.headers.get("content-type", "")
                            .split(";", 1)[0]
                            .strip()
                            .lower()
                        )
                        if content_type not in allowed_types:
                            raise FederationFetchError("content_type_rejected")
                        length = response.headers.get("content-length")
                        if length:
                            try:
                                declared_length = int(length)
                            except ValueError as exc:
                                raise FederationFetchError("invalid_content_length") from exc
                            if declared_length < 0:
                                raise FederationFetchError("invalid_content_length")
                            if declared_length > max_bytes:
                                raise FederationFetchError("response_too_large")
                        chunks: list[bytes] = []
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > max_bytes:
                                raise FederationFetchError("response_too_large")
                            chunks.append(chunk)
                        return RemoteResponse(
                            current,
                            response.status_code,
                            content_type,
                            b"".join(chunks),
                            response.headers,
                        )
                except httpx.HTTPError as exc:
                    raise FederationFetchError("fetch_failed") from exc
    raise FederationFetchError("redirect_limit")


def _peer_address(response: httpx.Response) -> str | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    try:
        address = stream.get_extra_info("server_addr")
        return address[0] if isinstance(address, tuple) else None
    except AttributeError, OSError:
        return None
