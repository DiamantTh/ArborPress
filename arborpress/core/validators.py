"""Shared input validators (§10 Input Validation).

Used across install, auth and public routes to enforce consistent
validation rules without duplicating regex patterns.

All functions are pure (no I/O) and return bool, EXCEPT:
  - ``is_safe_external_url`` performs a DNS lookup and must be awaited
    in async contexts (call ``is_safe_external_url_sync`` for sync paths).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Control-character sanitisation
# ---------------------------------------------------------------------------

# Strip all ASCII control chars except horizontal tab, LF and CR.
# Covers null-bytes (\x00), BEL, BS, DEL, etc.
_CTRL_TABLE: dict[int, None] = {
    c: None
    for c in range(0, 32)
    if c not in (9, 10, 13)  # keep \t, \n, \r
}
_CTRL_TABLE[127] = None  # DEL


def strip_control_chars(s: str) -> str:
    """Remove ASCII control characters (including null bytes) from *s*.

    Safe to call on any user-supplied string before further validation or
    storage. Keeps standard whitespace (\\t, \\n, \\r).
    """
    return s.translate(_CTRL_TABLE)


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Letters, digits, dot, hyphen, underscore; start + end alphanumeric; max 32.
# 32 chars is consistent with ActivityPub/Mastodon norms and URL ergonomics.
_USERNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9][a-zA-Z0-9._\-]{0,30}[a-zA-Z0-9]|[a-zA-Z0-9])$"
)

# Slug: lowercase alphanumeric + hyphen, must not start/end with hyphen
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$|^[a-z0-9]$")

# Fallback regex used when email-validator package is not installed.
# Covers >99 % of real addresses; max length enforced separately.
_EMAIL_RE_FALLBACK = re.compile(
    r"^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}$"
)

try:
    from email_validator import EmailNotValidError as _EmailNotValidError
    from email_validator import validate_email as _validate_email
    _HAS_EMAIL_VALIDATOR = True
except ImportError:  # pragma: no cover
    _HAS_EMAIL_VALIDATOR = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_valid_username(s: str) -> bool:
    """True when *s* matches the ArborPress username rules (max 32 chars)."""
    s = strip_control_chars(s)
    return bool(_USERNAME_RE.match(s))


def is_valid_email(s: str) -> bool:
    """True when *s* is a syntactically valid e-mail address.

    Uses the ``email-validator`` package when available (RFC 5321 + IDNA 2008),
    otherwise falls back to a conservative regex.  Deliverability (DNS MX) is
    intentionally **not** checked to avoid network round-trips in request
    handlers.
    """
    s = strip_control_chars(s).strip()
    if len(s) > 254:
        return False
    if _HAS_EMAIL_VALIDATOR:
        try:
            _validate_email(s, check_deliverability=False)
            return True
        except _EmailNotValidError:
            return False
    # Fallback
    return bool(_EMAIL_RE_FALLBACK.match(s))


def is_safe_url(s: str) -> bool:
    """True when *s* is an absolute http(s) URL with a non-empty host.

    Blocks javascript:, data:, vbscript: and relative URLs.
    """
    s = strip_control_chars(s).strip()
    try:
        p = urlparse(s)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def is_valid_slug(s: str) -> bool:
    """True when *s* is a valid URL slug."""
    s = strip_control_chars(s)
    return bool(_SLUG_RE.match(s))


# ---------------------------------------------------------------------------
# SSRF guard (§10 – Server-Side Request Forgery prevention)
# ---------------------------------------------------------------------------

# IP networks that must never be the target of server-initiated HTTP requests.
# Covers all private, loopback, link-local (incl. AWS IMDS 169.254.169.254),
# and multicast ranges for both IPv4 and IPv6.
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),          # "this" network
    ipaddress.ip_network("10.0.0.0/8"),          # private class A
    ipaddress.ip_network("100.64.0.0/10"),       # shared address space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / AWS IMDS
    ipaddress.ip_network("172.16.0.0/12"),       # private class B
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1 (docs)
    ipaddress.ip_network("192.168.0.0/16"),      # private class C
    ipaddress.ip_network("198.18.0.0/15"),       # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2 (docs)
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3 (docs)
    ipaddress.ip_network("224.0.0.0/4"),         # multicast
    ipaddress.ip_network("240.0.0.0/4"),         # reserved / future
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # loopback
    ipaddress.ip_network("fc00::/7"),            # unique local (ULA)
    ipaddress.ip_network("fe80::/10"),           # link-local
    ipaddress.ip_network("ff00::/8"),            # multicast
)


def _ip_is_blocked(addr: str) -> bool:
    """True when *addr* (string) falls into a private/reserved range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable → block
    return any(ip in net for net in _BLOCKED_NETWORKS)


def is_safe_external_url(url: str) -> bool:
    """True when *url* is a public http(s) URL that does NOT resolve to a
    private/internal network address (SSRF protection).

    Performs a DNS lookup; use only from async code via
    ``asyncio.to_thread(is_safe_external_url, url)`` or call it directly
    in a sync/threaded context.

    Rules enforced:
    - Scheme must be ``http`` or ``https``.
    - Hostname must be present.
    - All resolved IP addresses must be public (not private, loopback,
      link-local, reserved, or multicast).
    """
    url = strip_control_chars(url).strip()
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False

    # Reject bare IP literals that are private immediately (no DNS needed)
    try:
        literal_ip = ipaddress.ip_address(host)
        return not _ip_is_blocked(str(literal_ip))
    except ValueError:
        pass  # not an IP literal → proceed to DNS resolution

    # DNS resolution: ALL returned addresses must be public
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False  # resolution failure → block (fail-closed)

    if not infos:
        return False

    for _family, _type, _proto, _canonname, sockaddr in infos:
        addr = sockaddr[0]
        if _ip_is_blocked(addr):
            return False

    return True
