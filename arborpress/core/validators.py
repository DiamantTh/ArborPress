"""Shared input validators (§10 Input Validation).

Used across install, auth and public routes to enforce consistent
validation rules without duplicating regex patterns.

All functions are pure (no I/O) and return bool.
"""

from __future__ import annotations

import re
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
