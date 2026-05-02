"""Have I Been Pwned – Pwned Passwords k-Anonymity check.

Uses the public range API (https://api.pwnedpasswords.com/range/{prefix})
which only sees the first five hex characters of the SHA-1 hash. The full
password never leaves the host. Padding is requested via ``Add-Padding: true``
so traffic analysis cannot infer the response size.

Reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib
import logging

import httpx

log = logging.getLogger("arborpress.auth.hibp")

_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_USER_AGENT = "ArborPress-HIBP-Check/1.0"
_DEFAULT_TIMEOUT = 3.0


class HIBPCheckError(RuntimeError):
    """Raised when the HIBP API call cannot be completed."""


def _hash_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def _parse_count(body: str, suffix: str) -> int:
    for line in body.splitlines():
        head, _, count = line.partition(":")
        if head.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def check_pwned(password: str, *, timeout: float = _DEFAULT_TIMEOUT) -> int:
    """Return the breach count for ``password``. ``0`` means not seen.

    Raises :class:`HIBPCheckError` on network or HTTP failures so callers can
    decide whether to fail open or closed.
    """
    if not password:
        return 0
    prefix, suffix = _hash_prefix_suffix(password)
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(
                _API_URL.format(prefix=prefix),
                headers={"Add-Padding": "true", "User-Agent": _USER_AGENT},
            )
            response.raise_for_status()
            return _parse_count(response.text, suffix)
    except httpx.HTTPError as exc:
        raise HIBPCheckError(str(exc)) from exc


async def check_pwned_async(password: str, *, timeout: float = _DEFAULT_TIMEOUT) -> int:
    """Async sibling of :func:`check_pwned`."""
    if not password:
        return 0
    prefix, suffix = _hash_prefix_suffix(password)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                _API_URL.format(prefix=prefix),
                headers={"Add-Padding": "true", "User-Agent": _USER_AGENT},
            )
            response.raise_for_status()
            return _parse_count(response.text, suffix)
    except httpx.HTTPError as exc:
        raise HIBPCheckError(str(exc)) from exc


def enforce_hibp_policy(
    password: str,
    *,
    max_count: int = 0,
    timeout: float = _DEFAULT_TIMEOUT,
    fail_open: bool = True,
) -> int:
    """Check ``password`` against HIBP and raise :class:`ValueError` if leaked.

    ``max_count`` is the maximum tolerated breach count (default ``0`` =
    reject any match). When the API call fails and ``fail_open`` is true,
    the check is skipped silently (with a log warning); otherwise the
    underlying :class:`HIBPCheckError` is re-raised.

    Returns the breach count (0 if the API was unreachable in fail-open mode).
    """
    try:
        count = check_pwned(password, timeout=timeout)
    except HIBPCheckError as exc:
        if fail_open:
            log.warning("HIBP check failed (fail-open): %s", exc)
            return 0
        raise
    if count > max_count:
        raise ValueError(
            f"Password appears in known data breaches ({count} times). "
            "Please choose a different password."
        )
    return count


async def enforce_hibp_policy_async(
    password: str,
    *,
    max_count: int = 0,
    timeout: float = _DEFAULT_TIMEOUT,
    fail_open: bool = True,
) -> int:
    """Async variant of :func:`enforce_hibp_policy`."""
    try:
        count = await check_pwned_async(password, timeout=timeout)
    except HIBPCheckError as exc:
        if fail_open:
            log.warning("HIBP check failed (fail-open): %s", exc)
            return 0
        raise
    if count > max_count:
        raise ValueError(
            f"Password appears in known data breaches ({count} times). "
            "Please choose a different password."
        )
    return count
