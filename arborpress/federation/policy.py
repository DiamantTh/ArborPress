"""Instance-scoped federation switches, canonical IDs and domain policy."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.federation.security import FederationFetchError, normalize_domain
from arborpress.models.federation import FederationDomainRule


def federation_is_enabled(settings: dict[str, Any]) -> bool:
    """The explicit 10A master switch is authoritative over legacy mode values."""
    return bool(settings.get("enabled", False)) and settings.get("mode", "disabled") != "disabled"


def canonical_origin() -> str:
    """Return the configured public HTTPS base URL; never derive IDs from a request."""
    value = get_settings().web.base_url.rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise FederationFetchError("canonical_https_origin_required")
    if parsed.query or parsed.fragment:
        raise FederationFetchError("invalid_canonical_origin")
    return value


def canonical_domain() -> str:
    host = urlsplit(canonical_origin()).hostname
    if not host:
        raise FederationFetchError("canonical_domain_missing")
    return normalize_domain(host)


async def domain_allowed(db: AsyncSession, domain: str, settings: dict[str, Any]) -> bool:
    """Apply global off, persisted allow/block rules and legacy blocklist."""
    if not federation_is_enabled(settings):
        return False
    try:
        normalized = normalize_domain(domain)
    except FederationFetchError:
        return False
    result = await db.execute(
        select(FederationDomainRule).where(FederationDomainRule.domain == normalized)
    )
    rule = result.scalar_one_or_none()
    legacy_blocks: set[str] = set()
    for item in settings.get("inbox_blocklist_domains", []):
        if not isinstance(item, str):
            continue
        try:
            legacy_blocks.add(normalize_domain(item))
        except FederationFetchError:
            continue
    if normalized in legacy_blocks or (rule and rule.rule == "block"):
        return False
    if settings.get("domain_policy", "open") == "limited" or settings.get("allowlist_mode", False):
        return bool(rule and rule.rule == "allow")
    return True
