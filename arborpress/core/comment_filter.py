"""IP-based comment filter with whitelist/blocklist, RBL and country checks (§10).

Checks incoming comment submitter IPs against:
  1. IP whitelist / blocklist  – exact IPs and CIDR ranges (stdlib ipaddress)
  2. Country filter            – ISO 3166-1 alpha-2 codes via GeoIP2 (optional)
  3. RBL / DNSBL               – DNS-based block lists via asyncio DNS

Settings section: ``comment_filter`` (stored in DB / site_settings).

Filter decision (in order):
  whitelist match  → "allow"  (stops further checks)
  blocklist match  → "block"
  country check    → "block"  (if country_blocklist or country_whitelist configured)
  RBL listed       → rbl_action ("block" | "flag")
  no match         → "allow"

Public API:
  check_comment_ip(ip_str, filter_settings) → (action, reason)
    action: "allow" | "block" | "flag"
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Literal

log = logging.getLogger("arborpress.comment_filter")

FilterAction = Literal["allow", "block", "flag"]

# ---------------------------------------------------------------------------
# IP whitelist / blocklist
# ---------------------------------------------------------------------------


def _check_ip_lists(
    ip_str: str,
    blocklist_lines: list[str],
    whitelist_lines: list[str],
) -> FilterAction | None:
    """Check IP against CIDR whitelist and blocklist.

    Returns a decision or ``None`` if neither list matches.
    Whitelist is evaluated first (takes priority over blocklist).
    CIDR notation (e.g. ``192.168.0.0/16``) and exact IPs are supported.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        log.debug("comment_filter: invalid IP %r – skipping list check", ip_str)
        return None

    def _matches(entry: str) -> bool:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            return False
        try:
            return addr in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return ip_str == entry

    if any(_matches(e) for e in whitelist_lines):
        return "allow"
    if any(_matches(e) for e in blocklist_lines):
        return "block"
    return None


# ---------------------------------------------------------------------------
# GeoIP2 country lookup (optional dependency)
# ---------------------------------------------------------------------------


def _lookup_country(ip_str: str, db_path: str) -> str | None:
    """Return ISO 3166-1 alpha-2 country code for *ip_str*.

    Uses the MaxMind GeoLite2 / GeoIP2 Country database.
    Returns ``None`` when geoip2 is not installed, the DB is missing,
    or the IP is not found (e.g. private ranges).
    """
    try:
        import geoip2.database  # optional dep ([geoip] extra)
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip_str)
            return response.country.iso_code
    except Exception as exc:
        log.debug("GeoIP lookup failed for %s: %s", ip_str, exc)
        return None


# ---------------------------------------------------------------------------
# RBL / DNSBL lookup
# ---------------------------------------------------------------------------


def _reverse_ip(ip_str: str) -> str | None:
    """Return the reversed-IP label for a DNSBL query.

    IPv4 ``1.2.3.4``  → ``4.3.2.1``
    IPv6 (expanded)   → nibble-reversed dotted label
    Returns ``None`` on parse error.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return ".".join(reversed(ip_str.split(".")))
    # IPv6: expand, remove colons, reverse nibbles
    full = addr.exploded.replace(":", "")
    return ".".join(reversed(list(full)))


async def _rbl_lookup_one(reversed_ip: str, zone: str) -> bool:
    """Return True if *reversed_ip*.*zone* resolves (i.e. IP is listed)."""
    hostname = f"{reversed_ip}.{zone}"
    loop = asyncio.get_event_loop()
    try:
        await loop.getaddrinfo(hostname, None)
        return True
    except OSError:
        return False


async def _check_rbl(ip_str: str, rbl_zones: list[str]) -> list[str]:
    """Return list of RBL zones in which *ip_str* is listed.

    Queries all zones concurrently.  An empty list means clean.
    """
    reversed_ip = _reverse_ip(ip_str)
    if reversed_ip is None:
        return []

    results = await asyncio.gather(
        *[_rbl_lookup_one(reversed_ip, z) for z in rbl_zones],
        return_exceptions=True,
    )
    return [
        zone for zone, listed in zip(rbl_zones, results)
        if listed is True
    ]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def check_comment_ip(
    ip_str: str,
    filter_settings: dict,
) -> tuple[FilterAction, str, str | None]:
    """Evaluate all configured network filters for a comment submitter IP.

    Args:
        ip_str:          Submitter's IP address (IPv4 or IPv6 string).
        filter_settings: The ``comment_filter`` site-settings section dict.

    Returns:
        ``("allow" | "block" | "flag", reason_str, country_code | None)``
        country_code is the ISO 3166-1 alpha-2 code if GeoIP is configured,
        otherwise None. It is returned even when the action is "allow" so
        the caller can store it on the Comment record.
    """
    if not ip_str:
        return "allow", "no IP available", None

    # Parse settings
    whitelist_lines = [
        e for e in filter_settings.get("ip_whitelist", "").splitlines() if e.strip()
    ]
    blocklist_lines = [
        e for e in filter_settings.get("ip_blocklist", "").splitlines() if e.strip()
    ]
    country_whitelist = [
        c.strip().upper()
        for c in filter_settings.get("country_whitelist", "").split(",")
        if c.strip()
    ]
    country_blocklist = [
        c.strip().upper()
        for c in filter_settings.get("country_blocklist", "").split(",")
        if c.strip()
    ]
    rbl_enabled = bool(filter_settings.get("rbl_enabled", False))
    rbl_zones_raw: str = filter_settings.get(
        "rbl_zones", "zen.spamhaus.org\nbl.spamcop.net"
    )
    rbl_zones = [z.strip() for z in rbl_zones_raw.splitlines() if z.strip()]
    rbl_action: FilterAction = filter_settings.get("rbl_action", "block")
    if rbl_action not in ("block", "flag"):
        rbl_action = "block"
    geoip_db: str = filter_settings.get("geoip_db_path", "").strip()

    # 1. IP whitelist / blocklist
    ip_decision = _check_ip_lists(ip_str, blocklist_lines, whitelist_lines)
    if ip_decision == "allow":
        return "allow", f"IP {ip_str} is on whitelist", None
    if ip_decision == "block":
        return "block", f"IP {ip_str} is on blocklist", None

    # 2. Country filter (always look up country if GeoIP DB is set, regardless of lists)
    country: str | None = None
    if geoip_db:
        loop = asyncio.get_event_loop()
        country = await loop.run_in_executor(None, _lookup_country, ip_str, geoip_db)
        if country:
            if country_whitelist and country not in country_whitelist:
                return "block", f"Country {country} not in whitelist", country
            if country_blocklist and country in country_blocklist:
                return "block", f"Country {country} is on country blocklist", country
        else:
            if filter_settings.get("country_block_unknown", False):
                return "block", "Country unknown and block_unknown=true", None

    # 3. RBL / DNSBL
    if rbl_enabled and rbl_zones:
        try:
            listed_in = await asyncio.wait_for(
                _check_rbl(ip_str, rbl_zones),
                timeout=5.0,  # don't stall the request more than 5 s
            )
        except asyncio.TimeoutError:
            log.warning("comment_filter: RBL lookup timed out for %s", ip_str)
            listed_in = []

        if listed_in:
            reason = f"IP {ip_str} listed in RBL: {', '.join(listed_in)}"
            log.info("comment_filter: %s → %s", rbl_action, reason)
            return rbl_action, reason, country

    return "allow", "passed all network checks", country
