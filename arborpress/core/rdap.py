"""Async RDAP lookup for IP addresses (§10 – admin info panel).

RDAP (Registration Data Access Protocol, RFC 9083) is the structured
successor to WHOIS. It returns JSON with information about the
registrant/network of an IP address.

Lookup flow:
  1. Try ARIN's redirect-capable endpoint first
     (https://rdap.arin.net/registry/ip/{ip}).  ARIN follows redirects
     to the responsible RIR (RIPE, APNIC, LACNIC, AFRINIC).
  2. If the first request already returns data → use it.
  3. If the response contains a ``link`` with ``rel=related`` pointing
     to another RDAP server → follow that link (one hop only).
  4. Extract the relevant fields into a flat dict.

Result is cached per IP (in-memory, 24 h TTL) so production traffic
does not generate excessive RDAP queries.

Private / RFC1918 addresses → return a stub "private_network" result
without any external lookup.

Public API:
  lookup(ip_str)              → dict (never raises, returns {} on error)
  invalidate_cache(ip=None)   → clear one or all entries
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from urllib.parse import urlparse

log = logging.getLogger("arborpress.rdap")

_CACHE_TTL: int   = 86_400   # 24 hours
_TIMEOUT: float   = 8.0      # per request, applied as httpx connect+read timeout
_MAX_BODY: int    = 512 * 1024  # 512 KB – abort oversized responses
_ARIN_BASE: str   = "https://rdap.arin.net/registry/ip"

# Allowed RDAP server hostnames (SSRF whitelist – only follow links to these)
_RIR_RDAP_HOSTS: frozenset[str] = frozenset({
    "rdap.arin.net",
    "rdap.db.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
})

# ip_str → (expires_monotonic, result_dict)
_CACHE: dict[str, tuple[float, dict]] = {}
# ip_str → asyncio.Event  (set when lookup is complete, used to prevent stampedes)
_IN_FLIGHT: dict[str, asyncio.Event] = {}


def invalidate_cache(ip: str | None = None) -> None:
    """Clear the in-memory RDAP cache for one IP or all IPs."""
    if ip:
        _CACHE.pop(ip, None)
    else:
        _CACHE.clear()


def _is_private(ip_str: str) -> bool:
    """Return True for private / loopback / reserved addresses."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _extract(data: dict) -> dict:
    """Flatten an RDAP response into the fields we care about."""
    result: dict = {}

    # Handle field
    result["handle"] = data.get("handle", "")

    # Network name
    result["name"] = data.get("name", "")

    # IP range / CIDR
    start = data.get("startAddress", "")
    end   = data.get("endAddress", "")
    if start and end:
        result["range"] = f"{start} – {end}"
    elif start:
        result["range"] = start

    # Country
    result["country"] = data.get("country", "")

    # Type (ALLOCATED, ASSIGNED, etc.)
    result["type"] = data.get("type", "")

    # Organization / registrant from entities
    entities = data.get("entities", [])
    org_name = ""
    abuse_email = ""
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles", [])

        # vCard / jCard name extraction
        vcard = ent.get("vcardArray", [])
        name = ""
        email = ""
        if isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if not isinstance(prop, list) or len(prop) < 4:
                    continue
                ptype = prop[0]
                if ptype == "fn":
                    name = str(prop[3])
                elif ptype == "email":
                    email = str(prop[3])

        if "registrant" in roles or "technical" in roles:
            if not org_name:
                org_name = name
        if "abuse" in roles and email:
            abuse_email = email

        # Also try nested entities (ARIN nests org under the network entity)
        for sub in ent.get("entities", []):
            if not isinstance(sub, dict):
                continue
            sub_roles = sub.get("roles", [])
            sub_vcard = sub.get("vcardArray", [])
            sub_name  = ""
            sub_email = ""
            if isinstance(sub_vcard, list) and len(sub_vcard) > 1:
                for prop in sub_vcard[1]:
                    if not isinstance(prop, list) or len(prop) < 4:
                        continue
                    if prop[0] == "fn":
                        sub_name = str(prop[3])
                    elif prop[0] == "email":
                        sub_email = str(prop[3])
            if "registrant" in sub_roles and not org_name:
                org_name = sub_name
            if "abuse" in sub_roles and sub_email and not abuse_email:
                abuse_email = sub_email

    result["org"] = org_name
    result["abuse_email"] = abuse_email

    # RIR (deduce from the RDAP response URL if present)
    links = data.get("links", [])
    for link in links:
        if isinstance(link, dict) and link.get("rel") in ("self", "related"):
            href = link.get("href", "")
            for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
                if rir in href.lower():
                    result["rir"] = rir.upper()
                    break
            break

    # Remarks / description
    remarks = data.get("remarks", [])
    descs: list[str] = []
    for r in remarks:
        if isinstance(r, dict):
            for d in r.get("description", []):
                if isinstance(d, str) and d.strip():
                    descs.append(d.strip())
    if descs:
        result["remarks"] = " | ".join(descs[:3])

    return {k: v for k, v in result.items() if v}


def _is_allowed_rdap_host(url: str) -> bool:
    """Return True only if *url* points to a known RIR RDAP server (SSRF guard)."""
    try:
        host = urlparse(url).hostname or ""
        return host.lower() in _RIR_RDAP_HOSTS
    except Exception:
        return False


async def _fetch_rdap(url: str, *, follow_redirects: bool = True) -> dict | None:
    """Fetch a single RDAP URL and return parsed JSON or None.

    Safety measures:
    - Response body capped at _MAX_BODY (512 KB) – abort if exceeded.
    - follow_redirects allowed only from the ARIN entry-point (to reach the
      correct RIR); second-hop fetches are made with follow_redirects=False.
    - Tight timeout on both connect and read phases.
    """
    try:
        import httpx
        timeout = httpx.Timeout(connect=5.0, read=_TIMEOUT, write=5.0, pool=5.0)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers={"Accept": "application/rdap+json, application/json"},
        ) as client:
            async with client.stream("GET", url) as r:
                if r.status_code != 200:
                    log.debug("RDAP: %s returned HTTP %d", url, r.status_code)
                    return None
                # Content-Length pre-check (optional header, not always present)
                cl = r.headers.get("content-length")
                if cl and int(cl) > _MAX_BODY:
                    log.warning("RDAP: Content-Length %s from %s exceeds cap, aborting", cl, url)
                    return None
                # Streaming read with hard size cap
                chunks: list[bytes] = []
                total = 0
                async for chunk in r.aiter_bytes(8192):
                    total += len(chunk)
                    if total > _MAX_BODY:
                        log.warning("RDAP: response from %s exceeded %d KB cap, aborting", url, _MAX_BODY // 1024)
                        return None
                    chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except Exception as exc:
        log.debug("RDAP fetch error for %s: %s", url, exc)
        return None


async def lookup(ip_str: str) -> dict:
    """Perform an RDAP lookup for *ip_str* and return a flat info dict.

    Never raises. Returns ``{}`` on error or when nothing is found.
    Private addresses return a stub dict without network I/O.
    """
    if not ip_str:
        return {}

    # Cache check
    cached = _CACHE.get(ip_str)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    # Private addresses: no external lookup
    if _is_private(ip_str):
        result = {"type": "private_network", "org": "Private / RFC1918 address space"}
        _CACHE[ip_str] = (time.monotonic() + _CACHE_TTL, result)
        return result

    # SSRF guard: only query public, routable IPs
    try:
        addr = ipaddress.ip_address(ip_str)
        if not addr.is_global:
            return {}
    except ValueError:
        return {}

    # Stampede guard: if another coroutine is already fetching this IP, wait for it
    if ip_str in _IN_FLIGHT:
        await _IN_FLIGHT[ip_str].wait()
        # Result should now be cached
        cached = _CACHE.get(ip_str)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        return {}

    event = asyncio.Event()
    _IN_FLIGHT[ip_str] = event
    try:
        # ARIN accepts any IP and redirects to the responsible RIR;
        # follow_redirects=True is intentional here (ARIN → RIR).
        data = await _fetch_rdap(f"{_ARIN_BASE}/{ip_str}", follow_redirects=True)

        # Follow a single ``related`` link hop (RIPE/APNIC delegate differently).
        # SSRF guard: only follow links that point to a known RIR RDAP host.
        if data is not None:
            links = data.get("links", [])
            for link in links:
                if isinstance(link, dict) and link.get("rel") == "related":
                    href = link.get("href", "")
                    if href and href != f"{_ARIN_BASE}/{ip_str}":
                        if not _is_allowed_rdap_host(href):
                            log.warning("RDAP: related link %s rejected (not a known RIR host)", href)
                            break
                        # Second hop: no further redirects allowed
                        deeper = await _fetch_rdap(href, follow_redirects=False)
                        if deeper:
                            data = deeper
                    break

        if not data:
            _CACHE[ip_str] = (time.monotonic() + _CACHE_TTL, {})
            return {}

        result = _extract(data)
        _CACHE[ip_str] = (time.monotonic() + _CACHE_TTL, result)
        return result
    finally:
        _IN_FLIGHT.pop(ip_str, None)
        event.set()
