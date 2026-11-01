"""Small transport inspection helpers shared by guarded outbound clients."""

from __future__ import annotations

import httpx


def response_peer_address(response: httpx.Response) -> str | None:
    """Return the connected peer IP when the active HTTP transport exposes it."""
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    try:
        address = stream.get_extra_info("server_addr")
        return address[0] if isinstance(address, tuple) else None
    except (AttributeError, OSError):
        return None
