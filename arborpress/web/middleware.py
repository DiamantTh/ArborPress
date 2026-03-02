"""Einfaches ASGI-Middleware für Reverse-Proxy-Header."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class ReverseProxyMiddleware:
    """Wertet X-Forwarded-For / X-Forwarded-Proto aus.

    ``trusted_proxies``: Anzahl der vertrauten Proxy-Hops vom rechten Ende.
    """

    def __init__(self, app: Any, *, trusted_proxies: int = 1) -> None:
        self.app = app
        self.trusted_proxies = trusted_proxies

    async def __call__(
        self, scope: dict, receive: Callable, send: Callable
    ) -> None:
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))

            # Proto
            forwarded_proto = headers.get(b"x-forwarded-proto", b"").decode()
            if forwarded_proto in ("http", "https"):
                scope["scheme"] = forwarded_proto

            # Host
            forwarded_host = headers.get(b"x-forwarded-host", b"").decode()
            if forwarded_host:
                scope["server"] = (forwarded_host, None)

        await self.app(scope, receive, send)
