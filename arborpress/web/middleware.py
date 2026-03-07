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

            # Client-IP: rechte N Einträge aus X-Forwarded-For vertrauen
            xff = headers.get(b"x-forwarded-for", b"").decode().strip()
            if xff and self.trusted_proxies > 0:
                ips = [ip.strip() for ip in xff.split(",")]
                # Das N-te Element von rechts ist die vertrauenswürdige Client-IP
                client_ip = ips[-min(self.trusted_proxies, len(ips))]
                # Scope: (host, port) – Port aus Original-Client übernehmen
                orig_port = (scope.get("client") or (None, 0))[1]
                scope["client"] = (client_ip, orig_port)

        await self.app(scope, receive, send)
