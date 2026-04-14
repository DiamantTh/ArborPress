"""Simple ASGI middleware for reverse-proxy headers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class ReverseProxyMiddleware:
    """Evaluates common reverse-proxy headers.

    Supported headers:
      - X-Forwarded-Proto
      - X-Forwarded-Host
      - X-Forwarded-Port
      - X-Forwarded-Prefix
      - X-Forwarded-For

    ``trusted_proxies``: number of trusted proxy hops from the right end.
    """

    def __init__(self, app: Any, *, trusted_proxies: int = 1) -> None:
        self.app = app
        self.trusted_proxies = trusted_proxies

    async def __call__(
        self, scope: dict, receive: Callable, send: Callable
    ) -> None:
        if scope["type"] in ("http", "websocket"):
            raw_headers = list(scope.get("headers", []))
            headers = dict(raw_headers)

            # Proto
            forwarded_proto = headers.get(b"x-forwarded-proto", b"").decode().split(",")[0].strip()
            if forwarded_proto in ("http", "https"):
                scope["scheme"] = forwarded_proto

            # Host (+ optional port)
            forwarded_host = headers.get(b"x-forwarded-host", b"").decode().split(",")[0].strip()
            forwarded_port = headers.get(b"x-forwarded-port", b"").decode().split(",")[0].strip()
            if forwarded_host:
                host_value = forwarded_host
                if forwarded_port and ":" not in forwarded_host:
                    default_port = "443" if scope.get("scheme") == "https" else "80"
                    if forwarded_port != default_port:
                        host_value = f"{forwarded_host}:{forwarded_port}"
                scope["server"] = (host_value, None)
                raw_headers = [(k, v) for k, v in raw_headers if k.lower() != b"host"]
                raw_headers.append((b"host", host_value.encode()))

            # Prefix for apps mounted below /
            forwarded_prefix = headers.get(b"x-forwarded-prefix", b"").decode().split(",")[0].strip()
            if forwarded_prefix:
                prefix = "/" + forwarded_prefix.strip("/")
                scope["root_path"] = "" if prefix == "/" else prefix

            # Client IP: remove trusted proxy hops from the right side.
            xff = headers.get(b"x-forwarded-for", b"").decode().strip()
            if xff and self.trusted_proxies > 0:
                ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
                if ips:
                    if len(ips) > self.trusted_proxies:
                        client_ip = ips[-(self.trusted_proxies + 1)]
                    else:
                        client_ip = ips[0]
                    orig_port = (scope.get("client") or (None, 0))[1]
                    scope["client"] = (client_ip, orig_port)

            scope["headers"] = raw_headers

        await self.app(scope, receive, send)
