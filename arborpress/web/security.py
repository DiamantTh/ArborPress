"""Security-Middleware (§10 – Security-First Design Principles).

- Strict CSP defaults
- frame-ancestors restricted
- no-store für Admin/Auth-Routen
- korrekte Cache-Control für statische Medien
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from arborpress.core.config import get_settings

# §10 CSP Default – keine remote HTML-Includes
_CSP_DEFAULT = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)

# §10 Admin/Auth: kein Caching
_NO_STORE = "no-store, no-cache, must-revalidate, private"
# §10 Statische Medien: aggressiv cachen
_MEDIA_CACHE = "public, max-age=31536000, immutable"


class SecurityHeadersMiddleware:
    """ASGI-Middleware: Security-Header nach §10.

    - Alle Antworten erhalten Basis-Security-Header.
    - Admin- und Auth-Pfade erhalten no-store.
    - Media-Pfade erhalten aggressive Cache-Control.
    """

    def __init__(self, app: Any) -> None:
        self.app = app
        cfg = get_settings()
        self._admin_path = cfg.web.admin_path.rstrip("/")

    async def __call__(
        self, scope: dict, receive: Callable, send: Callable
    ) -> None:
        if scope["type"] not in ("http",):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        headers_to_add = self._build_headers(path)

        async def _send(message: dict) -> None:
            if message["type"] == "http.response.start":
                existing = list(message.get("headers", []))
                for k, v in headers_to_add:
                    existing.append((k.encode(), v.encode()))
                message = dict(message)
                message["headers"] = existing
            await send(message)

        await self.app(scope, receive, _send)

    def _build_headers(self, path: str) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Content-Security-Policy", _CSP_DEFAULT),
            ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
        ]

        # §8 Admin/Auth: no-store + noindex
        if path.startswith(self._admin_path) or path.startswith("/auth"):
            headers.append(("Cache-Control", _NO_STORE))
            headers.append(("X-Robots-Tag", "noindex, nofollow"))

        # §6 Media: aggressives Caching
        elif path.startswith("/media/"):
            headers.append(("Cache-Control", _MEDIA_CACHE))

        # Public-Content: moderate Caching
        else:
            headers.append(("Cache-Control", "public, max-age=300, stale-while-revalidate=60"))

        return headers
