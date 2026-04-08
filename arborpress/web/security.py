"""Security middleware + CSRF protection (§10 – Security-First Design Principles).

- Strict CSP (no remote includes, no inline scripts)
- CSRF token for all state-changing admin/auth forms
- frame-ancestors 'none'
- no-store for admin/auth routes
- correct Cache-Control for static media
- X-Permitted-Cross-Domain-Policies: none

HSTS is deliberately NOT set by the app. ArborPress runs behind a reverse
proxy (nginx/Apache/Traefik) that terminates TLS. Only the proxy knows
whether the client is actually using HTTPS. Direct connections over HTTP (e.g.
local development) must not receive an HSTS header – browsers would ignore it
but the concept would be wrong. → HSTS comes from the proxy.
See docs/proxy/*.conf.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any

from quart import abort, request, session

from arborpress.core.config import get_settings

# ---------------------------------------------------------------------------
# CSRF (§10)
# ---------------------------------------------------------------------------

_CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "_csrf"  # hidden-input-Name in Templates


def get_csrf_token() -> str:
    """Returns the CSRF token for the current session; generates it on demand."""
    if _CSRF_SESSION_KEY not in session:
        session[_CSRF_SESSION_KEY] = secrets.token_hex(32)
    return session[_CSRF_SESSION_KEY]


async def validate_csrf() -> None:
    """Validates the CSRF token; aborts with HTTP 403 if invalid.

    Accepts tokens from:
      1. HTML forms  (POST body field ``_csrf``)
      2. AJAX/SPA requests (header ``X-CSRF-Token``)
    """
    expected = session.get(_CSRF_SESSION_KEY)
    form = await request.form
    submitted = (
        form.get(CSRF_FORM_FIELD)
        or request.headers.get("X-CSRF-Token", "")
    )
    if not expected or not submitted or not secrets.compare_digest(expected, submitted):
        abort(403, "CSRF token invalid or missing")


# ---------------------------------------------------------------------------
# CSP / Security-Header (§10)
# ---------------------------------------------------------------------------

# No 'unsafe-inline' for scripts; 'unsafe-inline' for styles is acceptable
# (no script injection via CSS possible), can be tightened later via nonce.
_CSP_DEFAULT = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "media-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "upgrade-insecure-requests;"
)

# §10 Admin/Auth: no caching
_NO_STORE = "no-store, no-cache, must-revalidate, private"
# §10 Static media: aggressive caching
_MEDIA_CACHE = "public, max-age=31536000, immutable"


class SecurityHeadersMiddleware:
    """ASGI middleware: security headers per §10.

    - All responses receive base security headers.
    - Admin and auth paths receive no-store.
    - Media paths receive aggressive Cache-Control.
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
            ("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()"),
            ("X-Permitted-Cross-Domain-Policies", "none"),
            # HSTS is NOT set here. ArborPress runs behind a proxy that
            # terminates TLS. Only the proxy knows the actual transport protocol.
            # HSTS must come exclusively from the proxy – see docs/proxy/*.conf.
        ]

        # §8 Admin/Auth: no-store + noindex
        if path.startswith(self._admin_path) or path.startswith("/auth"):
            headers.append(("Cache-Control", _NO_STORE))
            headers.append(("X-Robots-Tag", "noindex, nofollow"))

        # §6 Media: aggressive caching
        elif path.startswith("/media/"):
            headers.append(("Cache-Control", _MEDIA_CACHE))

        # Public-Content: moderate Caching
        else:
            headers.append(("Cache-Control", "public, max-age=300, stale-while-revalidate=60"))

        return headers
