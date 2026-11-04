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

from markupsafe import Markup
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


def csrf_input() -> Markup:
    """Render the session-bound CSRF token as a safe HTML form field."""
    return Markup('<input type="hidden" name="_csrf" value="{}">').format(
        get_csrf_token()
    )


async def validate_csrf() -> None:
    """Validates the CSRF token; aborts with HTTP 403 if invalid.

    Accepts tokens from:
      1. HTML forms  (POST body field ``_csrf``)
      2. AJAX/SPA requests (header ``X-CSRF-Token``)

    Additionally checks the Origin/Referer header as a second CSRF layer
    (defense-in-depth per §10).
    """
    # Layer 1 – Origin/Referer check (defense-in-depth)
    cfg = get_settings()
    base = cfg.web.base_url.rstrip("/")
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    if origin and not origin.startswith(base):
        abort(403, "Cross-origin request rejected")

    # Layer 2 – CSRF token comparison
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
        request_headers = {key.lower(): value for key, value in scope.get("headers", [])}
        has_cookie = b"cookie" in request_headers
        has_authorization = b"authorization" in request_headers

        async def _send(message: dict) -> None:
            if message["type"] == "http.response.start":
                existing = list(message.get("headers", []))
                names = {key.lower() for key, _ in existing}
                response_sets_cookie = any(key.lower() == b"set-cookie" for key, _ in existing)
                existing_cache_control = next(
                    (value.lower() for key, value in existing if key.lower() == b"cache-control"),
                    b"",
                )
                explicitly_no_store = b"no-store" in existing_cache_control
                force_no_store = (
                    path.startswith(self._admin_path)
                    or path.startswith("/auth")
                    or path.startswith("/api/v1/admin")
                    or path.startswith("/api/v1/oauth")
                    or has_authorization
                )
                if force_no_store:
                    if explicitly_no_store:
                        # Preserve a route's stricter, deliberate no-store
                        # value while removing duplicate middleware headers.
                        kept_cache_control = False
                        unique_headers = []
                        for key, value in existing:
                            if key.lower() == b"cache-control":
                                if kept_cache_control:
                                    continue
                                kept_cache_control = True
                            unique_headers.append((key, value))
                        existing = unique_headers
                    else:
                        existing = [(k, v) for k, v in existing if k.lower() != b"cache-control"]
                        names.discard(b"cache-control")
                        existing.append((b"cache-control", _NO_STORE.encode()))
                        names.add(b"cache-control")
                elif explicitly_no_store:
                    # Keep explicit route policy (e.g. one-time token results).
                    pass
                elif has_cookie or response_sets_cookie:
                    # Never let an SSR response that can include account- or
                    # session-specific controls enter a shared cache.
                    existing = [(k, v) for k, v in existing if k.lower() != b"cache-control"]
                    names.discard(b"cache-control")
                    existing.append((b"cache-control", b"private, no-cache"))
                    names.add(b"cache-control")
                for k, v in headers_to_add:
                    if k.encode().lower() not in names:
                        existing.append((k.encode(), v.encode()))
                        names.add(k.encode().lower())
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

        # Admin, auth, and bearer APIs are never cacheable.
        if (
            path.startswith(self._admin_path)
            or path.startswith("/auth")
            or path.startswith("/api/v1/admin")
            or path.startswith("/api/v1/oauth")
        ):
            headers.append(("Cache-Control", _NO_STORE))
            headers.append(("X-Robots-Tag", "noindex, nofollow"))

        # §6 Media: aggressive caching
        elif path.startswith("/media/"):
            headers.append(("Cache-Control", _MEDIA_CACHE))

        # Public-Content: moderate Caching
        else:
            headers.append(("Cache-Control", "public, max-age=300, stale-while-revalidate=60"))

        return headers
