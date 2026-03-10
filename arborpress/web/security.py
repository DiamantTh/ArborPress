"""Security-Middleware + CSRF-Schutz (§10 – Security-First Design Principles).

- Strict CSP (keine remote-Includes, keine Inline-Scripts)
- CSRF-Token für alle state-ändernden Admin/Auth-Formulare
- frame-ancestors 'none'
- no-store für Admin/Auth-Routen
- korrekte Cache-Control für statische Medien
- X-Permitted-Cross-Domain-Policies: none

HSTS wird bewusst NICHT von der App gesetzt. ArborPress läuft hinter einem
Reverse-Proxy (nginx/Apache/Traefik), der TLS terminiert. Nur der Proxy weiß,
ob der Client tatsächlich HTTPS nutzt. Direktverbindungen über HTTP (z. B.
lokale Entwicklung) dürfen keinen HSTS-Header erhalten – Browser würden ihn
zwar ignorieren, das Konzept wäre aber falsch. → HSTS kommt vom Proxy.
Siehe docs/proxy/*.conf.
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
    """Gibt den CSRF-Token der aktuellen Session zurück; generiert ihn on-demand."""
    if _CSRF_SESSION_KEY not in session:
        session[_CSRF_SESSION_KEY] = secrets.token_hex(32)
    return session[_CSRF_SESSION_KEY]


def validate_csrf() -> None:
    """Prüft CSRF-Token; bricht mit HTTP 403 ab wenn ungültig.

    Akzeptiert Token aus:
      1. HTML-Formularen  (POST-Body-Feld ``_csrf``)
      2. AJAX/SPA-Requests (Header ``X-CSRF-Token``)
    """
    expected = session.get(_CSRF_SESSION_KEY)
    submitted = (
        request.form.get(CSRF_FORM_FIELD)
        or request.headers.get("X-CSRF-Token", "")
    )
    if not expected or not submitted or not secrets.compare_digest(expected, submitted):
        abort(403, "CSRF-Token ungültig oder fehlend")


# ---------------------------------------------------------------------------
# CSP / Security-Header (§10)
# ---------------------------------------------------------------------------

# Kein 'unsafe-inline' für scripts; 'unsafe-inline' für styles ist akzeptabel
# (kein Script-Injection via CSS möglich), kann via Nonce später schärfer werden.
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
            ("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()"),
            ("X-Permitted-Cross-Domain-Policies", "none"),
            # HSTS wird NICHT hier gesetzt. ArborPress läuft hinter einem Proxy,
            # der TLS terminiert. Nur der Proxy kennt das tatsächliche Transportprotokoll.
            # HSTS muss ausschließlich vom Proxy kommen – siehe docs/proxy/*.conf.
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
