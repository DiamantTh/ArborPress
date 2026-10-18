"""Quart application factory (complete §0–§17)."""

from __future__ import annotations

import logging
from datetime import UTC
from pathlib import Path
from typing import Any, cast

from quart import Quart, Response
from quart.templating import Environment as QuartEnvironment
from quart.typing import ResponseReturnValue

from arborpress.core.config import get_settings
from arborpress.logging.config import setup_logging
from arborpress.plugins.registry import get_registry
from arborpress.runtime.paths import ensure_instance_layout, get_runtime_paths
from arborpress.web.assets import AssetResolver
from arborpress.web.middleware import ReverseProxyMiddleware
from arborpress.web.routes.api import api_admin_bp, api_v1_bp
from arborpress.web.routes.auth import auth_bp
from arborpress.web.routes.federation import federation_bp, wellknown_bp
from arborpress.web.routes.health import health_bp
from arborpress.web.routes.install import install_bp
from arborpress.web.routes.public import public_bp
from arborpress.web.routes.sso import sso_bp
from arborpress.web.security import SecurityHeadersMiddleware

# Package root = arborpress/
_PKG_ROOT = Path(__file__).parent.parent
log = logging.getLogger("arborpress.web")


def create_app() -> Quart:
    # The caller (CLI, ASGI host, or embedding application) must have selected
    # this process's prefix before application construction. Resolve it before
    # reading config or initializing any instance-owned subsystem; never infer
    # an installed instance from the process working directory.
    paths = get_runtime_paths()
    ensure_instance_layout(paths)
    cfg = get_settings()
    setup_logging(cfg.logging)

    app = Quart(
        __name__,
        template_folder=str(_PKG_ROOT / "templates"),
        static_folder=str(_PKG_ROOT / "static"),
        static_url_path="/static",
    )
    from arborpress.themes.sandbox import ArborPressSandboxedEnvironment

    app.jinja_environment = cast(type[QuartEnvironment], ArborPressSandboxedEnvironment)
    # Vite assets are resolved lazily when a Jinja template requests an entry.
    # This keeps application startup usable in a source checkout before a local
    # frontend build, while installed releases ship the manifest and bundles.
    app.jinja_env.globals["vite_asset"] = AssetResolver().resolve
    app.secret_key = cfg.web.secret_key.get_secret_value()

    @app.before_request
    async def _restore_maintenance_gate() -> ResponseReturnValue | None:
        """Fail closed while an offline restore is switching instance state."""
        marker = paths.run / "restore-maintenance.json"
        if marker.exists() or marker.is_symlink():
            log.warning("Web request rejected while instance restore maintenance is active")
            return Response(
                "ArborPress is temporarily unavailable while an offline restore is in progress.\n",
                status=503,
                headers={"Retry-After": "60", "Cache-Control": "no-store"},
            )
        return None

    # §10 Session cookie hardening
    # Secure=True: served as HTTPS by the proxy; in a local dev setup
    # set to False if no HTTPS is available.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    # SameSite=Strict: cookie not sent on cross-site navigations (e.g. clicking a
    # link in an e-mail). SSO callback flows re-establish the session via the
    # provider redirect and are therefore not affected.
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = cfg.web.base_url.startswith("https")
    # Session lifetime: not "permanent" – ends on browser close
    app.config["PERMANENT_SESSION_LIFETIME"] = cfg.auth.admin_session_ttl
    # §10 Request-size guard: reject bodies > 2 MB before route handlers run.
    # File uploads go through a dedicated endpoint that overrides this per-route.
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB

    # §7 I18N
    from arborpress.core.i18n import register_i18n

    register_i18n(app)

    # §10 CSRF token function as Jinja2 global
    from arborpress.auth.roles import has_min_role
    from arborpress.web.security import csrf_input, get_csrf_token

    app.jinja_env.globals["csrf_token"] = get_csrf_token
    app.jinja_env.globals["csrf_input"] = csrf_input
    app.jinja_env.globals["has_role"] = has_min_role
    # Themes receive a deliberately small per-request view of these values in
    # _theme_context below; remove Quart's unrestricted proxies from globals.
    app.jinja_env.globals.pop("g", None)
    app.jinja_env.globals.pop("request", None)
    app.jinja_env.globals.pop("session", None)

    # nl2br filter (for comment display: \n → <br>)
    import markupsafe as _mu

    def _nl2br(value: str) -> _mu.Markup:
        escaped = _mu.escape(value)
        return _mu.Markup(str(escaped).replace("\n", "<br>\n"))  # noqa: S704

    app.jinja_env.filters["nl2br"] = _nl2br

    # country_flag filter: ISO 3166-1 alpha-2 code → regional indicator emoji
    # Example: "DE" → "🇩🇪"  — pure Unicode, zero external resources
    def _country_flag(code: str) -> str:
        if not code or len(code) < 2:
            return ""
        try:
            return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper()[:2])
        except ValueError, TypeError:
            return ""

    app.jinja_env.filters["country_flag"] = _country_flag

    # from_json filter: parse JSON string in templates (used by admin RDAP block)
    import json as _json

    def _from_json(value: str | None) -> dict[str, Any]:
        if not value:
            return {}
        try:
            parsed = _json.loads(value)
        except ValueError, TypeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    app.jinja_env.filters["from_json"] = _from_json

    # Helper for template time comparisons (e.g. expiry check in sessions.html)
    from datetime import datetime as _dt

    app.jinja_env.globals["now"] = lambda: _dt.now(UTC)

    # Templates need only presentation-safe config values. Do not expose the
    # complete Settings object here: it also contains database credentials,
    # signing keys and other runtime secrets that themes must never receive.
    app.jinja_env.globals["config"] = {
        "web": {
            "base_url": cfg.web.base_url,
            "admin_editor": cfg.web.admin_editor,
        },
        "auth": {
            "legacy_password_enabled": cfg.auth.legacy_password_enabled,
        },
    }
    app.jinja_env.globals["demo_mode"] = False  # Overridden by context processor per request

    # Theme selection is resolved per request. Public/Admin are independent,
    # and Jinja's loader uses the same type boundary for template overrides.
    from arborpress.core.site_settings import get_cached, get_defaults
    from arborpress.themes.jinja import (
        active_theme_for_request,
        install_theme_template_loader,
        template_overrides_trusted,
        template_theme_type,
    )
    from arborpress.themes.manifest import get_theme_registry

    theme_registry = get_theme_registry()
    install_theme_template_loader(app.jinja_env, theme_registry)

    @app.context_processor
    async def _theme_context() -> dict[str, object]:
        from quart import g
        from quart import request as quart_request
        from quart import session as quart_session

        from arborpress.themes.jinja import theme_context_view
        from arborpress.themes.management import resolve_option_values

        theme_type = template_theme_type()
        theme_settings = getattr(g, "_theme_runtime_settings", None)
        if not isinstance(theme_settings, dict):
            theme_settings = get_cached("theme") or get_defaults("theme")
        selected = active_theme_for_request(theme_registry)
        trusted = template_overrides_trusted(selected)
        stored_options = theme_settings.get("option_values", {})
        theme_options = resolve_option_values(
            theme_registry,
            selected.id,
            stored_options if isinstance(stored_options, dict) else {},
        )

        dark = (
            theme_registry.get(selected.dark_companion)
            if theme_type == "public" and selected.dark_companion
            else None
        )
        theme_context: dict[str, object] = {
            "theme": theme_context_view(selected),
            "theme_options": theme_options,
            "theme_trusted": trusted,
            "theme_trust_tier": "trusted" if trusted else "normal",
            "theme_dark": theme_context_view(dark) if dark else None,
            "theme_css_url": theme_registry.asset_url(selected.id),
            "theme_dark_css_url": theme_registry.asset_url(dark.id) if dark else "",
            "theme_auto_dark": bool(theme_settings.get("auto_dark", False))
            if theme_type == "public"
            else False,
            "theme_auto_dark_start": int(theme_settings.get("auto_dark_start", 19)),
            "theme_auto_dark_end": int(theme_settings.get("auto_dark_end", 6)),
            # Do not expose the full signed session or Quart request proxy to
            # theme templates. Core templates use only these presentation-safe
            # fields; authentication state remains server-side.
            "session": {
                "user_id": quart_session.get("user_id"),
                "user_name": quart_session.get("user_name"),
            },
            "request": {"endpoint": quart_request.endpoint},
        }
        if trusted:
            def theme_asset_url(filename: str) -> str:
                """Resolve a same-origin URL for a manifest-declared local asset."""
                try:
                    resolved = theme_registry.resolve_asset(selected.id, filename)
                except ValueError:
                    return ""
                if resolved is None:
                    return ""
                owner, asset_path = resolved
                relative = asset_path.relative_to(owner.static_dir.resolve()).as_posix()
                from quart import url_for as quart_url_for

                return quart_url_for(
                    "theme_static", theme_id=selected.id, filename=relative
                )

            setattr(  # noqa: B010 - the sandbox reads this explicit callable marker.
                theme_asset_url, "__arborpress_safe_template_callable__", True
            )
            theme_context["theme_asset_url"] = theme_asset_url
        return theme_context

    # Background pattern override: read from cache per request
    @app.context_processor
    async def _pattern_context() -> dict[str, Any]:
        from arborpress.core.site_settings import get_cached, get_defaults
        from arborpress.themes.patterns import make_pattern_url

        _ts = get_cached("theme") or get_defaults("theme")
        _pid = _ts.get("bg_pattern", "auto")
        _color = _ts.get("bg_pattern_color", "") or "#818cf8"
        _opacity = float(_ts.get("bg_pattern_opacity", 0.07))
        _css_val = make_pattern_url(_pid, _color, _opacity)
        return {"theme_bg_pattern": _pid, "theme_bg_pattern_css": _css_val}

    # Federation – per-request context processor (value from DB/cache)
    @app.context_processor
    async def _federation_context() -> dict[str, Any]:
        from arborpress.core.site_settings import get_cached, get_defaults

        fed = get_cached("federation") or get_defaults("federation")
        return {"federation_settings": fed}

    # Demo mode – per-request context processor reads cache dynamically
    # (takes effect immediately after admin change without restart)
    @app.context_processor
    async def _demo_context() -> dict[str, Any]:
        _demo_cfg = get_cached("demo") or get_defaults("demo")
        demo_enabled = bool(_demo_cfg.get("enabled", False))
        if not demo_enabled:
            return {"demo_mode": False}

        reg = theme_registry
        all_t = reg.all("public")
        from arborpress.themes.jinja import theme_context_view

        # Main themes (no light_companion → excludes dark-only companions)
        demo_light = [theme_context_view(t) for t in all_t if t.light_companion is None]
        demo_map = {t.id: theme_context_view(t) for t in all_t}
        demo_css_urls = {theme.id: reg.asset_url(theme.id) for theme in all_t}
        return {
            "demo_mode": True,
            "demo_show_banner": bool(_demo_cfg.get("show_banner", True)),
            "demo_light_themes": demo_light,
            "demo_theme_map": demo_map,
            "demo_theme_css_urls": demo_css_urls,
        }

    @app.after_request
    async def _theme_preview_headers(response: Response) -> Response:
        from quart import session as quart_session

        if quart_session.get("_theme_preview"):
            response.headers["Cache-Control"] = "private, no-store"
            response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        return response

    # §8 Admin-Blueprint dynamisch registrieren
    from arborpress.web.routes.admin import admin_bp

    admin_prefix = cfg.web.admin_path.rstrip("/")

    # §14 Install-Wizard (vor allen anderen Blueprints registrieren)
    app.register_blueprint(install_bp)

    # §14 Install gate: redirect all requests to /install while .installed is missing
    # Exceptions: /install itself, /static/, /health
    @app.before_request
    async def _install_gate() -> ResponseReturnValue | None:
        from arborpress.core.config import is_installed

        if is_installed():
            return None
        from quart import redirect as _redir
        from quart import request as _req
        from quart import session as _session
        from quart import url_for as _uf

        path = _req.path
        install_enrollment_routes = {
            "/auth/register",
            "/auth/register/begin",
            "/auth/register/complete",
        }
        if (
            path == "/install"
            or (path in install_enrollment_routes and _session.get("install_enrollment"))
            or path.startswith("/static/")
            or path == "/_health"
            or path == "/favicon.ico"
        ):
            return None
        return _redir(_uf("install.install_page"))

    @app.before_request
    async def _recovery_session_gate() -> None:
        """Limit recovery sessions to the account's own recovery surface."""
        from quart import abort as _abort
        from quart import request as _req
        from quart import session as _session

        if not _session.get("recovery_only"):
            return None
        if _req.path.startswith("/static/") or _req.path == "/favicon.ico":
            return None
        allowed_endpoints = {
            "auth.register_page",
            "auth.register_begin",
            "auth.register_complete",
            "auth.account_security_page",
            "auth.totp_enrollment_begin",
            "auth.totp_enrollment_complete",
            "auth.totp_remove",
            "auth.webauthn_credential_remove",
            "auth.recovery_complete",
            "auth.logout",
        }
        if _req.endpoint not in allowed_endpoints:
            _abort(403, "Recovery-only session")

        from arborpress.auth.sessions import refresh_session_identity
        from arborpress.core.db import get_db_session

        async for db in get_db_session():
            if await refresh_session_identity(db, _session) is None:
                _session.clear()
                await db.commit()
                _abort(401, "Recovery session expired or revoked")
            await db.commit()
            break

    @app.before_request
    async def _load_theme_runtime_settings() -> None:
        """Refresh theme selection and trust from the prefix DB per worker request."""
        from quart import g, request

        if request.endpoint in {"static", "health.health", "theme_static"}:
            return
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_defaults, get_section_uncached

        selected = get_defaults("theme")
        try:
            async for db in get_db_session():
                selected = await get_section_uncached("theme", db)
                break
        except Exception as exc:
            # Static built-in fallbacks keep pages renderable while the DB is
            # unavailable; authorization and writes still fail in their routes.
            log.debug("Could not refresh per-request theme settings.", exc_info=exc)
        g._theme_runtime_settings = selected

    # §1 / §6 Public routes
    app.register_blueprint(public_bp)

    # §2 / §11 Auth + SSO
    app.register_blueprint(auth_bp, url_prefix="/auth")
    # §11: SSO blueprint registered; individual routes return 404 if provider not configured
    app.register_blueprint(sso_bp, url_prefix="/auth/sso")

    # §5 Federation (Well-Known + ActivityPub)
    app.register_blueprint(wellknown_bp)
    app.register_blueprint(federation_bp)

    # §8 Admin (dynamischer Pfad)
    app.register_blueprint(admin_bp, url_prefix=admin_prefix)

    # §8 API v1 (public + admin sub)
    app.register_blueprint(api_v1_bp)
    app.register_blueprint(api_admin_bp)

    # Health
    app.register_blueprint(health_bp)

    # §15 Plugin-Blueprints
    _register_plugin_blueprints(app)

    # §9 Theme static files are served only when declared in a valid manifest.
    @app.route("/static/themes/<theme_id>/<path:filename>")
    async def theme_static(theme_id: str, filename: str) -> Response:
        from quart import abort as _abort
        from quart import send_file

        try:
            resolved = theme_registry.resolve_asset(theme_id, filename)
        except ValueError:
            _abort(404)
        if resolved is None:
            _abort(404)
        _theme, asset_path = resolved
        response = await send_file(asset_path)
        response.headers["Cache-Control"] = "public, no-cache"
        return response

    # §10 Security headers (inner middleware – executed first)
    app.asgi_app = SecurityHeadersMiddleware(app.asgi_app)  # type: ignore[assignment]

    # §10 Reverse-Proxy
    if cfg.web.trusted_proxies > 0:
        app.asgi_app = ReverseProxyMiddleware(  # type: ignore[assignment]
            app.asgi_app, trusted_proxies=cfg.web.trusted_proxies
        )

    # §12 DB-Capability-Detection beim Start
    @app.before_serving
    async def _on_startup() -> None:
        import asyncio
        import logging as _log
        import secrets as _sec

        from arborpress.core.config import install_token_path, is_installed
        from arborpress.core.db import get_engine
        from arborpress.core.db_capabilities import detect_capabilities, set_capabilities
        from arborpress.core.scheduler import run_scheduler

        restore_marker = paths.run / "restore-maintenance.json"
        if restore_marker.exists() or restore_marker.is_symlink():
            raise RuntimeError(
                "An interrupted ArborPress restore is marked in maintenance mode; "
                "run `arborpress restore recover --offline` before starting the web service."
            )

        # §14 Installations-Token generieren wenn noch nicht installiert
        if not is_installed():
            token_file = install_token_path()
            if not token_file.exists():
                token = _sec.token_urlsafe(32)
                token_file.write_text(token + "\n", encoding="utf-8")
                _log.getLogger("arborpress").warning(
                    "\n"
                    "══════════════════════════════════════════════════════\n"
                    "  ArborPress has not been set up yet.                \n"
                    "  Open http://… /install in your browser and enter    \n"
                    "  the following token:                                \n"
                    "                                                      \n"
                    "  %s                                                  \n"
                    "                                                      \n"
                    "  Or read it from: %s                                 \n"
                    "══════════════════════════════════════════════════════",
                    token,
                    token_file.resolve(),
                )
            else:
                _log.getLogger("arborpress").warning(
                    "ArborPress not set up – token located at: %s",
                    token_file.resolve(),
                )

        # DB-abhängige Services nur starten wenn bereits installiert.
        # Im Install-Modus ist noch keine DB konfiguriert/bereit.
        if is_installed():
            from arborpress.core.migrations import schema_status

            schema = await schema_status(get_engine())
            if not schema.is_current:
                raise RuntimeError(
                    "Database schema is not at this ArborPress release's migration head "
                    f"({schema.state}: {schema.detail}). "
                    "Run 'arborpress db upgrade' before starting."
                )
            try:
                caps = await detect_capabilities(get_engine())
                set_capabilities(caps)
            except Exception as exc:
                _log.getLogger("arborpress").warning(
                    "DB-Capability-Detection fehlgeschlagen: %s", exc
                )

            # Scheduled-Publishing-Worker starten
            asyncio.ensure_future(run_scheduler())

            # Mail-Queue-Worker starten
            from arborpress.mail.queue import run_queue_worker

            asyncio.ensure_future(run_queue_worker())

    return app


def _register_plugin_blueprints(app: Quart) -> None:
    """§15: Kein Plugin darf Security-Seiten definieren."""
    for _plugin in get_registry().all():
        pass  # TODO: Plugin-Blueprints registrieren wenn entry_points.web definiert
