"""Quart application factory (complete §0–§17)."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from quart import Quart

from arborpress.core.config import get_settings
from arborpress.logging.config import setup_logging
from arborpress.plugins.registry import get_registry
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


def create_app() -> Quart:
    cfg = get_settings()
    setup_logging(cfg.logging)

    app = Quart(
        __name__,
        template_folder=str(_PKG_ROOT / "templates"),
        static_folder=str(_PKG_ROOT / "static"),
        static_url_path="/static",
    )
    app.secret_key = cfg.web.secret_key.get_secret_value()

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
    from arborpress.web.security import get_csrf_token
    app.jinja_env.globals["csrf_token"] = get_csrf_token
    app.jinja_env.globals["has_role"] = has_min_role

    # nl2br filter (for comment display: \n → <br>)
    import markupsafe as _mu

    def _nl2br(value: str) -> _mu.Markup:
        escaped = _mu.escape(value)
        return _mu.Markup(str(escaped).replace("\n", "<br>\n"))  # noqa: S704

    app.jinja_env.filters["nl2br"] = _nl2br

    # Helper for template time comparisons (e.g. expiry check in sessions.html)
    from datetime import datetime as _dt
    app.jinja_env.globals["now"] = lambda: _dt.now(UTC)

    # Config + session as Jinja2 globals (for templates)
    app.jinja_env.globals["config"] = cfg
    app.jinja_env.globals["demo_mode"] = False  # Overridden by context processor per request

    # Load active theme and provide as Jinja2 global
    from arborpress.core.site_settings import get_cached, get_defaults
    from arborpress.themes.manifest import get_active_theme, get_theme_registry
    active_theme = get_active_theme()
    app.jinja_env.globals["theme"] = active_theme

    # Load dark companion (if configured) for client-side toggle
    _theme_settings = get_cached("theme") or get_defaults("theme")
    _dark_id = active_theme.theme.dark_companion
    _theme_dark = get_theme_registry().get(_dark_id) if _dark_id else None
    app.jinja_env.globals["theme_dark"] = _theme_dark
    app.jinja_env.globals["theme_auto_dark"] = bool(_theme_settings.get("auto_dark", False))
    app.jinja_env.globals["theme_auto_dark_start"] = int(_theme_settings.get("auto_dark_start", 19))
    app.jinja_env.globals["theme_auto_dark_end"] = int(_theme_settings.get("auto_dark_end", 6))

    # Background pattern override: read from cache per request
    @app.context_processor
    async def _pattern_context() -> dict:
        from arborpress.core.site_settings import get_cached, get_defaults
        from arborpress.themes.patterns import make_pattern_url
        _ts = get_cached("theme") or get_defaults("theme")
        _pid     = _ts.get("bg_pattern", "auto")
        _color   = _ts.get("bg_pattern_color", "") or "#818cf8"
        _opacity = float(_ts.get("bg_pattern_opacity", 0.07))
        _css_val = make_pattern_url(_pid, _color, _opacity)
        return {"theme_bg_pattern": _pid, "theme_bg_pattern_css": _css_val}

    # Federation – per-request context processor (value from DB/cache)
    @app.context_processor
    async def _federation_context() -> dict:
        from arborpress.core.site_settings import get_cached, get_defaults
        fed = get_cached("federation") or get_defaults("federation")
        return {"federation_settings": fed}

    # Demo mode – per-request context processor reads cache dynamically
    # (takes effect immediately after admin change without restart)
    @app.context_processor
    async def _demo_context() -> dict:
        _demo_cfg = get_cached("demo") or get_defaults("demo")
        demo_enabled = bool(_demo_cfg.get("enabled", False))
        if not demo_enabled:
            return {"demo_mode": False}

        reg = get_theme_registry()
        all_t = reg.all()
        # Main themes (no light_companion → excludes dark-only companions)
        demo_light = [t for t in all_t if t.theme.light_companion is None]
        demo_map   = {t.theme.id: t for t in all_t}

        ctx: dict = {
            "demo_mode":         True,
            "demo_show_banner":  bool(_demo_cfg.get("show_banner", True)),
            "demo_light_themes": demo_light,
            "demo_theme_map":    demo_map,
        }

        # Theme override via cookie (for SSR consistency)
        from quart import request as _req
        cookie_id = _req.cookies.get("ap-theme")
        if cookie_id:
            t_override = demo_map.get(cookie_id)
            if t_override:
                dark_id = t_override.theme.dark_companion
                ctx["theme"]      = t_override
                ctx["theme_dark"] = demo_map.get(dark_id) if dark_id else None
        return ctx
    # Theme templates (override core templates; §9)
    if active_theme.template_dir:
        from jinja2 import ChoiceLoader, FileSystemLoader
        existing = app.jinja_env.loader
        app.jinja_env.loader = ChoiceLoader([
            FileSystemLoader(str(active_theme.template_dir)),
            existing,
        ])

    # §8 Admin-Blueprint dynamisch registrieren
    from arborpress.web.routes.admin import admin_bp
    admin_prefix = cfg.web.admin_path.rstrip("/")

    # §14 Install-Wizard (vor allen anderen Blueprints registrieren)
    app.register_blueprint(install_bp)

    # §14 Install gate: redirect all requests to /install while .installed is missing
    # Exceptions: /install itself, /static/, /health
    @app.before_request
    async def _install_gate():
        from arborpress.core.config import is_installed
        if is_installed():
            return None
        from quart import request as _req, redirect as _redir, url_for as _uf
        path = _req.path
        if (
            path == "/install"
            or path.startswith("/static/")
            or path == "/health"
            or path == "/favicon.ico"
        ):
            return None
        return _redir(_uf("install.install_page"))

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

    # §9 Theme-Static-Files (GET /static/themes/<id>/css/style.css)
    @app.route("/static/themes/<theme_id>/<path:filename>")
    async def theme_static(theme_id: str, filename: str):  # type: ignore[return]
        from quart import abort as _abort
        from quart import send_from_directory

        from arborpress.themes.manifest import get_theme_registry
        t = get_theme_registry().get(theme_id)
        if t is None or t.static_dir is None or not t.static_dir.exists():
            _abort(404)
        return await send_from_directory(str(t.static_dir), filename)

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

        # §14 Installations-Token generieren wenn noch nicht installiert
        if not is_installed():
            token_file = install_token_path()
            if not token_file.exists():
                token = _sec.token_urlsafe(32)
                token_file.parent.mkdir(parents=True, exist_ok=True)
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
                    token, token_file.resolve(),
                )
            else:
                _log.getLogger("arborpress").warning(
                    "ArborPress not set up – token located at: %s",
                    token_file.resolve(),
                )

        # DB-abhängige Services nur starten wenn bereits installiert.
        # Im Install-Modus ist noch keine DB konfiguriert/bereit.
        if is_installed():
            try:
                caps = await detect_capabilities(get_engine())
                set_capabilities(caps)
            except Exception as exc:
                _log.getLogger("arborpress").warning(
                    "DB-Capability-Detection fehlgeschlagen: %s", exc
                )

            # Scheduled-Publishing-Worker starten
            asyncio.ensure_future(run_scheduler())

    return app


def _register_plugin_blueprints(app: Quart) -> None:
    """§15: Kein Plugin darf Security-Seiten definieren."""
    for _plugin in get_registry().all():
        pass  # TODO: Plugin-Blueprints registrieren wenn entry_points.web definiert
