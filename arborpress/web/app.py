"""Quart-Applikations-Factory (komplett §0–§17)."""

from __future__ import annotations

from pathlib import Path

from quart import Quart

from arborpress.core.config import get_settings
from arborpress.logging.config import setup_logging
from arborpress.plugins.registry import get_registry
from arborpress.web.middleware import ReverseProxyMiddleware
from arborpress.web.security import SecurityHeadersMiddleware
from arborpress.web.routes.auth import auth_bp
from arborpress.web.routes.health import health_bp
from arborpress.web.routes.public import public_bp
from arborpress.web.routes.federation import wellknown_bp, federation_bp
from arborpress.web.routes.sso import sso_bp
from arborpress.web.routes.api import api_v1_bp, api_admin_bp

# Paket-Root = arborpress/
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

    # §7 I18N
    from arborpress.core.i18n import register_i18n
    register_i18n(app)

    # Konfiguration + Session als Jinja2-Globals (für Templates)
    app.jinja_env.globals["config"] = cfg

    # Aktives Theme laden und als Jinja2-Global bereitstellen
    from arborpress.themes.manifest import get_active_theme
    active_theme = get_active_theme()
    app.jinja_env.globals["theme"] = active_theme
    # Theme-Templates (überschreiben Kern-Templates; §9)
    if active_theme.template_dir:
        from jinja2 import FileSystemLoader, ChoiceLoader
        existing = app.jinja_env.loader
        app.jinja_env.loader = ChoiceLoader([
            FileSystemLoader(str(active_theme.template_dir)),
            existing,
        ])

    # §8 Admin-Blueprint dynamisch registrieren
    from arborpress.web.routes.admin import admin_bp
    admin_prefix = cfg.web.admin_path.rstrip("/")

    # §1 / §6 Public routes
    app.register_blueprint(public_bp)

    # §2 / §11 Auth + SSO
    app.register_blueprint(auth_bp, url_prefix="/auth")
    # §11: SSO-Blueprint registriert; einzelne Routen geben 404 wenn Provider nicht konfiguriert
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
        from quart import send_from_directory, abort as _abort
        from arborpress.themes.manifest import get_theme_registry
        t = get_theme_registry().get(theme_id)
        if t is None or t.static_dir is None or not t.static_dir.exists():
            _abort(404)
        return await send_from_directory(str(t.static_dir), filename)

    # §10 Security-Headers (innere Middleware – wird zuerst ausgeführt)
    app.asgi_app = SecurityHeadersMiddleware(app.asgi_app)  # type: ignore[assignment]

    # §10 Reverse-Proxy
    if cfg.web.trusted_proxies > 0:
        app.asgi_app = ReverseProxyMiddleware(  # type: ignore[assignment]
            app.asgi_app, trusted_proxies=cfg.web.trusted_proxies
        )

    # §12 DB-Capability-Detection beim Start
    @app.before_serving
    async def _on_startup() -> None:
        from arborpress.core.db import get_engine
        from arborpress.core.db_capabilities import detect_capabilities, set_capabilities

        try:
            caps = await detect_capabilities(get_engine())
            set_capabilities(caps)
        except Exception as exc:
            import logging
            logging.getLogger("arborpress").warning("DB-Capability-Detection fehlgeschlagen: %s", exc)

    return app


def _register_plugin_blueprints(app: Quart) -> None:
    """§15: Kein Plugin darf Security-Seiten definieren."""
    for _plugin in get_registry().all():
        pass  # TODO: Plugin-Blueprints registrieren wenn entry_points.web definiert
