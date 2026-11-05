"""Health-Check-Endpunkt (Spec §17: Reverse-Proxy-freundlich)."""

import asyncio
import logging

from quart import Blueprint, jsonify
from quart.typing import ResponseReturnValue

health_bp = Blueprint("health", __name__)
log = logging.getLogger("arborpress.web.health")


@health_bp.get("/_health")
async def health() -> ResponseReturnValue:
    response = jsonify({"status": "ok"})
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@health_bp.get("/_ready")
async def ready() -> ResponseReturnValue:
    """Readiness check: database/schema, restore safety and required services."""
    try:
        from arborpress.core.config import get_settings, is_installed
        from arborpress.core.db import get_db_session, get_engine
        from arborpress.core.migrations import schema_status
        from arborpress.runtime.paths import get_runtime_paths

        paths = get_runtime_paths()
        marker_paths = (paths.run / "restore-maintenance.json", paths.run / "restore-journal.json")
        if any(path.exists() or path.is_symlink() for path in marker_paths):
            response = jsonify({"status": "not_ready", "reason": "maintenance"})
            response.headers["Cache-Control"] = "no-store"
            return response, 503
        if not is_installed():
            response = jsonify({"status": "not_ready", "reason": "installation"})
            response.headers["Cache-Control"] = "no-store"
            return response, 503

        engine = get_engine()
        schema = await asyncio.wait_for(schema_status(engine), timeout=5.0)
        if not schema.is_current:
            response = jsonify({"status": "not_ready", "reason": "schema"})
            response.headers["Cache-Control"] = "no-store"
            return response, 503

        from arborpress.core.cache import cache_backend_info, cache_health
        from arborpress.core.search import search_health
        from arborpress.core.site_settings import get_defaults, get_section

        cfg = get_settings()
        try:
            cache_ok, _cache_detail = await asyncio.wait_for(cache_health(), timeout=1.0)
        except TimeoutError:
            cache_ok, _cache_detail = False, "probe_timeout"
        search_settings = get_defaults("search")
        try:
            async for db in get_db_session():
                search_settings = await get_section("search", db)
                break
        except Exception as exc:
            # Readiness has already established DB connectivity; optional
            # settings diagnostics must not make it fail.
            log.debug("Search settings diagnostic failed (%s)", type(exc).__name__)
        try:
            raw_search_status = await asyncio.wait_for(
                search_health(engine, str(search_settings.get("provider", "auto"))),
                timeout=2.0,
            )
            search_status = {
                "provider": str(raw_search_status.get("provider", "unknown")),
                "healthy": bool(raw_search_status.get("healthy")),
                "degraded": bool(raw_search_status.get("degraded")),
                "required": bool(search_settings.get("required", False)),
                "index_mode": str(raw_search_status.get("index_mode", "unknown")),
            }
        except Exception:
            search_status = {
                "provider": "database",
                "healthy": False,
                "degraded": True,
                "required": bool(search_settings.get("required", False)),
                "index_mode": "unknown",
            }
        try:
            cache_backend = cache_backend_info()
        except Exception as exc:
            cache_backend = "unknown"
            cache_ok, _cache_detail = False, type(exc).__name__
        cache_required = bool(cfg.cache.required)
        search_required = bool(search_settings.get("required", False))
        dependencies_ready = (cache_ok or not cache_required) and (
            bool(search_status.get("healthy")) or not search_required
        )
        response = jsonify(
            {
                "status": "ready" if dependencies_ready else "not_ready",
                "db": "ok",
                "schema": "current",
                "search": search_status,
                "cache": {
                    "backend": cache_backend,
                    "healthy": cache_ok,
                    "required": cache_required,
                },
            }
        )
        response.headers["Cache-Control"] = "no-store"
        return response, 200 if dependencies_ready else 503
    except Exception:
        response = jsonify({"status": "not_ready", "db": "unavailable"})
        response.headers["Cache-Control"] = "no-store"
        return response, 503
