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
    """Readiness check: validates DB connection (§12)."""
    try:
        from sqlalchemy import text

        from arborpress.core.db import get_db_session, get_engine

        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        from arborpress.core.cache import cache_backend_info, cache_health
        from arborpress.core.search import search_health
        from arborpress.core.site_settings import get_defaults, get_section

        try:
            cache_ok, cache_detail = await asyncio.wait_for(cache_health(), timeout=1.0)
        except TimeoutError:
            cache_ok, cache_detail = False, "probe_timeout"
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
            search_status = await search_health(
                engine, str(search_settings.get("provider", "auto"))
            )
        except Exception as exc:
            search_status = {
                "provider": "database",
                "healthy": False,
                "degraded": True,
                "diagnostic": f"health_check_failed:{type(exc).__name__}",
            }
        try:
            cache_backend = cache_backend_info()
        except Exception as exc:
            cache_backend = "unknown"
            cache_ok, cache_detail = False, type(exc).__name__
        response = jsonify(
            {
                "status": "ready",
                "db": "ok",
                "search": search_status,
                "cache": {
                    "backend": cache_backend,
                    "healthy": cache_ok,
                    "diagnostic": cache_detail,
                    "required": False,
                },
            }
        )
        response.headers["Cache-Control"] = "no-store"
        return response, 200
    except Exception:
        response = jsonify({"status": "not_ready", "db": "unavailable"})
        response.headers["Cache-Control"] = "no-store"
        return response, 503
