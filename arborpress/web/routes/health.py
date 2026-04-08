"""Health-Check-Endpunkt (Spec §17: Reverse-Proxy-freundlich)."""

from quart import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/_health")
async def health() -> tuple:
    return jsonify({"status": "ok"}), 200


@health_bp.get("/_ready")
async def ready() -> tuple:
    """Readiness check: validates DB connection (§12)."""
    try:
        from sqlalchemy import text

        from arborpress.core.db import get_engine
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return jsonify({"status": "ready", "db": "ok"}), 200
    except Exception as exc:
        return jsonify({"status": "not_ready", "db": str(exc)}), 503
