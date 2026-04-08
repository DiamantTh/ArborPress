"""Role-based access control – RBAC helpers (§4).

Role hierarchy (ascending):
  viewer < author < editor < admin

Usage in route handlers::

    from arborpress.auth.roles import require_role
    require_role("editor")   # raises 403 if below editor

In Jinja2 templates (via Jinja global ``has_role``)::

    {% if has_role("admin") %} … {% endif %}
"""

from __future__ import annotations

from quart import abort, session

# Roles in ascending permission order (higher value = more privileges).
ROLE_ORDER: dict[str, int] = {
    "viewer": 0,
    "author": 1,
    "editor": 2,
    "admin":  3,
}


def require_role(min_role: str) -> None:
    """Abort with HTTP 403 if the session role is below *min_role*.

    Must be called after a session guard that checks `user_id`.
    """
    current = session.get("user_role", "viewer")
    if ROLE_ORDER.get(current, 0) < ROLE_ORDER.get(min_role, 99):
        abort(403)


def has_min_role(min_role: str) -> bool:
    """True if the current session role >= *min_role*.

    Intended for Jinja2 templates (registered via `app.jinja_env.globals`).
    """
    current = session.get("user_role", "viewer")
    return ROLE_ORDER.get(current, 0) >= ROLE_ORDER.get(min_role, 0)
