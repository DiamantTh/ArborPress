"""Rollenbasierte Zugriffskontrolle – RBAC-Hilfsfunktionen (§4).

Rollen-Hierarchie (aufsteigend):
  viewer < author < editor < admin

Verwendung in Route-Handlern::

    from arborpress.auth.roles import require_role
    require_role("editor")   # wirft 403 wenn unter editor

Im Jinja2-Template (über Jinja-Global ``has_role``)::

    {% if has_role("admin") %} … {% endif %}
"""

from __future__ import annotations

from quart import abort, session

# Rollen in aufsteigender Berechtigung (höherer Wert = mehr Rechte).
ROLE_ORDER: dict[str, int] = {
    "viewer": 0,
    "author": 1,
    "editor": 2,
    "admin":  3,
}


def require_role(min_role: str) -> None:
    """Bricht mit HTTP 403 ab, wenn die Session-Rolle unter *min_role* liegt.

    Muss nach einem Session-Guard aufgerufen werden, der `user_id` prüft.
    """
    current = session.get("user_role", "viewer")
    if ROLE_ORDER.get(current, 0) < ROLE_ORDER.get(min_role, 99):
        abort(403)


def has_min_role(min_role: str) -> bool:
    """True wenn die aktuelle Session-Rolle >= *min_role* ist.

    Gedacht für Jinja2-Templates (wird via `app.jinja_env.globals` registriert).
    """
    current = session.get("user_role", "viewer")
    return ROLE_ORDER.get(current, 0) >= ROLE_ORDER.get(min_role, 0)
