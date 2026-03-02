"""Asynchrones Event-System für Plugin-Hooks (§15 Plugin-Capabilities).

Plugins registrieren Handler via Capability-Metadaten oder direkt über
`subscribe()`. Der Core emittiert Events an definierten Hook-Punkten.

Beispiel:
    from arborpress.core.events import subscribe, emit

    @subscribe("post.published")
    async def on_post(event):
        ...  # Feed aktualisieren, Notification senden, …

    await emit("post.published", post=post_obj)
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger("arborpress.events")

# Event-Name → Liste von Handlern
_handlers: dict[str, list[Callable[..., Awaitable[None]]]] = defaultdict(list)

# ---------------------------------------------------------------------------
# Bekannte Core-Events (§15-Referenz für Plugins)
# ---------------------------------------------------------------------------

EVENTS = frozenset(
    {
        # Inhalts-Lifecycle
        "post.before_save",
        "post.published",
        "post.updated",
        "post.deleted",
        "page.published",
        "page.updated",
        "page.deleted",
        # Auth-Events (§2)
        "auth.login_success",
        "auth.login_failure",
        "auth.logout",
        "auth.credential_registered",
        "auth.credential_removed",
        "auth.stepup_granted",
        "auth.stepup_revoked",
        # Federation (§5)
        "federation.activity_received",
        "federation.activity_sent",
        "federation.follow_received",
        "federation.follow_accepted",
        # Media
        "media.uploaded",
        "media.deleted",
        # Plugin-Lifecycle (§15)
        "plugin.loaded",
        "plugin.enabled",
        "plugin.disabled",
        # Admin (§8)
        "admin.user_role_changed",
        "admin.auth_policy_changed",
        # Mail (§13)
        "mail.sent",
        "mail.failed",
    }
)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def subscribe(
    event: str,
    handler: Callable[..., Awaitable[None]] | None = None,
) -> Callable:
    """Registriert einen Async-Handler für das angegebene Event.

    Kann als Dekorator oder direkt aufgerufen werden:

        @subscribe("post.published")
        async def handler(event, **kwargs): ...

        subscribe("post.published", my_handler)
    """
    def _decorator(fn: Callable[..., Awaitable[None]]) -> Callable:
        _handlers[event].append(fn)
        log.debug("Event-Handler registriert: %s → %s", event, fn.__qualname__)
        return fn

    if handler is not None:
        _decorator(handler)
        return handler
    return _decorator


def unsubscribe(event: str, handler: Callable[..., Awaitable[None]]) -> bool:
    """Entfernt einen Handler. Gibt True zurück wenn gefunden."""
    try:
        _handlers[event].remove(handler)
        return True
    except ValueError:
        return False


async def emit(event: str, **kwargs: Any) -> None:
    """Sendet ein Event an alle registrierten Handler.

    Handler-Fehler werden geloggt, aber nicht propagiert (§15: Core-Stabilität
    darf nicht von Plugins abhängen).
    """
    if event not in EVENTS:
        log.warning("Unbekanntes Event emittiert: %r (nicht in EVENTS definiert)", event)

    handlers = list(_handlers.get(event, []))
    if not handlers:
        return

    for handler in handlers:
        try:
            await handler(event=event, **kwargs)
        except Exception as exc:
            log.exception(
                "Event-Handler %s schlug fehl für Event %r: %s",
                handler.__qualname__,
                event,
                exc,
            )


async def emit_all(events: list[tuple[str, dict[str, Any]]]) -> None:
    """Sendet mehrere Events nebenläufig."""
    await asyncio.gather(*(emit(ev, **kw) for ev, kw in events))


def clear_handlers(event: str | None = None) -> None:
    """Entfernt Handler (für Tests)."""
    if event:
        _handlers.pop(event, None)
    else:
        _handlers.clear()
