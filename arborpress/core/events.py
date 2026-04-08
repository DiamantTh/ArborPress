"""Asynchronous event system for plugin hooks (§15 Plugin-Capabilities).

Plugins register handlers via capability metadata or directly via
`subscribe()`. The core emits events at defined hook points.

Example:
    from arborpress.core.events import subscribe, emit

    @subscribe("post.published")
    async def on_post(event):
        ...  # Update feed, send notification, …

    await emit("post.published", post=post_obj)
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger("arborpress.events")

# event name → list of handlers
_handlers: dict[str, list[Callable[..., Awaitable[None]]]] = defaultdict(list)

# ---------------------------------------------------------------------------
# Known core events (§15 reference for plugins)
# ---------------------------------------------------------------------------

EVENTS = frozenset(
    {
        # Content lifecycle
        "post.before_save",
        "post.published",
        "post.updated",
        "post.deleted",
        "page.published",
        "page.updated",
        "page.deleted",
        # Auth events (§2)
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
        # Plugin lifecycle (§15)
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
    """Register an async handler for the given event.

    Can be used as a decorator or called directly:

        @subscribe("post.published")
        async def handler(event, **kwargs): ...

        subscribe("post.published", my_handler)
    """
    def _decorator(fn: Callable[..., Awaitable[None]]) -> Callable:
        _handlers[event].append(fn)
        log.debug("Event handler registered: %s → %s", event, fn.__qualname__)
        return fn

    if handler is not None:
        _decorator(handler)
        return handler
    return _decorator


def unsubscribe(event: str, handler: Callable[..., Awaitable[None]]) -> bool:
    """Remove a handler. Returns True if found."""
    try:
        _handlers[event].remove(handler)
        return True
    except ValueError:
        return False


async def emit(event: str, **kwargs: Any) -> None:
    """Send an event to all registered handlers.

    Handler errors are logged but not propagated (§15: core stability
    must not depend on plugins).
    """
    if event not in EVENTS:
        log.warning("Unknown event emitted: %r (not defined in EVENTS)", event)

    handlers = list(_handlers.get(event, []))
    if not handlers:
        return

    for handler in handlers:
        try:
            await handler(event=event, **kwargs)
        except Exception as exc:
            log.exception(
                "Event handler %s failed for event %r: %s",
                handler.__qualname__,
                event,
                exc,
            )


async def emit_all(events: list[tuple[str, dict[str, Any]]]) -> None:
    """Send multiple events concurrently."""
    await asyncio.gather(*(emit(ev, **kw) for ev, kw in events))


def clear_handlers(event: str | None = None) -> None:
    """Remove handlers (for tests)."""
    if event:
        _handlers.pop(event, None)
    else:
        _handlers.clear()
