"""Scheduled-Post-Worker (§1 PostStatus.SCHEDULED).

Hintergrundaufgabe, die alle 60 Sekunden nach fälligen Beiträgen sucht
und diese automatisch auf ``published`` setzt.

Wird in :func:`arborpress.web.app.create_app` als asyncio-Background-Task
gestartet und läuft für die gesamte Laufzeit der Anwendung.

Ablauf pro Tick:
  1. Alle Posts mit status=SCHEDULED und published_at <= jetzt laden
  2. Status auf PUBLISHED setzen, published_at ggf. auf jetzt setzen
  3. Event ``post.published`` emittieren (Plugin-Hooks)
  4. 60 Sekunden warten
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

log = logging.getLogger("arborpress.scheduler")

_TICK_INTERVAL = 60  # Sekunden


async def _publish_scheduled() -> int:
    """Einmaliger Tick: publiziert alle fälligen Scheduled Posts.

    Returns:
        Anzahl der veröffentlichten Posts.
    """
    from sqlalchemy import select

    from arborpress.core.db import get_db_session
    from arborpress.core.events import emit
    from arborpress.models.content import Post, PostStatus

    now = datetime.now(timezone.utc).replace(tzinfo=None)  # DB speichert UTC ohne tz
    published_count = 0

    try:
        async for db in get_db_session():
            stmt = select(Post).where(
                Post.status == PostStatus.SCHEDULED,
                Post.published_at != None,  # noqa: E711
                Post.published_at <= now,
            )
            result = await db.execute(stmt)
            posts = result.scalars().all()

            for post in posts:
                post.status = PostStatus.PUBLISHED
                if not post.published_at:
                    post.published_at = now
                db.add(post)
                log.info("Scheduler: Post veröffentlicht | slug=%s id=%s", post.slug, post.id)

            if posts:
                await db.commit()
                for post in posts:
                    await emit("post.published", post=post)
                published_count = len(posts)

    except Exception:
        log.exception("Scheduler: Fehler beim Veröffentlichen geplanter Posts")

    return published_count


async def run_scheduler() -> None:
    """Dauerhafter Background-Loop.

    Läuft bis zur Aufgaben-Cancellation (App-Shutdown).
    """
    log.info("Scheduler gestartet (Intervall: %ds)", _TICK_INTERVAL)
    while True:
        try:
            n = await _publish_scheduled()
            if n:
                log.info("Scheduler: %d Post(s) veröffentlicht", n)
        except asyncio.CancelledError:
            log.info("Scheduler: gestoppt")
            break
        except Exception:
            log.exception("Scheduler: unerwarteter Fehler")
        await asyncio.sleep(_TICK_INTERVAL)
