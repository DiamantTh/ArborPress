"""Scheduled post worker (§1 PostStatus.SCHEDULED).

Background task that checks every 60 seconds for due posts
and automatically sets them to ``published``.

Started in :func:`arborpress.web.app.create_app` as an asyncio background task
and runs for the entire lifetime of the application.

Flow per tick:
  1. Load all posts with status=SCHEDULED and published_at <= now
  2. Set status to PUBLISHED, set published_at to now if not already set
  3. Emit event ``post.published`` (plugin hooks)
  4. Wait 60 seconds
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

log = logging.getLogger("arborpress.scheduler")

_TICK_INTERVAL = 60  # seconds


async def _publish_scheduled() -> int:
    """Single tick: publishes all due scheduled posts.

    Returns:
        Number of published posts.
    """
    from sqlalchemy import select

    from arborpress.core.db import get_db_session
    from arborpress.core.events import emit
    from arborpress.models.content import Post, PostStatus

    now = datetime.now(UTC).replace(tzinfo=None)  # DB speichert UTC ohne tz
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
                log.info("Scheduler: post published | slug=%s id=%s", post.slug, post.id)

            if posts:
                await db.commit()
                for post in posts:
                    await emit("post.published", post=post)
                published_count = len(posts)

    except Exception:
        log.exception("Scheduler: error publishing scheduled posts")

    return published_count


async def run_scheduler() -> None:
    """Persistent background loop.

    Runs until task cancellation (app shutdown).
    """
    log.info("Scheduler started (interval: %ds)", _TICK_INTERVAL)
    while True:
        try:
            n = await _publish_scheduled()
            if n:
                log.info("Scheduler: %d post(s) published", n)
        except asyncio.CancelledError:
            log.info("Scheduler: stopped")
            break
        except Exception:
            log.exception("Scheduler: unexpected error")
        await asyncio.sleep(_TICK_INTERVAL)
