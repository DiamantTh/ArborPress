"""Core-owned bounded polling worker for declared plugin tasks."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arborpress.plugins.services import PluginCoreServices

log = logging.getLogger("arborpress.plugins.jobs")


async def run_plugin_job_worker(
    manager: Any,
    sessions: async_sessionmaker[AsyncSession],
    *,
    poll_interval: float = 1.0,
) -> None:
    """Deliver due jobs at least once with bounded retry, until cancelled."""
    services = PluginCoreServices(sessions)
    while True:
        job = await services.claim_due_job()
        if job is None:
            await asyncio.sleep(poll_interval)
            continue
        if manager.pid_for(job.plugin_id) is None:
            await services.defer_job(job.id)
            continue
        try:
            await manager.execute_task(
                job.plugin_id,
                job_id=job.id,
                task=job.task,
                payload=job.payload,
            )
        except asyncio.CancelledError:
            # Lease expiry allows the next Core worker to retry after restart.
            raise
        except PermissionError:
            await services.cancel_job(job.id, "jobs.schedule capability revoked")
        except Exception as exc:
            await services.finish_job(job.id, error=type(exc).__name__)
            log.warning(
                "plugin job failed plugin=%s job=%s error=%s",
                job.plugin_id,
                job.id,
                type(exc).__name__,
            )
        else:
            await services.finish_job(job.id)
