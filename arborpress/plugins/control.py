"""Core-owned enable/disable operations for discovered plugin processes."""

from __future__ import annotations

import logging
from typing import Any

from arborpress.plugins.registry import PluginRecord, PluginStatus
from arborpress.plugins.state import PluginStateStore

log = logging.getLogger("arborpress.plugins")


async def enable_plugin(record: PluginRecord, manager: Any, store: PluginStateStore) -> None:
    if record.manifest is None or record.status in {
        PluginStatus.INVALID,
        PluginStatus.INCOMPATIBLE,
    }:
        raise ValueError(record.error or "plugin is not compatible")
    await manager.start(record)
    try:
        store.set_enabled(record.id, True)
    except Exception:
        await manager.stop(record.id)
        raise
    record.enabled = True
    supervisor = getattr(manager, "supervisor", None)
    if supervisor is not None:
        supervisor.reset(record.id)
    log.warning("plugin_enabled plugin=%s pid=%s", record.id, manager.pid_for(record.id))


async def disable_plugin(record: PluginRecord, manager: Any, store: PluginStateStore) -> None:
    store.set_enabled(record.id, False)
    await manager.stop(record.id)
    record.enabled = False
    record.runtime_status = PluginStatus.DISABLED
    log.warning("plugin_disabled plugin=%s", record.id)
