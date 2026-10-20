"""Bounded plugin restart policy; failures are isolated per plugin."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from arborpress.plugins.registry import PluginRecord, PluginStatus
from arborpress.plugins.state import PluginStateStore

log = logging.getLogger("arborpress.plugins.supervisor")
audit_log = logging.getLogger("arborpress.audit")


class PluginSupervisor:
    """Restart unhealthy enabled plugins with a bounded per-instance policy."""

    def __init__(
        self,
        manager: Any,
        store: PluginStateStore,
        *,
        poll_interval: float = 1.0,
        restart_window: float = 600.0,
        max_restarts: int = 3,
        backoff: Sequence[float] = (1.0, 5.0, 30.0),
        ping_interval: float = 30.0,
        ping_timeout: float = 5.0,
        max_ping_failures: int = 3,
        audit_callback: Callable[[str, str, str], Awaitable[None]] | None = None,
    ) -> None:
        self.manager = manager
        self.store = store
        self.poll_interval = poll_interval
        self.restart_window = restart_window
        self.max_restarts = max_restarts
        self.backoff = tuple(backoff)
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.max_ping_failures = max_ping_failures
        self.audit_callback = audit_callback
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._next_attempt: dict[str, float] = {}
        self._initial_started: set[str] = set()
        self._last_ping: dict[str, float] = {}
        self._ping_failures: dict[str, int] = defaultdict(int)
        self._blocked_capability_grants: set[str] = set()

    async def run(self, records: list[PluginRecord]) -> None:
        """Start enabled records, then supervise until this task is cancelled."""
        while True:
            now = time.monotonic()
            enabled = {record.id for record in records if record.enabled}
            for record in records:
                if (
                    not record.enabled
                    or record.manifest is None
                    or record.status in {PluginStatus.INVALID, PluginStatus.INCOMPATIBLE}
                ):
                    continue
                if record.id in self._blocked_capability_grants:
                    from arborpress.plugins.capabilities import (
                        CapabilityGrantStore,
                        missing_required_grants,
                    )
                    from arborpress.runtime.paths import get_runtime_paths

                    if missing_required_grants(
                        record.id,
                        record.manifest.required_capabilities,
                        CapabilityGrantStore(get_runtime_paths().data / "plugin-grants.toml"),
                    ):
                        continue
                    self._blocked_capability_grants.discard(record.id)
                if record.id in self.manager.running_ids:
                    if now - self._last_ping.get(record.id, 0.0) >= self.ping_interval:
                        self._last_ping[record.id] = now
                        try:
                            await asyncio.wait_for(
                                self.manager.ping(record.id), timeout=self.ping_timeout
                            )
                        except Exception:
                            self._ping_failures[record.id] += 1
                            if self._ping_failures[record.id] >= self.max_ping_failures:
                                await self.manager.stop(record.id)
                                record.runtime_status = PluginStatus.FAILED
                                auto_disabled = self._record_failure(record, "heartbeat_timeout")
                                if auto_disabled:
                                    await self._audit_auto_disabled(record, "heartbeat_timeout")
                                self._ping_failures[record.id] = 0
                        else:
                            self._ping_failures[record.id] = 0
                    continue
                if record.runtime_status == PluginStatus.AUTO_DISABLED:
                    continue
                if record.id not in self._initial_started:
                    self._initial_started.add(record.id)
                elif record.runtime_status not in {
                    PluginStatus.FAILED,
                    PluginStatus.STOPPED,
                    PluginStatus.UNKNOWN,
                }:
                    continue
                deadline = self._next_attempt.get(record.id, 0.0)
                if now < deadline:
                    continue
                try:
                    await self.manager.start(record)
                except Exception as exc:
                    if record.last_error and record.last_error.startswith(
                        "missing_required_capabilities:"
                    ):
                        log.warning(
                            "plugin start deferred id=%s reason=missing_capability_grant",
                            record.id,
                        )
                        self._blocked_capability_grants.add(record.id)
                        continue
                    if record.last_error == "lifecycle_operation_in_progress":
                        continue
                    auto_disabled = self._record_failure(record, type(exc).__name__)
                    if auto_disabled:
                        await self._audit_auto_disabled(record, type(exc).__name__)
            for plugin_id in tuple(self._failures):
                if plugin_id not in enabled:
                    self._failures.pop(plugin_id, None)
                    self._next_attempt.pop(plugin_id, None)
            await asyncio.sleep(self.poll_interval)

    def reset(self, plugin_id: str) -> None:
        self._failures.pop(plugin_id, None)
        self._next_attempt.pop(plugin_id, None)
        self._ping_failures.pop(plugin_id, None)
        self._last_ping.pop(plugin_id, None)
        self._blocked_capability_grants.discard(plugin_id)

    def _record_failure(self, record: PluginRecord, reason: str) -> bool:
        now = time.monotonic()
        failures = self._failures[record.id]
        failures.append(now)
        while failures and now - failures[0] > self.restart_window:
            failures.popleft()
        restart_count = max(0, len(failures) - 1)
        record.restart_count = restart_count
        if restart_count >= self.max_restarts:
            record.enabled = False
            record.runtime_status = PluginStatus.AUTO_DISABLED
            record.last_error = f"auto_disabled: {reason}"
            self.store.set_auto_disabled(record.id, True)
            self.manager._save_status(record, None)
            audit_log.warning(
                "PLUGIN_AUTO_DISABLED outcome=failure plugin=%s failures=%s",
                record.id,
                len(failures),
            )
            log.error("plugin auto-disabled id=%s failures=%s", record.id, len(failures))
            return True
        delay = self.backoff[min(restart_count, len(self.backoff) - 1)] if self.backoff else 1.0
        self._next_attempt[record.id] = now + delay
        record.last_error = f"restart scheduled after {reason}"
        self.manager._save_status(record, None)
        log.warning(
            "plugin restart scheduled id=%s restart=%s delay=%.1f error=%s",
            record.id,
            restart_count,
            delay,
            reason,
        )
        return False

    async def _audit_auto_disabled(self, record: PluginRecord, reason: str) -> None:
        if self.audit_callback is None:
            return
        try:
            await self.audit_callback(
                "plugin_auto_disabled", record.id, f"bounded restart policy: {reason}"
            )
        except Exception as exc:
            log.warning(
                "plugin auto-disable audit failed id=%s error=%s",
                record.id,
                type(exc).__name__,
            )
