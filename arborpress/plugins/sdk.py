"""Small supported plugin-facing contract; no ORM or Quart objects are exposed."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast


class PluginError(Exception):
    """A safe, user-facing plugin error category and message."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class RPCClient(Protocol):
    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class PluginStorage:
    """Convenience wrapper around the Core-owned, plugin-scoped KV API."""

    rpc: RPCClient

    async def get(self, key: str) -> dict[str, Any]:
        return cast(dict[str, Any], await self.rpc.call("core.storage.get", {"key": key}))

    async def set(
        self, key: str, value: Any, expected_revision: int | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"key": key, "value": value}
        if expected_revision is not None:
            params["expected_revision"] = expected_revision
        return cast(dict[str, Any], await self.rpc.call("core.storage.set", params))

    async def delete(self, key: str, expected_revision: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"key": key}
        if expected_revision is not None:
            params["expected_revision"] = expected_revision
        return cast(dict[str, Any], await self.rpc.call("core.storage.delete", params))

    async def list(
        self, prefix: str = "", limit: int = 100, after: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"prefix": prefix, "limit": limit}
        if after is not None:
            params["after"] = after
        return cast(dict[str, Any], await self.rpc.call("core.storage.list", params))


@dataclass(frozen=True, slots=True)
class PluginContext:
    plugin_id: str
    plugin_version: str
    arborpress_version: str
    runtime_version: str
    rpc: RPCClient

    @property
    def storage(self) -> PluginStorage:
        return PluginStorage(self.rpc)

    async def schedule(
        self,
        task: str,
        payload: dict[str, Any] | None = None,
        *,
        delay_seconds: int = 0,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "task": task,
            "payload": payload or {},
            "delay_seconds": delay_seconds,
        }
        if idempotency_key is not None:
            params["idempotency_key"] = idempotency_key
        return cast(dict[str, Any], await self.rpc.call("core.jobs.schedule", params))


class PluginLifecycle(Protocol):
    async def initialize(self, context: PluginContext) -> None: ...

    async def ping(self) -> dict[str, Any] | None: ...

    async def shutdown(self) -> None: ...
