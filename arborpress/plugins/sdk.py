"""Small supported plugin-facing contract; no ORM or Quart objects are exposed."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class PluginError(Exception):
    """A safe, user-facing plugin error category and message."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class RPCClient(Protocol):
    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class PluginContext:
    plugin_id: str
    plugin_version: str
    arborpress_version: str
    runtime_version: str
    rpc: RPCClient


class PluginLifecycle(Protocol):
    async def initialize(self, context: PluginContext) -> None: ...

    async def ping(self) -> dict[str, Any] | None: ...

    async def shutdown(self) -> None: ...
