"""Static, capability-enforced handlers for plugin-to-Core RPC calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from arborpress.plugins.capabilities import Capability, CapabilityGrantStore
from arborpress.plugins.services import PluginCoreServices, PluginServiceError


@dataclass(frozen=True, slots=True)
class RPCMethod:
    capability: Capability
    handler_name: str


PLUGIN_RPC_METHODS: dict[str, RPCMethod] = {
    "core.storage.get": RPCMethod(Capability.STORAGE_KV, "storage_get"),
    "core.storage.set": RPCMethod(Capability.STORAGE_KV, "storage_set"),
    "core.storage.delete": RPCMethod(Capability.STORAGE_KV, "storage_delete"),
    "core.storage.list": RPCMethod(Capability.STORAGE_KV, "storage_list"),
    "core.data.content.get": RPCMethod(Capability.CONTENT_READ, "content_get"),
    "core.data.content.list": RPCMethod(Capability.CONTENT_READ, "content_list"),
    "core.data.comments.list": RPCMethod(Capability.COMMENTS_READ, "comments_list"),
    "core.jobs.schedule": RPCMethod(Capability.JOBS_SCHEDULE, "schedule_job"),
}


class PluginRPCDispatcher:
    def __init__(self, services: PluginCoreServices, grants: CapabilityGrantStore) -> None:
        self.services = services
        self.grants = grants

    async def dispatch(
        self,
        plugin_id: str,
        method: str,
        params: object,
        *,
        declared_tasks: tuple[str, ...] = (),
        requested_capabilities: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        descriptor = PLUGIN_RPC_METHODS.get(method)
        if descriptor is None:
            raise PluginServiceError("method_not_found", "unknown Core RPC method")
        if descriptor.capability.value not in requested_capabilities:
            raise PluginServiceError(
                "permission_denied", "capability was not requested by this plugin"
            )
        if descriptor.capability.value not in self.grants.grants_for(plugin_id):
            raise PluginServiceError("permission_denied", "plugin capability is not granted")
        if not isinstance(params, dict):
            raise PluginServiceError("invalid_params", "params must be an object")
        handler = getattr(self.services, descriptor.handler_name)
        if method == "core.jobs.schedule":
            return cast(dict[str, Any], await handler(plugin_id, params, declared_tasks))
        return cast(dict[str, Any], await handler(plugin_id, params))
