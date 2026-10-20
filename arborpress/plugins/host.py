"""Private child-process bootstrap; third-party code is imported only here."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import os
import socket
from pathlib import Path
from typing import Any

from arborpress.plugins.protocol import PROTOCOL_VERSION, ProtocolError, receive_frame, send_frame
from arborpress.plugins.sdk import PluginContext


class _HostRPCClient:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._counter = 0
        self._pending: dict[str, asyncio.Future[Any]] = {}
        self._send_lock = asyncio.Lock()

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        if not isinstance(method, str) or not method.startswith("core.") or len(method) > 128:
            raise ValueError("invalid Core RPC method")
        self._counter += 1
        request_id = f"plugin-{self._counter}"
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        async with self._send_lock:
            await send_frame(
                self.sock,
                {
                    "protocol": PROTOCOL_VERSION,
                    "id": request_id,
                    "method": method,
                    "params": params or {},
                },
            )
        try:
            return await asyncio.wait_for(future, timeout=30)
        finally:
            self._pending.pop(request_id, None)

    def resolve(self, message: dict[str, Any]) -> bool:
        request_id = message.get("id")
        future = self._pending.get(request_id) if isinstance(request_id, str) else None
        if future is None:
            return False
        if message.get("error") is not None:
            error = message["error"]
            code = error.get("code", "plugin_error") if isinstance(error, dict) else "plugin_error"
            future.set_exception(RuntimeError(f"Core RPC failed: {str(code)[:64]}"))
        else:
            future.set_result(message.get("result"))
        return True


async def _call(target: object, name: str, *args: object) -> Any:
    method = getattr(target, name, None)
    if method is None:
        return None
    result = method(*args)
    return await result if inspect.isawaitable(result) else result


async def _serve(args: argparse.Namespace) -> int:
    sock = socket.socket(fileno=args.fd)
    sock.set_inheritable(False)
    sock.setblocking(False)
    hardening_features = tuple(
        item for item in os.environ.get("ARBORPRESS_PLUGIN_HARDENING", "").split(",") if item
    )
    module_name, _, attribute = args.entrypoint.partition(":")
    rpc = _HostRPCClient(sock)
    try:
        module = importlib.import_module(module_name)
        Path(getattr(module, "__file__", "")).resolve().relative_to(
            Path(args.plugin_root).resolve()
        )
        plugin = getattr(module, attribute)
        if inspect.isclass(plugin):
            plugin = plugin()
    except Exception as exc:
        await send_frame(
            sock,
            {
                "protocol": PROTOCOL_VERSION,
                "id": "initialize",
                "error": {"code": "import_error", "message": type(exc).__name__},
            },
        )
        return 2

    lifecycle_lock = asyncio.Lock()
    shutdown_event = asyncio.Event()

    async def handle(request: dict[str, Any]) -> None:
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})
        if (
            not isinstance(request_id, (str, int))
            or not isinstance(method, str)
            or not isinstance(params, dict)
        ):
            response = {
                "protocol": PROTOCOL_VERSION,
                "id": request_id,
                "error": {"code": "invalid_request", "message": "invalid request shape"},
            }
        else:
            try:
                async with lifecycle_lock:
                    if method == "runtime.initialize":
                        if params.get("plugin_id") != args.plugin_id:
                            raise ValueError("plugin identity mismatch")
                        context = PluginContext(
                            args.plugin_id,
                            args.plugin_version,
                            str(params.get("arborpress_version", "")),
                            "1",
                            rpc,
                        )
                        await _call(plugin, "initialize", context)
                        result: dict[str, Any] = {
                            "ready": True,
                            "plugin_id": args.plugin_id,
                            "plugin_version": args.plugin_version,
                            "runtime_version": "1",
                            "features": list(hardening_features),
                        }
                    elif method == "runtime.ping":
                        result = await _call(plugin, "ping") or {"ok": True}
                    elif method == "plugin.task":
                        task = params.get("task")
                        if not isinstance(task, str) or not task:
                            raise ValueError("invalid task")
                        task_fn = getattr(plugin, "handle_task", None)
                        if task_fn is None:
                            raise LookupError("task handler unavailable")
                        value = task_fn(task, params.get("payload", {}), params.get("job_id"))
                        result = await value if inspect.isawaitable(value) else value
                        if not isinstance(result, dict):
                            result = {"value": result}
                    elif method == "plugin.event":
                        event_fn = getattr(plugin, "handle_event", None)
                        if event_fn is None:
                            result = {"accepted": False}
                        else:
                            value = event_fn(params.get("event", {}))
                            result = await value if inspect.isawaitable(value) else value
                            if not isinstance(result, dict):
                                result = {"accepted": True}
                    elif method == "plugin.admin_action":
                        action_fn = getattr(plugin, "handle_admin_action", None)
                        if action_fn is None:
                            raise LookupError("admin action handler unavailable")
                        value = action_fn(params.get("action_id"), params.get("values", {}))
                        result = await value if inspect.isawaitable(value) else value
                        if not isinstance(result, dict):
                            raise ValueError("admin action must return a JSON object")
                    elif method == "plugin.admin_page":
                        page_fn = getattr(plugin, "admin_page", None)
                        if page_fn is None:
                            result = {}
                        else:
                            value = page_fn(params.get("page_id"))
                            result = await value if inspect.isawaitable(value) else value
                            if not isinstance(result, dict):
                                raise ValueError("admin page values must be a JSON object")
                    elif method == "runtime.shutdown":
                        await _call(plugin, "shutdown")
                        result = {"stopped": True}
                    else:
                        raise LookupError("method not found")
                response = {"protocol": PROTOCOL_VERSION, "id": request_id, "result": result}
            except LookupError:
                response = {
                    "protocol": PROTOCOL_VERSION,
                    "id": request_id,
                    "error": {"code": "method_not_found", "message": "unknown plugin method"},
                }
            except Exception as exc:
                response = {
                    "protocol": PROTOCOL_VERSION,
                    "id": request_id,
                    "error": {"code": "plugin_error", "message": type(exc).__name__},
                }
        async with rpc._send_lock:
            await send_frame(sock, response)
        if method == "runtime.shutdown":
            shutdown_event.set()

    try:
        while True:
            message = await receive_frame(sock)
            if rpc.resolve(message):
                continue
            asyncio.create_task(handle(message))
            if message.get("method") == "runtime.shutdown":
                await shutdown_event.wait()
                return 0
    except EOFError, OSError, ValueError, ProtocolError:
        return 3
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--plugin-id", required=True)
    parser.add_argument("--plugin-version", required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--plugin-root", required=True)
    return asyncio.run(_serve(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
