"""Private child-process bootstrap. Third-party entrypoints are imported here only."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import json
import socket
import struct
from pathlib import Path
from typing import Any

from arborpress.plugins.protocol import MAX_MESSAGE_BYTES, PROTOCOL_VERSION
from arborpress.plugins.sdk import PluginContext


class _UnavailableRPC:
    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        raise RuntimeError("Core RPC methods are not available in plugin runtime v1")


def _read_exact(sock: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = sock.recv(size - len(output))
        if not chunk:
            raise EOFError("core closed private plugin channel")
        output.extend(chunk)
    return bytes(output)


def _receive(sock: socket.socket) -> dict[str, Any]:
    (length,) = struct.unpack("!I", _read_exact(sock, 4))
    if length > MAX_MESSAGE_BYTES:
        raise ValueError("oversized RPC frame")
    value = json.loads(_read_exact(sock, length).decode("utf-8"))
    if not isinstance(value, dict) or value.get("protocol") != PROTOCOL_VERSION:
        raise ValueError("unsupported RPC request")
    return value


def _send(sock: socket.socket, message: dict[str, Any]) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError("oversized RPC response")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


async def _call(target: object, name: str, *args: object) -> Any:
    method = getattr(target, name, None)
    if method is None:
        return None
    result = method(*args)
    return await result if inspect.isawaitable(result) else result


async def _serve(args: argparse.Namespace) -> int:
    sock = socket.socket(fileno=args.fd)
    sock.set_inheritable(False)
    module_name, _, attribute = args.entrypoint.partition(":")
    try:
        module = importlib.import_module(module_name)
        module_file = Path(getattr(module, "__file__", "")).resolve()
        module_file.relative_to(Path(args.plugin_root).resolve())
        plugin = getattr(module, attribute)
        if inspect.isclass(plugin):
            plugin = plugin()
    except Exception as exc:
        _send(
            sock,
            {
                "protocol": PROTOCOL_VERSION,
                "id": "initialize",
                "error": {"code": "import_error", "message": type(exc).__name__},
            },
        )
        return 2

    try:
        while True:
            request = await asyncio.to_thread(_receive, sock)
            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})
            if not isinstance(params, dict) or not isinstance(method, str):
                _send(
                    sock,
                    {
                        "protocol": PROTOCOL_VERSION,
                        "id": request_id,
                        "error": {"code": "invalid_request", "message": "invalid request shape"},
                    },
                )
                continue
            try:
                if method == "runtime.initialize":
                    if params.get("plugin_id") != args.plugin_id:
                        raise ValueError("plugin identity mismatch")
                    context = PluginContext(
                        plugin_id=args.plugin_id,
                        plugin_version=args.plugin_version,
                        arborpress_version=str(params.get("arborpress_version", "")),
                        runtime_version="1",
                        rpc=_UnavailableRPC(),
                    )
                    await _call(plugin, "initialize", context)
                    result = {
                        "ready": True,
                        "plugin_id": args.plugin_id,
                        "plugin_version": args.plugin_version,
                        "runtime_version": "1",
                        "features": [],
                    }
                elif method == "runtime.ping":
                    result = await _call(plugin, "ping") or {"ok": True}
                elif method == "runtime.shutdown":
                    await _call(plugin, "shutdown")
                    _send(
                        sock,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "id": request_id,
                            "result": {"stopped": True},
                        },
                    )
                    return 0
                else:
                    _send(
                        sock,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "id": request_id,
                            "error": {
                                "code": "method_not_found",
                                "message": "unknown lifecycle method",
                            },
                        },
                    )
                    continue
                _send(sock, {"protocol": PROTOCOL_VERSION, "id": request_id, "result": result})
            except Exception as exc:
                _send(
                    sock,
                    {
                        "protocol": PROTOCOL_VERSION,
                        "id": request_id,
                        "error": {"code": "plugin_error", "message": type(exc).__name__},
                    },
                )
                if method == "runtime.initialize":
                    return 2
    except EOFError, OSError, ValueError, json.JSONDecodeError:
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
    args = parser.parse_args()
    return asyncio.run(_serve(args))


if __name__ == "__main__":
    raise SystemExit(main())
