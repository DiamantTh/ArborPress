"""Private versioned length-prefixed JSON RPC transport for plugin hosts."""

from __future__ import annotations

import asyncio
import json
import socket
import struct
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1024 * 1024
DEFAULT_STARTUP_TIMEOUT = 10.0
DEFAULT_REQUEST_TIMEOUT = 30.0
DEFAULT_SHUTDOWN_TIMEOUT = 3.0
_HEADER = struct.Struct("!I")


class ProtocolError(Exception):
    """Invalid or unsupported RPC frame."""


def encode_frame(message: dict[str, Any]) -> bytes:
    try:
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("RPC message is not JSON serializable") from exc
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError("RPC message exceeds the maximum frame size")
    return _HEADER.pack(len(payload)) + payload


def decode_payload(payload: bytes) -> dict[str, Any]:
    try:
        result = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("malformed JSON RPC payload") from exc
    if not isinstance(result, dict):
        raise ProtocolError("RPC payload must be a JSON object")
    if result.get("protocol") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported RPC protocol version")
    return result


def decode_header(header: bytes) -> int:
    if len(header) != _HEADER.size:
        raise ProtocolError("truncated RPC frame header")
    (size,) = _HEADER.unpack(header)
    if size > MAX_MESSAGE_BYTES:
        raise ProtocolError("RPC frame exceeds the maximum frame size")
    return int(size)


def decode_frame(frame: bytes) -> dict[str, Any]:
    """Decode a complete frame; useful for deterministic protocol validation."""
    if len(frame) < _HEADER.size:
        raise ProtocolError("truncated RPC frame header")
    size = decode_header(frame[: _HEADER.size])
    payload = frame[_HEADER.size :]
    if len(payload) != size:
        raise ProtocolError("truncated RPC frame payload")
    return decode_payload(payload)


async def _recv_exact(sock: socket.socket, length: int) -> bytes:
    loop = asyncio.get_running_loop()
    data = bytearray()
    while len(data) < length:
        chunk = await loop.sock_recv(sock, length - len(data))
        if not chunk:
            raise EOFError("plugin RPC peer closed the channel")
        data.extend(chunk)
    return bytes(data)


async def send_frame(sock: socket.socket, message: dict[str, Any]) -> None:
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(sock, encode_frame(message))


async def receive_frame(sock: socket.socket) -> dict[str, Any]:
    header = await _recv_exact(sock, _HEADER.size)
    size = decode_header(header)
    return decode_payload(await _recv_exact(sock, size))


def encode_header(size: int) -> bytes:
    """Used by the stdlib-only host bootstrap; validates before allocation."""
    if size < 0 or size > MAX_MESSAGE_BYTES:
        raise ProtocolError("RPC frame exceeds the maximum frame size")
    return _HEADER.pack(size)
