"""Sanitized ephemeral plugin process diagnostics under instance var/run."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def status_path(runtime_root: Path, plugin_id: str) -> Path:
    return runtime_root / plugin_id / "status.json"


def write_status(runtime_root: Path, plugin_id: str, payload: dict[str, Any]) -> None:
    root = runtime_root / plugin_id
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.resolve().parent != runtime_root.resolve():
        raise ValueError("plugin status path escapes runtime root")
    path = root / "status.json"
    fd, name = tempfile.mkstemp(prefix=".plugin-status-", dir=root)
    temporary = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def read_status(runtime_root: Path, plugin_id: str) -> dict[str, Any] | None:
    path = status_path(runtime_root, plugin_id)
    if path.is_symlink() or not path.is_file() or path.resolve().parent != path.parent.resolve():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None
