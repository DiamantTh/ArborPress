"""Instance-local plugin enablement state (not executable plugin metadata)."""

from __future__ import annotations

import os
import tempfile
import tomllib
from pathlib import Path

from arborpress.plugins.manifest import PLUGIN_ID_RE


class PluginStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def enabled_ids(self) -> set[str]:
        if not self.path.is_file():
            return set()
        try:
            with self.path.open("rb") as stream:
                data = tomllib.load(stream)
            values = data.get("enabled", [])
            if not isinstance(values, list):
                return set()
            return {item for item in values if isinstance(item, str)}
        except OSError, tomllib.TOMLDecodeError:
            return set()

    def set_enabled(self, plugin_id: str, enabled: bool) -> None:
        if not PLUGIN_ID_RE.fullmatch(plugin_id):
            raise ValueError("invalid plugin ID")
        values = self.enabled_ids()
        if enabled:
            values.add(plugin_id)
        else:
            values.discard(plugin_id)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        content = "enabled = [\n" + "".join(f'  "{item}",\n' for item in sorted(values)) + "]\n"
        fd, name = tempfile.mkstemp(prefix=".plugin-state-", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
