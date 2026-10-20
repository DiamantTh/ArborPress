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
        current: dict[str, object] = {}
        try:
            with self.path.open("rb") as stream:
                current = tomllib.load(stream)
        except OSError, tomllib.TOMLDecodeError:
            pass
        auto_disabled = current.get("auto_disabled", [])
        if not isinstance(auto_disabled, list):
            auto_disabled = []
        auto_ids = {item for item in auto_disabled if isinstance(item, str)}
        if enabled:
            auto_ids.discard(plugin_id)
        content = "enabled = [\n" + "".join(f'  "{item}",\n' for item in sorted(values)) + "]\n"
        if auto_ids:
            content += (
                "auto_disabled = [\n"
                + "".join(f'  "{item}",\n' for item in sorted(auto_ids))
                + "]\n"
            )
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

    def auto_disabled_ids(self) -> set[str]:
        try:
            with self.path.open("rb") as stream:
                data = tomllib.load(stream)
        except OSError, tomllib.TOMLDecodeError:
            return set()
        values = data.get("auto_disabled", [])
        if not isinstance(values, list):
            return set()
        return {item for item in values if isinstance(item, str)}

    def set_auto_disabled(self, plugin_id: str, disabled: bool) -> None:
        if not PLUGIN_ID_RE.fullmatch(plugin_id):
            raise ValueError("invalid plugin ID")
        # Preserve both state sets through the normal atomic writer.
        enabled = self.enabled_ids()
        auto_ids = self.auto_disabled_ids()
        if disabled:
            enabled.discard(plugin_id)
            auto_ids.add(plugin_id)
        else:
            auto_ids.discard(plugin_id)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lines = ["enabled = ["]
        lines.extend(f'  "{item}",' for item in sorted(enabled))
        lines.append("]")
        if auto_ids:
            lines.append("auto_disabled = [")
            lines.extend(f'  "{item}",' for item in sorted(auto_ids))
            lines.append("]")
        fd, name = tempfile.mkstemp(prefix=".plugin-state-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write("\n".join(lines) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        except BaseException:
            Path(name).unlink(missing_ok=True)
            raise
