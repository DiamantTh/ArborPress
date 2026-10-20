from __future__ import annotations

import asyncio
import struct
import textwrap
import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from arborpress.plugins.manifest import PluginManifest
from arborpress.plugins.process import PluginProcessManager
from arborpress.plugins.protocol import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    decode_frame,
    decode_payload,
    encode_frame,
)
from arborpress.plugins.registry import PluginRegistry, PluginStatus


def _manifest(plugin_id: str, entrypoint: str = "worker:plugin", **overrides: object) -> str:
    values: dict[str, object] = {
        "manifest_version": 1,
        "id": plugin_id,
        "name": f"Plugin {plugin_id}",
        "version": "1.0.0",
        "author": "Test Suite",
        "license": "MIT",
        "requires_arborpress": ">=0.1.0",
        "entrypoint": entrypoint,
        "requested_capabilities": ["importer"],
        "required_capabilities": [],
        "python": ">=3.14,<3.15",
    }
    values.update(overrides)
    lines = []
    for key, value in values.items():
        if isinstance(value, str):
            encoded = f'"{value}"'
        elif isinstance(value, list):
            encoded = "[" + ", ".join(f'"{item}"' for item in value) + "]"
        else:
            encoded = str(value).lower()
        lines.append(f"{key} = {encoded}")
    return "\n".join(lines) + "\n"


def _write_plugin(root: Path, plugin_id: str, source: str) -> Path:
    directory = root / plugin_id
    directory.mkdir(parents=True)
    (directory / "plugin.toml").write_text(_manifest(plugin_id), encoding="utf-8")
    (directory / "worker.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return directory


def test_manifest_parses_versioned_plugin_contract(tmp_path: Path) -> None:
    path = tmp_path / "plugin.toml"
    path.write_text(_manifest("sample-plugin"), encoding="utf-8")
    manifest = PluginManifest.from_file(path)
    assert manifest.id == "sample-plugin"
    assert manifest.requested_capabilities == ("importer",)


@pytest.mark.parametrize(
    "override",
    [
        {"id": "../escape"},
        {"entrypoint": "os.system"},
        {"requires_arborpress": "future"},
        {"requested_capabilities": ["filesystem-root"]},
        {"manifest_version": 99},
    ],
)
def test_manifest_rejects_unsafe_or_unknown_contract(
    tmp_path: Path, override: dict[str, object]
) -> None:
    path = tmp_path / "plugin.toml"
    path.write_text(_manifest("sample-plugin", **override), encoding="utf-8")
    with pytest.raises(ValidationError):
        PluginManifest.from_file(path)


def test_manifest_missing_required_field_and_malformed_toml_fail(tmp_path: Path) -> None:
    path = tmp_path / "plugin.toml"
    path.write_text(
        _manifest("sample-plugin").replace('name = "Plugin sample-plugin"\n', ""), encoding="utf-8"
    )
    with pytest.raises(ValidationError):
        PluginManifest.from_file(path)
    path.write_text("manifest_version = [\n", encoding="utf-8")
    with pytest.raises(tomllib.TOMLDecodeError):
        PluginManifest.from_file(path)


def test_registry_keeps_invalid_and_incompatible_plugins_diagnostic(tmp_path: Path) -> None:
    invalid = tmp_path / "bad-name"
    invalid.mkdir()
    (invalid / "plugin.toml").write_text(_manifest("other-id"), encoding="utf-8")
    future = tmp_path / "future"
    future.mkdir()
    (future / "plugin.toml").write_text(
        _manifest("future", requires_arborpress=">=99.0"), encoding="utf-8"
    )
    registry = PluginRegistry()
    registry.load_directory(tmp_path)
    assert registry.get("other-id").status == PluginStatus.INVALID
    assert registry.get("future").status == PluginStatus.INCOMPATIBLE


def test_registry_detects_duplicate_ids_instead_of_shadowing(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    (first / "plugin.toml").write_text(_manifest("shared"), encoding="utf-8")
    (second / "plugin.toml").write_text(_manifest("shared"), encoding="utf-8")
    registry = PluginRegistry()
    registry.load_directory(tmp_path)
    assert registry.get("shared").status == PluginStatus.INVALID
    assert "collision" in registry.get("shared").error


def test_enabled_state_is_instance_scoped(tmp_path: Path) -> None:
    from arborpress.plugins.state import PluginStateStore

    first = PluginStateStore(tmp_path / "a" / "instance" / "data" / "plugin-state.toml")
    second = PluginStateStore(tmp_path / "b" / "instance" / "data" / "plugin-state.toml")
    first.set_enabled("sample-plugin", True)
    assert first.enabled_ids() == {"sample-plugin"}
    assert second.enabled_ids() == set()
    first.set_enabled("sample-plugin", False)
    assert first.enabled_ids() == set()


def test_discovery_uses_prefix_roots_not_foreign_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.core.config import reset_settings
    from arborpress.plugins.registry import discover_instance_plugins
    from arborpress.runtime.paths import ArborPressPaths, reset_runtime_for_tests

    prefix = tmp_path / "prefix"
    foreign = tmp_path / "foreign"
    prefix_paths = ArborPressPaths.from_prefix(prefix)
    prefix_paths.plugins.mkdir(parents=True)
    _write_plugin(prefix_paths.plugins, "in-instance", "plugin = object()")
    (foreign / "plugins" / "cwd-only").mkdir(parents=True)
    (foreign / "plugins" / "cwd-only" / "plugin.toml").write_text(
        _manifest("cwd-only"), encoding="utf-8"
    )
    reset_runtime_for_tests(prefix)
    reset_settings()
    monkeypatch.chdir(foreign)
    registry = discover_instance_plugins()
    assert registry.get("in-instance") is not None
    assert registry.get("cwd-only") is None


def test_rpc_json_frame_limits_and_protocol_validation() -> None:
    payload = encode_frame({"protocol": PROTOCOL_VERSION, "id": 1, "method": "runtime.ping"})
    assert len(payload) > 4
    with pytest.raises(ProtocolError):
        encode_frame({"protocol": PROTOCOL_VERSION, "blob": "x" * (MAX_MESSAGE_BYTES + 1)})
    with pytest.raises(ProtocolError):
        decode_payload(b"not json")
    with pytest.raises(ProtocolError):
        decode_payload(b'{"protocol":999}')

    with pytest.raises(ProtocolError, match="maximum frame"):
        decode_frame(struct.pack("!I", MAX_MESSAGE_BYTES + 1))
    with pytest.raises(ProtocolError, match="truncated RPC frame header"):
        decode_frame(b"\x00\x01")
    with pytest.raises(ProtocolError, match="truncated RPC frame payload"):
        decode_frame(struct.pack("!I", 8) + b"{}")


def test_two_plugins_run_in_distinct_processes_without_parent_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.runtime.paths import get_runtime_paths

    monkeypatch.setenv("DATABASE_URL", "do-not-inherit")
    plugin_a = _write_plugin(
        tmp_path,
        "plugin-a",
        """
        import os
        from pathlib import Path
        class Worker:
            async def initialize(self, context):
                Path(__file__).with_name('env.txt').write_text(
                    repr({k: os.environ.get(k) for k in (
                        'DATABASE_URL', 'SMTP_PASSWORD', 'ARBORPRESS_MASTER_SECRET',
                        'HOME', 'ARBORPRESS_PLUGIN_ID'
                    )})
                )
            async def ping(self): return {'pong': True}
        plugin = Worker
        """,
    )
    plugin_b = _write_plugin(
        tmp_path,
        "plugin-b",
        """
        class Worker:
            async def initialize(self, context): pass
            async def ping(self): return {'pong': True}
        plugin = Worker
        """,
    )
    manager = PluginProcessManager()

    async def exercise() -> tuple[int, int]:
        registry = PluginRegistry()
        records = []
        for directory in (plugin_a, plugin_b):
            registry.load_directory(directory.parent)
        # Both roots can share one parent, so registry discovery is direct.
        records = [registry.get("plugin-a"), registry.get("plugin-b")]
        await asyncio.gather(*(manager.start(record) for record in records))
        pids = (manager.pid_for("plugin-a"), manager.pid_for("plugin-b"))
        assert await manager.ping("plugin-a") == {"pong": True}
        assert await manager.ping("plugin-b") == {"pong": True}
        with pytest.raises(RuntimeError, match="method_not_found"):
            await manager._request(
                manager._running["plugin-a"],
                "arbitrary.core_method",
                {},
                timeout=1,
            )
        await manager.shutdown()
        return pids

    pids = asyncio.run(exercise())
    assert pids[0] is not None and pids[1] is not None
    assert pids[0] != pids[1]
    assert "do-not-inherit" not in (plugin_a / "env.txt").read_text(encoding="utf-8")
    assert (plugin_a / "env.txt").read_text(encoding="utf-8").find("DATABASE_URL': None") >= 0
    environment = (plugin_a / "env.txt").read_text(encoding="utf-8")
    for secret_key in ("SMTP_PASSWORD", "ARBORPRESS_MASTER_SECRET", "HOME"):
        assert f"'{secret_key}': None" in environment
    paths = get_runtime_paths()
    assert paths.plugin_runtime.is_dir()
    assert (paths.plugin_data / "plugin-a").is_dir()
    assert (paths.plugin_cache / "plugin-a").is_dir()
    assert (paths.plugin_run / "plugin-a").is_dir()


def test_plugin_host_bootstraps_from_empty_isolated_venv(tmp_path: Path) -> None:
    import venv

    from arborpress.runtime.paths import get_runtime_paths

    plugin_dir = _write_plugin(
        tmp_path,
        "isolated-venv",
        """
        class Worker:
            async def initialize(self, context): pass
            async def ping(self): return {'venv': True}
        plugin = Worker
        """,
    )
    registry = PluginRegistry()
    registry.load_directory(plugin_dir.parent)
    record = registry.get("isolated-venv")
    runtime = get_runtime_paths().plugin_runtime / "isolated-venv"
    runtime.mkdir(parents=True, exist_ok=True)
    venv.EnvBuilder(with_pip=False).create(runtime / "venv")
    manager = PluginProcessManager()

    async def exercise() -> None:
        await manager.start(record)
        assert record.interpreter.endswith("/isolated-venv/venv/bin/python")
        assert await manager.ping("isolated-venv") == {"venv": True}
        await manager.shutdown()

    asyncio.run(exercise())


def test_hanging_plugin_times_out_and_is_terminated(tmp_path: Path) -> None:
    _write_plugin(
        tmp_path,
        "hang",
        """
        import asyncio
        class Worker:
            async def initialize(self, context): await asyncio.sleep(5)
        plugin = Worker
        """,
    )
    registry = PluginRegistry()
    registry.load_directory(tmp_path)
    manager = PluginProcessManager(startup_timeout=0.15, shutdown_timeout=0.15)

    async def exercise() -> None:
        with pytest.raises(RuntimeError, match="startup failed"):
            await manager.start(registry.get("hang"))
        assert not manager.running_ids

    asyncio.run(exercise())


def test_plugin_request_timeout_does_not_block_core_shutdown(tmp_path: Path) -> None:
    _write_plugin(
        tmp_path,
        "slow-ping",
        """
        import asyncio
        class Worker:
            async def initialize(self, context): pass
            async def ping(self):
                await asyncio.sleep(5)
                return {'alive': True}
        plugin = Worker
        """,
    )
    registry = PluginRegistry()
    registry.load_directory(tmp_path)
    manager = PluginProcessManager(request_timeout=0.1, shutdown_timeout=0.1)

    async def exercise() -> None:
        await manager.start(registry.get("slow-ping"))
        with pytest.raises(TimeoutError, match="RPC timed out"):
            await manager.ping("slow-ping")
        await manager.shutdown()
        assert not manager.running_ids

    asyncio.run(exercise())


def test_plugin_crash_isolated_from_another_plugin(tmp_path: Path) -> None:
    stable = _write_plugin(
        tmp_path,
        "stable-plugin",
        """
        class Worker:
            async def initialize(self, context): pass
            async def ping(self): return {'alive': True}
        plugin = Worker
        """,
    )
    _write_plugin(
        tmp_path,
        "crashing-plugin",
        """
        class Worker:
            async def initialize(self, context): raise SystemExit(17)
        plugin = Worker
        """,
    )
    registry = PluginRegistry()
    registry.load_directory(stable.parent)
    manager = PluginProcessManager(startup_timeout=2)

    async def exercise() -> None:
        await manager.start(registry.get("stable-plugin"))
        with pytest.raises(RuntimeError, match="startup failed"):
            await manager.start(registry.get("crashing-plugin"))
        assert manager.running_ids == {"stable-plugin"}
        assert await manager.ping("stable-plugin") == {"alive": True}
        await manager.shutdown()

    asyncio.run(exercise())
