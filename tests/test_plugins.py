from __future__ import annotations

import asyncio
import hashlib
import struct
import sys
import textwrap
import tomllib
import zipfile
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


def _local_plugin_bundle(
    destination: Path,
    plugin_id: str,
    version: str,
    worker: str = "class Plugin:\n    pass\nplugin = Plugin()\n",
    requested: tuple[str, ...] = (),
) -> Path:
    manifest = _manifest(
        plugin_id,
        version=version,
        requested_capabilities=list(requested),
        required_capabilities=[],
    ).encode()
    members = {"plugin.toml": manifest, "package/worker.py": worker.encode()}
    checksum = "".join(
        f"{hashlib.sha256(value).hexdigest()}  {name}\n" for name, value in sorted(members.items())
    ).encode()
    path = destination / f"{plugin_id}-{version}.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
        archive.writestr("checksums.sha256", checksum)
    return path


def test_local_plugin_install_stages_venv_and_defaults_disabled(tmp_path: Path) -> None:
    from arborpress.plugins.lifecycle import PluginLifecycle, verify_installed_package
    from arborpress.plugins.state import PluginStateStore
    from arborpress.runtime.paths import initialize_runtime, reset_runtime_for_tests

    paths = initialize_runtime(tmp_path / "prefix-a", override=True)
    try:
        bundle = _local_plugin_bundle(tmp_path, "local-one", "1.0.0")
        installed = PluginLifecycle(paths).install(bundle)
        assert installed.manifest.id == "local-one"
        assert (paths.plugins / "local-one" / "worker.py").is_file()
        assert (paths.plugin_runtime / "local-one" / "venv" / "bin" / "python").is_file()
        assert "local-one" not in PluginStateStore(paths.data / "plugin-state.toml").enabled_ids()
        assert (paths.data / "plugin-installations" / "local-one.json").is_file()
        package = paths.plugins / "local-one"
        assert verify_installed_package(paths, "local-one", package)
        (package / "worker.py").write_text("# modified\n", encoding="utf-8")
        assert not verify_installed_package(paths, "local-one", package)
    finally:
        reset_runtime_for_tests()


def test_plugin_update_preserves_data_and_does_not_grant_new_capabilities(tmp_path: Path) -> None:
    from arborpress.plugins.capabilities import CapabilityGrantStore
    from arborpress.plugins.lifecycle import PluginLifecycle
    from arborpress.plugins.state import PluginStateStore
    from arborpress.runtime.paths import initialize_runtime, reset_runtime_for_tests

    paths = initialize_runtime(tmp_path / "prefix-b", override=True)
    try:
        lifecycle = PluginLifecycle(paths)
        lifecycle.install(_local_plugin_bundle(tmp_path, "local-two", "1.0.0"))
        data_root = paths.plugin_data / "local-two"
        data_root.mkdir(parents=True, exist_ok=True)
        (data_root / "state.json").write_text("{}", encoding="utf-8")
        updated = lifecycle.update(
            "local-two",
            _local_plugin_bundle(
                tmp_path,
                "local-two",
                "1.1.0",
                requested=("storage.kv",),
            ),
        )
        assert updated.manifest.version == "1.1.0"
        assert updated.added_capabilities == ("storage.kv",)
        assert updated.removed_capabilities == ()
        assert not CapabilityGrantStore(paths.data / "plugin-grants.toml").grants_for("local-two")
        assert (data_root / "state.json").read_text(encoding="utf-8") == "{}"
        from arborpress.plugins.lifecycle import PluginLifecycleError

        failing_worker = "\n".join(
            (
                "class Plugin:",
                "    def initialize(self, context):",
                "        raise RuntimeError('bad startup')",
                "plugin = Plugin()",
            )
        )
        failing_update = _local_plugin_bundle(
            tmp_path,
            "local-two",
            "1.2.0",
            worker=failing_worker,
        )
        with pytest.raises(PluginLifecycleError):
            lifecycle.update("local-two", failing_update)
        current = PluginManifest.from_file(paths.plugins / "local-two" / "plugin.toml")
        assert current.version == "1.1.0"
        lifecycle.uninstall("local-two")
        assert not (paths.plugins / "local-two").exists()
        assert (data_root / "state.json").exists()
        assert "local-two" not in PluginStateStore(paths.data / "plugin-state.toml").enabled_ids()
    finally:
        reset_runtime_for_tests()


def test_plugin_bundle_rejects_path_traversal(tmp_path: Path) -> None:
    from arborpress.plugins.lifecycle import PluginLifecycle, PluginLifecycleError
    from arborpress.runtime.paths import initialize_runtime, reset_runtime_for_tests

    paths = initialize_runtime(tmp_path / "prefix-c", override=True)
    try:
        bundle = tmp_path / "unsafe.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("../escape.py", "pass")
        with pytest.raises(PluginLifecycleError):
            PluginLifecycle(paths).install(bundle)
        assert not (paths.prefix / "escape.py").exists()
    finally:
        reset_runtime_for_tests()


def test_plugin_supervisor_bounded_restart_then_persists_auto_disable(tmp_path: Path) -> None:
    from arborpress.plugins.registry import PluginRecord, PluginStatus
    from arborpress.plugins.state import PluginStateStore
    from arborpress.plugins.supervisor import PluginSupervisor

    class Manager:
        @staticmethod
        def _save_status(record, pid):
            del record, pid

    store = PluginStateStore(tmp_path / "instance" / "data" / "plugin-state.toml")
    store.set_enabled("supervised", True)
    record = PluginRecord(
        PluginManifest.model_validate(
            tomllib.loads(_manifest("supervised", requested_capabilities=[]))
        ),
        tmp_path / "supervised",
        enabled=True,
    )
    supervisor = PluginSupervisor(Manager(), store, max_restarts=1, backoff=(0.01,))
    supervisor._record_failure(record, "startup")
    assert record.runtime_status != PluginStatus.AUTO_DISABLED
    supervisor._record_failure(record, "startup")
    assert record.runtime_status == PluginStatus.AUTO_DISABLED
    assert "supervised" in store.auto_disabled_ids()
    assert "supervised" not in store.enabled_ids()


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


def test_required_capability_must_be_locally_granted_before_start(tmp_path: Path) -> None:
    from arborpress.runtime.paths import get_runtime_paths

    plugin_dir = _write_plugin(tmp_path, "requires-kv", "plugin = object()")
    (plugin_dir / "plugin.toml").write_text(
        _manifest(
            "requires-kv",
            requested_capabilities=["storage.kv"],
            required_capabilities=["storage.kv"],
        ),
        encoding="utf-8",
    )
    registry = PluginRegistry()
    registry.load_directory(plugin_dir.parent)
    manager = PluginProcessManager()

    async def exercise() -> None:
        with pytest.raises(ValueError, match="missing_required_capabilities"):
            await manager.start(registry.get("requires-kv"))
        assert not manager.running_ids

    asyncio.run(exercise())
    assert not (get_runtime_paths().plugin_run / "requires-kv").exists()


def test_capability_change_uses_registered_sensitive_stepup_operation() -> None:
    from arborpress.auth.stepup import require_stepup

    assert require_stepup("plugin_capability_change") is True


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


def test_capability_grants_are_local_and_only_known_requested_values(tmp_path: Path) -> None:
    from arborpress.plugins.capabilities import CapabilityError, CapabilityGrantStore

    first = CapabilityGrantStore(tmp_path / "a" / "instance" / "data" / "plugin-grants.toml")
    second = CapabilityGrantStore(tmp_path / "b" / "instance" / "data" / "plugin-grants.toml")
    first.set_grant("alpha", "storage.kv", True)
    assert first.grants_for("alpha") == {"storage.kv"}
    assert second.grants_for("alpha") == set()
    with pytest.raises(CapabilityError):
        first.set_grant("alpha", "database", True)
    first.set_grant("alpha", "storage.kv", False)
    assert first.grants_for("alpha") == set()


def test_admin_descriptor_rejects_raw_html_and_script_fields(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(
            {
                "manifest_version": 1,
                "id": "admin-plugin",
                "name": "Admin Plugin",
                "version": "1.0.0",
                "author": "test",
                "license": "MIT",
                "requires_arborpress": ">=0.1.0",
                "entrypoint": "worker:plugin",
                "admin_ui": {
                    "pages": [
                        {
                            "id": "main",
                            "title": "Settings",
                            "fields": [{"id": "raw", "label": "Raw", "type": "html"}],
                            "actions": [],
                        }
                    ]
                },
            }
        )


@pytest.mark.asyncio
async def test_plugin_rpc_dispatch_requires_grant_and_scopes_storage(
    test_engine, tmp_path: Path
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.plugins.capabilities import CapabilityGrantStore
    from arborpress.plugins.rpc import PluginRPCDispatcher
    from arborpress.plugins.services import PluginCoreServices

    sessions = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    grants = CapabilityGrantStore(tmp_path / "plugin-grants.toml")
    dispatcher = PluginRPCDispatcher(PluginCoreServices(sessions), grants)
    with pytest.raises(Exception, match="capability is not granted"):
        await dispatcher.dispatch(
            "alpha",
            "core.storage.set",
            {"key": "k", "value": "a"},
            requested_capabilities=("storage.kv",),
        )
    grants.set_grant("alpha", "storage.kv", True)
    grants.set_grant("beta", "storage.kv", True)
    assert await dispatcher.dispatch(
        "alpha",
        "core.storage.set",
        {"key": "shared", "value": {"n": 1}, "plugin_id": "beta"},
        requested_capabilities=("storage.kv",),
    ) == {"revision": 1}
    assert (
        await dispatcher.dispatch(
            "alpha", "core.storage.get", {"key": "shared"}, requested_capabilities=("storage.kv",)
        )
    ) == {
        "found": True,
        "value": {"n": 1},
        "revision": 1,
    }
    assert (
        await dispatcher.dispatch(
            "beta", "core.storage.get", {"key": "shared"}, requested_capabilities=("storage.kv",)
        )
    ) == {
        "found": False,
        "value": None,
        "revision": None,
    }
    with pytest.raises(Exception, match="unknown Core RPC"):
        await dispatcher.dispatch(
            "alpha", "core.db.query", {"sql": "select 1"}, requested_capabilities=("storage.kv",)
        )
    with pytest.raises(Exception, match="not requested"):
        await dispatcher.dispatch("alpha", "core.storage.get", {"key": "shared"})


@pytest.mark.asyncio
async def test_plugin_storage_optimistic_revision_and_quota_error(
    test_engine, tmp_path: Path
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.plugins.services import PluginCoreServices, PluginServiceError

    services = PluginCoreServices(async_sessionmaker(bind=test_engine, expire_on_commit=False))
    assert await services.storage_set("alpha", {"key": "counter", "value": 1}) == {"revision": 1}
    assert await services.storage_set(
        "alpha", {"key": "counter", "value": 2, "expected_revision": 1}
    ) == {"revision": 2}
    with pytest.raises(PluginServiceError, match="revision changed"):
        await services.storage_set("alpha", {"key": "counter", "value": 3, "expected_revision": 1})
    with pytest.raises(PluginServiceError, match="per-value"):
        await services.storage_set("alpha", {"key": "large", "value": "x" * 70000})


@pytest.mark.asyncio
async def test_plugin_jobs_are_declared_leased_and_retry_bounded(test_engine) -> None:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.plugins.services import PluginCoreServices, PluginServiceError

    services = PluginCoreServices(async_sessionmaker(bind=test_engine, expire_on_commit=False))
    scheduled = await services.schedule_job(
        "alpha", {"task": "refresh", "payload": {"page": 1}}, ("refresh",)
    )
    duplicate = await services.schedule_job(
        "alpha",
        {
            "task": "refresh",
            "payload": {"page": 1},
            "delay_seconds": 3600,
            "idempotency_key": "same",
        },
        ("refresh",),
    )
    assert duplicate["duplicate"] is False
    with pytest.raises(PluginServiceError, match="not declared"):
        await services.schedule_job("alpha", {"task": "undeclared"}, ("refresh",))
    job = await services.claim_due_job(
        datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=1)
    )
    assert job is not None and job.id == scheduled["job_id"]
    assert job.status == "running" and job.attempts == 1
    await services.finish_job(job.id, error="timeout")
    assert await services.claim_due_job() is None


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

    async def exercise() -> tuple[tuple[int | None, int | None], tuple[str, ...]]:
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
        return pids, records[0].hardening

    pids, hardening = asyncio.run(exercise())
    assert pids[0] is not None and pids[1] is not None
    assert pids[0] != pids[1]
    assert "umask" in hardening
    if sys.platform.startswith("linux"):
        assert "no_new_privs" in hardening
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


@pytest.mark.asyncio
async def test_private_rpc_calls_core_storage_from_child_process(
    tmp_path: Path, test_engine
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.plugins.capabilities import CapabilityGrantStore
    from arborpress.plugins.rpc import PluginRPCDispatcher
    from arborpress.plugins.services import PluginCoreServices
    from arborpress.runtime.paths import get_runtime_paths

    plugin_dir = _write_plugin(
        tmp_path,
        "rpc-worker",
        """
        class Worker:
            async def initialize(self, context):
                await context.storage.set('boot', {'ready': True})
            async def ping(self): return {'pong': True}
        plugin = Worker
        """,
    )
    # Replace the fixture manifest using its real, immutable manifest contract.
    (plugin_dir / "plugin.toml").write_text(
        _manifest("rpc-worker", requested_capabilities=["storage.kv"]), encoding="utf-8"
    )
    registry = PluginRegistry()
    registry.load_directory(plugin_dir.parent)
    record = registry.get("rpc-worker")
    grants = CapabilityGrantStore(get_runtime_paths().data / "plugin-grants.toml")
    grants.set_grant("rpc-worker", "storage.kv", True)
    manager = PluginProcessManager(
        dispatcher=PluginRPCDispatcher(
            PluginCoreServices(async_sessionmaker(bind=test_engine, expire_on_commit=False)), grants
        )
    )

    async def exercise() -> None:
        await manager.start(record)
        assert await manager.ping("rpc-worker") == {"pong": True}
        await manager.shutdown()

    await exercise()


def test_subscribed_plugin_receives_only_core_event_dto(tmp_path: Path) -> None:
    from arborpress.plugins.capabilities import CapabilityGrantStore
    from arborpress.runtime.paths import get_runtime_paths

    plugin_dir = _write_plugin(
        tmp_path,
        "event-worker",
        """
        import json
        from pathlib import Path
        class Worker:
            async def handle_event(self, event):
                Path(__file__).with_name('event.json').write_text(json.dumps(event))
        plugin = Worker
        """,
    )
    (plugin_dir / "plugin.toml").write_text(
        _manifest(
            "event-worker",
            requested_capabilities=["events.subscribe"],
            events=["post.published"],
        ),
        encoding="utf-8",
    )
    registry = PluginRegistry()
    registry.load_directory(plugin_dir.parent)
    record = registry.get("event-worker")
    CapabilityGrantStore(get_runtime_paths().data / "plugin-grants.toml").set_grant(
        "event-worker", "events.subscribe", True
    )
    manager = PluginProcessManager()

    async def exercise() -> None:
        await manager.start(record)
        assert manager.publish_event("post.published", {"id": "p1"}) == 1
        for _ in range(50):
            if (plugin_dir / "event.json").exists():
                break
            await asyncio.sleep(0.02)
        await manager.shutdown()

    asyncio.run(exercise())
    payload = __import__("json").loads((plugin_dir / "event.json").read_text(encoding="utf-8"))
    assert payload == {"type": "post.published", "id": "p1"}


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
