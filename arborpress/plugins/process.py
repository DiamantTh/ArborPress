"""Async one-process-per-plugin lifecycle over a private Unix socketpair."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import sys
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from arborpress import __version__
from arborpress.plugins.capabilities import (
    Capability,
    CapabilityGrantStore,
    missing_required_grants,
)
from arborpress.plugins.protocol import (
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_SHUTDOWN_TIMEOUT,
    DEFAULT_STARTUP_TIMEOUT,
    PROTOCOL_VERSION,
    ProtocolError,
    receive_frame,
    send_frame,
)
from arborpress.plugins.registry import PluginRecord, PluginSource, PluginStatus
from arborpress.plugins.rpc import PluginRPCDispatcher
from arborpress.runtime.paths import get_runtime_paths

log = logging.getLogger("arborpress.plugins.runtime")
audit_log = logging.getLogger("arborpress.audit")
_PACKAGE_ROOT = str(Path(__file__).resolve().parents[2])


@dataclass(slots=True)
class PluginProcess:
    record: PluginRecord
    process: asyncio.subprocess.Process
    channel: socket.socket
    stdout_task: asyncio.Task[None] | None = None
    stderr_task: asyncio.Task[None] | None = None
    exit_task: asyncio.Task[None] | None = None
    expected_shutdown: bool = False
    rpc_lock: asyncio.Lock = dataclass_field(default_factory=asyncio.Lock)
    event_queue: asyncio.Queue[dict[str, Any]] = dataclass_field(
        default_factory=lambda: asyncio.Queue(maxsize=100)
    )
    event_task: asyncio.Task[None] | None = None


class PluginProcessManager:
    """Owns independent subprocesses; never imports a third-party entrypoint."""

    def __init__(
        self,
        *,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT,
        dispatcher: PluginRPCDispatcher | None = None,
    ) -> None:
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.shutdown_timeout = shutdown_timeout
        self.dispatcher = dispatcher
        self._running: dict[str, PluginProcess] = {}
        self._request_ids: dict[str, int] = {}
        self._closing = False
        self._start_lock = asyncio.Lock()

    @property
    def running_ids(self) -> frozenset[str]:
        return frozenset(self._running)

    def pid_for(self, plugin_id: str) -> int | None:
        running = self._running.get(plugin_id)
        return running.process.pid if running else None

    def exit_status_for(self, plugin_id: str) -> int | None:
        running = self._running.get(plugin_id)
        return running.process.returncode if running else None

    async def start(self, record: PluginRecord) -> None:
        # Serialize descriptor handoff and startup status transitions. This
        # avoids concurrent spawn races while still allowing running plugins
        # to handle their own channels independently.
        async with self._start_lock:
            await self._start_process(record)

    async def _start_process(self, record: PluginRecord) -> None:
        if self._closing:
            raise RuntimeError("plugin manager is shutting down")
        if record.manifest is None or record.status in {
            PluginStatus.INVALID,
            PluginStatus.INCOMPATIBLE,
        }:
            raise ValueError(
                f"plugin {record.id} is not startable: {record.error or record.status}"
            )
        if record.source != PluginSource.THIRD_PARTY:
            raise ValueError("only third-party plugin records use the isolated host")
        paths = get_runtime_paths()
        grants = CapabilityGrantStore(paths.data / "plugin-grants.toml")
        missing = missing_required_grants(record.id, record.manifest.required_capabilities, grants)
        if missing:
            record.last_error = "missing_required_capabilities: " + ", ".join(missing)
            raise ValueError(record.last_error)
        if record.id in self._running:
            return
        record.runtime_status = PluginStatus.STARTING
        runtime_dir = paths.plugin_runtime / record.id
        data_dir = paths.plugin_data / record.id
        cache_dir = paths.plugin_cache / record.id
        run_dir = paths.plugin_run / record.id
        instance_root = paths.instance.resolve()
        for directory, root in (
            (runtime_dir, paths.plugin_runtime),
            (data_dir, paths.plugin_data),
            (cache_dir, paths.plugin_cache),
            (run_dir, paths.plugin_run),
        ):
            if not root.resolve().is_relative_to(instance_root):
                record.runtime_status = PluginStatus.FAILED
                raise ValueError("plugin runtime base path escapes the instance root")
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.resolve().parent != root.resolve():
                record.runtime_status = PluginStatus.FAILED
                raise ValueError("plugin runtime path escapes its instance root")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent.setblocking(False)
        child.set_inheritable(True)
        venv_python = runtime_dir / "venv" / "bin" / "python"
        executable = str(venv_python) if venv_python.is_file() else sys.executable
        record.interpreter = executable
        manifest = record.manifest
        command = [
            executable,
            "-P",
            "-m",
            "arborpress.plugins.host",
            "--fd",
            str(child.fileno()),
            "--plugin-id",
            manifest.id,
            "--plugin-version",
            manifest.version,
            "--entrypoint",
            manifest.entrypoint,
            "--plugin-root",
            str(record.directory.resolve()),
        ]
        # Deliberately do not inherit the Core environment. In particular, no
        # DB, SMTP, session, WebAuthn, or backup credentials enter the plugin.
        env = {
            "PATH": os.defpath,
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "PYTHONPATH": os.pathsep.join((_PACKAGE_ROOT, str(record.directory.resolve()))),
            "ARBORPRESS_PLUGIN_ID": manifest.id,
            "ARBORPRESS_PLUGIN_PROTOCOL": str(PROTOCOL_VERSION),
        }
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=record.directory.resolve(),
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                close_fds=True,
                pass_fds=(child.fileno(),),
                limit=16 * 1024,
                start_new_session=True,
            )
        except BaseException:
            parent.close()
            child.close()
            record.runtime_status = PluginStatus.FAILED
            raise
        child.close()
        running = PluginProcess(record, process, parent)
        self._running[record.id] = running
        running.exit_task = asyncio.create_task(self._watch_exit(running))
        self._save_status(record, process.pid)
        running.stdout_task = asyncio.create_task(
            self._drain_log(record.id, process.pid, "stdout", process.stdout)
        )
        running.stderr_task = asyncio.create_task(
            self._drain_log(record.id, process.pid, "stderr", process.stderr)
        )
        try:
            response = await self._request(
                running,
                "runtime.initialize",
                {
                    "protocol": PROTOCOL_VERSION,
                    "plugin_id": manifest.id,
                    "plugin_version": manifest.version,
                    "arborpress_version": __version__,
                    "runtime_version": "1",
                    "granted_capabilities": sorted(grants.grants_for(manifest.id)),
                },
                timeout=self.startup_timeout,
            )
            if (
                response.get("ready") is not True
                or response.get("plugin_id") != manifest.id
                or response.get("plugin_version") != manifest.version
            ):
                raise ProtocolError("plugin handshake identity or ready state mismatch")
            record.runtime_status = PluginStatus.RUNNING
            record.last_error = None
            self._save_status(record, process.pid)
            running.event_task = asyncio.create_task(self._event_worker(running))
            log.info("plugin started id=%s pid=%s", manifest.id, process.pid)
            audit_log.warning(
                "PLUGIN_PROCESS_START outcome=success plugin=%s pid=%s",
                manifest.id,
                process.pid,
            )
        except Exception as exc:
            child_exit_status = process.returncode
            await self._terminate(running)
            record.runtime_status = PluginStatus.FAILED
            record.error = f"startup failed: {type(exc).__name__}"
            record.last_error = type(exc).__name__
            if record.exit_status is None:
                record.exit_status = child_exit_status
            self._save_status(record, process.pid)
            log.error(
                "plugin startup failed id=%s pid=%s error=%s child_exit_status=%s",
                manifest.id,
                process.pid,
                type(exc).__name__,
                record.exit_status,
            )
            audit_log.warning(
                "PLUGIN_PROCESS_START outcome=failure plugin=%s error=%s",
                manifest.id,
                type(exc).__name__,
            )
            raise RuntimeError(record.error) from exc

    async def ping(self, plugin_id: str) -> dict[str, Any]:
        running = self._running.get(plugin_id)
        if running is None:
            raise RuntimeError(f"plugin process {plugin_id!r} is unavailable")
        result = await self._request(running, "runtime.ping", {}, timeout=self.request_timeout)
        if not isinstance(result, dict):
            raise ProtocolError("plugin ping result must be an object")
        return result

    async def execute_task(
        self, plugin_id: str, *, job_id: str, task: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        running = self._running.get(plugin_id)
        if running is None or running.record.manifest is None:
            raise RuntimeError("plugin process is unavailable")
        if task not in running.record.manifest.tasks:
            raise ValueError("task is not declared by this plugin")
        if Capability.JOBS_SCHEDULE.value not in CapabilityGrantStore(
            get_runtime_paths().data / "plugin-grants.toml"
        ).grants_for(plugin_id):
            raise PermissionError("jobs.schedule capability is not granted")
        result = await self._request(
            running,
            "plugin.task",
            {"job_id": job_id, "task": task, "payload": payload},
            timeout=self.request_timeout,
        )
        return result

    async def execute_admin_action(
        self, plugin_id: str, *, action_id: str, values: dict[str, Any]
    ) -> dict[str, Any]:
        running = self._running.get(plugin_id)
        if running is None or running.record.manifest is None:
            raise RuntimeError("plugin process is unavailable")
        if Capability.ADMIN_DECLARATIVE.value not in CapabilityGrantStore(
            get_runtime_paths().data / "plugin-grants.toml"
        ).grants_for(plugin_id):
            raise PermissionError("admin.declarative capability is not granted")
        descriptor = running.record.manifest.admin_ui or {}
        pages = cast(list[Any], descriptor.get("pages", []))
        actions = {
            action.get("id")
            for page in pages
            if isinstance(page, dict)
            for action in page.get("actions", [])
            if isinstance(action, dict)
        }
        if action_id not in actions:
            raise ValueError("admin action is not declared")
        return await self._request(
            running,
            "plugin.admin_action",
            {"action_id": action_id, "values": values},
            timeout=self.request_timeout,
        )

    async def get_admin_page(self, plugin_id: str, page_id: str) -> dict[str, Any]:
        running = self._running.get(plugin_id)
        if running is None or running.record.manifest is None:
            raise RuntimeError("plugin process is unavailable")
        if Capability.ADMIN_DECLARATIVE.value not in CapabilityGrantStore(
            get_runtime_paths().data / "plugin-grants.toml"
        ).grants_for(plugin_id):
            raise PermissionError("admin.declarative capability is not granted")
        pages = (running.record.manifest.admin_ui or {}).get("pages", [])
        if not isinstance(pages, list) or not any(
            isinstance(page, dict) and page.get("id") == page_id for page in pages
        ):
            raise ValueError("admin page is not declared")
        return await self._request(
            running,
            "plugin.admin_page",
            {"page_id": page_id},
            timeout=self.request_timeout,
        )

    async def stop(self, plugin_id: str) -> None:
        running = self._running.get(plugin_id)
        if running is None:
            return
        running.expected_shutdown = True
        running.record.runtime_status = PluginStatus.STOPPING
        try:
            await self._request(running, "runtime.shutdown", {}, timeout=self.shutdown_timeout)
            await asyncio.wait_for(running.process.wait(), timeout=self.shutdown_timeout)
        except Exception:
            await self._terminate(running)
        else:
            await self._finish_log_drain(running)
            self._close(running)
            running.record.runtime_status = PluginStatus.STOPPED
            self._save_status(running.record, running.process.pid)
            log.info("plugin stopped id=%s pid=%s", plugin_id, running.process.pid)
            audit_log.warning(
                "PLUGIN_PROCESS_STOP outcome=success plugin=%s pid=%s",
                plugin_id,
                running.process.pid,
            )

    async def shutdown(self) -> None:
        self._closing = True
        await asyncio.gather(
            *(self.stop(plugin_id) for plugin_id in list(self._running)), return_exceptions=True
        )

    def publish_event(self, event_name: str, payload: dict[str, Any]) -> int:
        """Best-effort bounded event fanout; the caller never waits on a plugin."""
        delivered = 0
        for plugin_id, running in tuple(self._running.items()):
            manifest = running.record.manifest
            if manifest is None or event_name not in manifest.event_subscriptions:
                continue
            grants = CapabilityGrantStore(get_runtime_paths().data / "plugin-grants.toml")
            if Capability.EVENTS_SUBSCRIBE.value not in grants.grants_for(plugin_id):
                continue
            try:
                running.event_queue.put_nowait({"type": event_name, **payload})
                delivered += 1
            except asyncio.QueueFull:
                log.warning(
                    "plugin_event_dropped plugin=%s event=%s reason=queue_full",
                    plugin_id,
                    event_name,
                )
        return delivered

    async def _request(
        self,
        running: PluginProcess,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float,
    ) -> dict[str, Any]:
        async with running.rpc_lock:
            return await self._request_unlocked(running, method, params, timeout=timeout)

    async def _request_unlocked(
        self,
        running: PluginProcess,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float,
    ) -> dict[str, Any]:
        plugin_id = running.record.id
        request_id = self._request_ids.get(plugin_id, 0) + 1
        self._request_ids[plugin_id] = request_id
        request = {
            "protocol": PROTOCOL_VERSION,
            "id": request_id,
            "method": method,
            "params": params,
        }
        try:
            await asyncio.wait_for(send_frame(running.channel, request), timeout=timeout)
            response = await asyncio.wait_for(receive_frame(running.channel), timeout=timeout)
            while response.get("id") != request_id:
                child_id = response.get("id")
                child_method = response.get("method")
                child_params = response.get("params", {})
                if child_id is None or not isinstance(child_method, str):
                    raise ProtocolError("unexpected plugin RPC frame")
                try:
                    if self.dispatcher is None:
                        raise RuntimeError("unavailable")
                    rpc_result = await asyncio.wait_for(
                        self.dispatcher.dispatch(
                            plugin_id,
                            child_method,
                            child_params,
                            declared_tasks=(
                                running.record.manifest.tasks if running.record.manifest else ()
                            ),
                            requested_capabilities=(
                                running.record.manifest.requested_capabilities
                                if running.record.manifest
                                else ()
                            ),
                        ),
                        timeout=timeout,
                    )
                    reply = {"protocol": PROTOCOL_VERSION, "id": child_id, "result": rpc_result}
                except Exception as exc:
                    code = getattr(exc, "code", "internal_error")
                    message = str(exc)[:200] if hasattr(exc, "code") else "Core RPC request failed"
                    reply = {
                        "protocol": PROTOCOL_VERSION,
                        "id": child_id,
                        "error": {"code": str(code)[:64], "message": message},
                    }
                await asyncio.wait_for(send_frame(running.channel, reply), timeout=timeout)
                response = await asyncio.wait_for(receive_frame(running.channel), timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"plugin {plugin_id} RPC timed out") from exc
        if response.get("id") != request_id:
            raise ProtocolError("RPC response id mismatch")
        error = response.get("error")
        if error is not None:
            if not isinstance(error, dict):
                raise ProtocolError("invalid RPC error response")
            raise RuntimeError(f"plugin RPC error: {str(error.get('code', 'plugin_error'))[:64]}")
        final_result: Any = response.get("result")
        if not isinstance(final_result, dict):
            raise ProtocolError("RPC result must be an object")
        return final_result

    async def _event_worker(self, running: PluginProcess) -> None:
        while running.process.returncode is None:
            event = await running.event_queue.get()
            try:
                await self._request(
                    running, "plugin.event", {"event": event}, timeout=self.request_timeout
                )
            except Exception as exc:
                log.warning(
                    "plugin event delivery failed plugin=%s error=%s",
                    running.record.id,
                    type(exc).__name__,
                )
            finally:
                running.event_queue.task_done()

    async def _terminate(self, running: PluginProcess) -> None:
        running.expected_shutdown = True
        process = running.process
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=self.shutdown_timeout)
            except TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
        await self._finish_log_drain(running)
        self._close(running)
        running.record.runtime_status = PluginStatus.STOPPED
        self._save_status(running.record, process.pid)

    async def _watch_exit(self, running: PluginProcess) -> None:
        code = await running.process.wait()
        running.record.exit_status = code
        if self._running.get(running.record.id) is running:
            self._running.pop(running.record.id, None)
            running.channel.close()
            running.record.runtime_status = (
                PluginStatus.STOPPED if running.expected_shutdown else PluginStatus.FAILED
            )
            running.record.last_error = None if running.expected_shutdown else "unexpected_exit"
            self._save_status(running.record, running.process.pid)
            if not running.expected_shutdown:
                log.error(
                    "plugin exited unexpectedly id=%s pid=%s exit_status=%s",
                    running.record.id,
                    running.process.pid,
                    code,
                )
                audit_log.warning(
                    "PLUGIN_PROCESS_EXIT outcome=unexpected plugin=%s exit_status=%s",
                    running.record.id,
                    code,
                )

    def _close(self, running: PluginProcess) -> None:
        self._running.pop(running.record.id, None)
        running.channel.close()
        for task in (running.stdout_task, running.stderr_task):
            if task is not None and not task.done():
                task.cancel()
        if running.event_task is not None and not running.event_task.done():
            running.event_task.cancel()

    async def _finish_log_drain(self, running: PluginProcess) -> None:
        tasks = [task for task in (running.stdout_task, running.stderr_task) if task is not None]
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=0.2)
            except TimeoutError:
                pass
        if (
            running.exit_task is not None
            and running.exit_task is not asyncio.current_task()
            and not running.exit_task.done()
        ):
            running.exit_task.cancel()

    @staticmethod
    def _save_status(record: PluginRecord, pid: int | None) -> None:
        from arborpress.plugins.runtime_state import write_status

        try:
            write_status(
                get_runtime_paths().plugin_run,
                record.id,
                {
                    "plugin_id": record.id,
                    "runtime_status": record.runtime_status.value,
                    "pid": pid,
                    "exit_status": record.exit_status,
                    "last_error": record.last_error,
                    "updated_at": datetime.now(UTC).isoformat(),
                },
            )
        except (OSError, ValueError) as exc:
            log.warning(
                "could not persist plugin runtime status id=%s error=%s",
                record.id,
                type(exc).__name__,
            )

    async def _drain_log(
        self,
        plugin_id: str,
        pid: int,
        stream_name: str,
        stream: asyncio.StreamReader | None,
    ) -> None:
        if stream is None:
            return
        count = 0
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            count += 1
            if count <= 100:
                log.info(
                    "plugin_output plugin=%s pid=%s stream=%s data=%r",
                    plugin_id,
                    pid,
                    stream_name,
                    chunk[:2048].decode("utf-8", "replace").rstrip(),
                )
            elif count == 101:
                log.warning(
                    "plugin_output_throttled plugin=%s pid=%s stream=%s",
                    plugin_id,
                    pid,
                    stream_name,
                )
