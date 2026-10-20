"""Offline, staged lifecycle operations for locally supplied plugin bundles."""

from __future__ import annotations

import asyncio
import email
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import venv
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from uuid import uuid4

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from arborpress import __version__
from arborpress.plugins.manifest import PLUGIN_ID_RE, PluginManifest
from arborpress.runtime.paths import ArborPressPaths, get_runtime_paths

_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")
_MAX_BUNDLE_BYTES = 512 * 1024 * 1024
_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_MEMBERS = 20_000
_MAX_TOTAL_UNPACKED = 1024 * 1024 * 1024


class PluginLifecycleError(RuntimeError):
    """A local plugin lifecycle operation cannot safely proceed."""


@dataclass(frozen=True, slots=True)
class ValidatedBundle:
    manifest: PluginManifest
    package: Path
    wheels: Path
    bundle_digest: str
    added_capabilities: tuple[str, ...]
    removed_capabilities: tuple[str, ...]


class PluginLifecycle:
    """Install/update/uninstall local ZIP bundles without remote resolution."""

    def __init__(self, paths: ArborPressPaths | None = None) -> None:
        self.paths = paths or get_runtime_paths()
        self.installations = self.paths.data / "plugin-installations"

    def install(self, bundle_path: Path) -> ValidatedBundle:
        bundle = self._stage(bundle_path)
        try:
            if (self.paths.plugins / bundle.manifest.id).exists():
                raise PluginLifecycleError("plugin ID is already installed")
            self._commit(bundle, is_update=False)
            return bundle
        finally:
            self._cleanup_stage(bundle)

    def update(self, plugin_id: str, bundle_path: Path) -> ValidatedBundle:
        if not PLUGIN_ID_RE.fullmatch(plugin_id):
            raise PluginLifecycleError("invalid plugin ID")
        live = self.paths.plugins / plugin_id
        if not live.is_dir() or live.is_symlink():
            raise PluginLifecycleError("plugin package is not installed")
        if not verify_installed_package(self.paths, plugin_id, live):
            raise PluginLifecycleError("installed plugin package digest mismatch")
        if _pid_is_running(self.paths.plugin_run / plugin_id / "status.json"):
            raise PluginLifecycleError("plugin process is active; stop ArborPress before updating")
        bundle = self._stage(bundle_path)
        try:
            if bundle.manifest.id != plugin_id:
                raise PluginLifecycleError("update bundle ID must match installed plugin ID")
            current = PluginManifest.from_file(live / "plugin.toml")
            if Version(bundle.manifest.version) <= Version(current.version):
                raise PluginLifecycleError("update version must be newer than installed version")
            self._commit(bundle, is_update=True)
            return bundle
        finally:
            self._cleanup_stage(bundle)

    def uninstall(self, plugin_id: str, *, purge: bool = False) -> None:
        if not PLUGIN_ID_RE.fullmatch(plugin_id):
            raise PluginLifecycleError("invalid plugin ID")
        if _pid_is_running(self.paths.plugin_run / plugin_id / "status.json"):
            raise PluginLifecycleError("plugin process is active; disable it before uninstall")
        package = self.paths.plugins / plugin_id
        runtime = self.paths.plugin_runtime / plugin_id
        data = self.paths.plugin_data / plugin_id
        state = self.installations / f"{plugin_id}.json"
        if state.is_symlink() or not state.is_file():
            raise PluginLifecycleError("plugin was not installed from a managed local bundle")
        _assert_instance_root(self.paths.plugin_data, self.paths.instance)
        _assert_instance_root(self.paths.plugins, self.paths.instance)
        _assert_instance_root(self.paths.plugin_runtime, self.paths.instance)
        with _lifecycle_lock(self.paths, plugin_id):
            if _pid_is_running(self.paths.plugin_run / plugin_id / "status.json"):
                raise PluginLifecycleError("plugin process became active during uninstall")
            _remove_tree(package, self.paths.plugins)
            _remove_tree(runtime, self.paths.plugin_runtime)
            state.unlink(missing_ok=True)
            from arborpress.plugins.capabilities import CapabilityGrantStore
            from arborpress.plugins.state import PluginStateStore

            state_store = PluginStateStore(self.paths.data / "plugin-state.toml")
            state_store.set_enabled(plugin_id, False)
            state_store.set_auto_disabled(plugin_id, False)
            grants_path = self.paths.data / "plugin-grants.toml"
            grants = CapabilityGrantStore(grants_path)
            for capability in grants.grants_for(plugin_id):
                grants.set_grant(plugin_id, capability, False)
            if purge:
                _remove_tree(data, self.paths.plugin_data)

    def _stage(self, bundle_path: Path) -> ValidatedBundle:
        _assert_instance_root(self.paths.tmp, self.paths.instance)
        supplied = bundle_path.expanduser()
        if supplied.is_symlink() or not supplied.is_file():
            raise PluginLifecycleError("bundle must be a local regular ZIP file")
        source = supplied.resolve()
        if source.stat().st_size > _MAX_BUNDLE_BYTES:
            raise PluginLifecycleError("bundle exceeds the compressed size limit")
        token = uuid4().hex
        self.paths.tmp.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage_root = self.paths.tmp / f"plugin-stage-{token}"
        package = stage_root / "package"
        wheels = stage_root / "wheels"
        package.mkdir(parents=True, mode=0o700)
        wheels.mkdir(mode=0o700)
        try:
            manifest, digest = _extract_bundle(source, package, wheels)
            if not SpecifierSet(manifest.requires_arborpress).contains(
                Version(__version__), prereleases=True
            ):
                raise PluginLifecycleError("plugin requires an incompatible ArborPress version")
            if not SpecifierSet(manifest.python).contains(
                Version(
                    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                ),
                prereleases=True,
            ):
                raise PluginLifecycleError("plugin does not support this Python runtime")
            old_capabilities: set[str] = set()
            existing = self.paths.plugins / manifest.id / "plugin.toml"
            if existing.is_file() and not existing.is_symlink():
                old_capabilities = set(PluginManifest.from_file(existing).requested_capabilities)
            new_capabilities = set(manifest.requested_capabilities)
            added = tuple(sorted(new_capabilities - old_capabilities))
            removed = tuple(sorted(old_capabilities - new_capabilities))
            return ValidatedBundle(manifest, package, wheels, digest, added, removed)
        except BaseException:
            shutil.rmtree(stage_root, ignore_errors=True)
            raise

    def _commit(self, bundle: ValidatedBundle, *, is_update: bool) -> None:
        plugin_id = bundle.manifest.id
        package_root = self.paths.plugins
        runtime_root = self.paths.plugin_runtime
        _assert_instance_root(package_root, self.paths.instance)
        _assert_instance_root(runtime_root, self.paths.instance)
        _assert_instance_root(self.installations, self.paths.instance)
        package_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.installations.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _lifecycle_lock(self.paths, plugin_id):
            if _pid_is_running(self.paths.plugin_run / plugin_id / "status.json"):
                raise PluginLifecycleError("plugin process became active during lifecycle switch")
            package_target = package_root / plugin_id
            runtime_target = runtime_root / plugin_id
            if package_target.is_symlink() or runtime_target.is_symlink():
                raise PluginLifecycleError("plugin package/runtime root must not be a symlink")
            _ensure_child(package_target, package_root)
            _ensure_child(runtime_target, runtime_root)
            stage_root = bundle.package.parent
            stage_runtime = runtime_root / f".staging-{plugin_id}-{uuid4().hex}"
            stage_package = package_root / f".staging-{plugin_id}-{uuid4().hex}"
            stage_runtime.mkdir(mode=0o700)
            shutil.copytree(bundle.package, stage_package)
            stage_venv = stage_runtime / "venv"
            try:
                venv.EnvBuilder(with_pip=True, clear=False).create(stage_venv)
                wheel_files = tuple(bundle.wheels.glob("*.whl"))
                if len(wheel_files) != len(tuple(bundle.wheels.iterdir())):
                    raise PluginLifecycleError("only prebuilt dependency wheels are supported")
                for wheel in wheel_files:
                    _validate_wheel(wheel)
                if bundle.manifest.dependencies:
                    if not wheel_files:
                        raise PluginLifecycleError("bundle is missing required local wheels")
                    python = stage_venv / "bin" / "python"
                    environment = {
                        "PATH": os.defpath,
                        "HOME": str(stage_root),
                        "PYTHONNOUSERSITE": "1",
                        "PIP_CONFIG_FILE": os.devnull,
                        "PIP_NO_INDEX": "1",
                        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    }
                    completed = subprocess.run(  # noqa: S603 - venv pip, offline, no shell
                        [
                            str(python),
                            "-I",
                            "-m",
                            "pip",
                            "install",
                            "--no-index",
                            "--only-binary=:all:",
                            "--find-links",
                            str(bundle.wheels),
                            *bundle.manifest.dependencies,
                        ],
                        cwd=stage_root,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        text=True,
                        timeout=300,
                        check=False,
                    )  # noqa: S603 - fixed venv interpreter, no shell, pip offline-only
                    if completed.returncode:
                        raise PluginLifecycleError("offline wheel installation failed")
                old_package = package_root / f".{plugin_id}.rollback-{uuid4().hex}"
                old_venv = runtime_target / f".venv.rollback-{uuid4().hex}"
                package_switched = False
                venv_switched = False
                metadata_path = self.installations / f"{plugin_id}.json"
                previous_metadata = metadata_path.read_bytes() if metadata_path.is_file() else None
                runtime_target.mkdir(parents=True, exist_ok=True, mode=0o700)
                try:
                    if package_target.exists():
                        if not is_update:
                            raise PluginLifecycleError("plugin ID is already installed")
                        os.replace(package_target, old_package)
                    if (runtime_target / "venv").exists():
                        os.replace(runtime_target / "venv", old_venv)
                    os.replace(stage_package, package_target)
                    package_switched = True
                    os.replace(stage_venv, runtime_target / "venv")
                    venv_switched = True
                    missing_required: tuple[str, ...] = ()
                    from arborpress.plugins.capabilities import (
                        CapabilityGrantStore,
                        missing_required_grants,
                    )

                    missing_required = missing_required_grants(
                        plugin_id,
                        bundle.manifest.required_capabilities,
                        CapabilityGrantStore(self.paths.data / "plugin-grants.toml"),
                    )
                    metadata: dict[str, object] = {
                        "plugin_id": plugin_id,
                        "version": bundle.manifest.version,
                        "bundle_sha256": bundle.bundle_digest,
                        "package_sha256": _directory_digest(package_target),
                        "installed_at": datetime.now(UTC).isoformat(),
                    }
                    _write_json_atomic(metadata_path, metadata)
                    if not missing_required:
                        _run_plugin_self_check(package_target, bundle.manifest)
                        if not verify_installed_package(self.paths, plugin_id, package_target):
                            raise PluginLifecycleError(
                                "plugin package changed during the startup self-check"
                            )
                except BaseException:
                    if venv_switched:
                        _remove_tree(runtime_target / "venv", runtime_target)
                    if old_venv.exists():
                        os.replace(old_venv, runtime_target / "venv")
                    if package_switched:
                        _remove_tree(package_target, package_root)
                    if old_package.exists():
                        os.replace(old_package, package_target)
                    if previous_metadata is None:
                        metadata_path.unlink(missing_ok=True)
                    else:
                        _write_bytes_atomic(metadata_path, previous_metadata)
                    raise
                _remove_tree(old_package, package_root)
                _remove_tree(old_venv, runtime_target)
                from arborpress.plugins.state import PluginStateStore

                state = PluginStateStore(self.paths.data / "plugin-state.toml")
                if not is_update:
                    state.set_enabled(plugin_id, False)
                else:
                    from arborpress.plugins.capabilities import CapabilityGrantStore

                    grants = CapabilityGrantStore(self.paths.data / "plugin-grants.toml")
                    for stale in grants.grants_for(plugin_id) - set(
                        bundle.manifest.requested_capabilities
                    ):
                        grants.set_grant(plugin_id, stale, False)
                    if missing_required:
                        state.set_enabled(plugin_id, False)
            except PluginLifecycleError:
                raise
            except (OSError, subprocess.SubprocessError) as exc:
                raise PluginLifecycleError(
                    f"plugin lifecycle failed: {type(exc).__name__}"
                ) from exc
            finally:
                shutil.rmtree(stage_package, ignore_errors=True)
                shutil.rmtree(stage_runtime, ignore_errors=True)

    @staticmethod
    def _cleanup_stage(bundle: ValidatedBundle) -> None:
        shutil.rmtree(bundle.package.parent, ignore_errors=True)


@contextmanager
def _lifecycle_lock(paths: ArborPressPaths, plugin_id: str) -> Iterator[None]:
    lock_file = acquire_lifecycle_lock(paths, plugin_id)
    try:
        yield
    finally:
        lock_file.close()


def acquire_lifecycle_lock(paths: ArborPressPaths, plugin_id: str) -> BinaryIO:
    """Acquire a non-blocking per-plugin lock; the caller owns its lifetime."""
    if not PLUGIN_ID_RE.fullmatch(plugin_id):
        raise PluginLifecycleError("invalid plugin ID")
    lock_root = paths.plugin_run / plugin_id
    _assert_instance_root(paths.plugin_run, paths.instance)
    lock_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if lock_root.resolve().parent != paths.plugin_run.resolve():
        raise PluginLifecycleError("plugin lifecycle lock escapes runtime root")
    lock_path = lock_root / "lifecycle.lock"
    if lock_path.is_symlink():
        raise PluginLifecycleError("plugin lifecycle lock must not be a symlink")
    lock_file = lock_path.open("a+b")
    try:
        import fcntl

        os.fchmod(lock_file.fileno(), 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        lock_file.close()
        raise PluginLifecycleError("another lifecycle operation is active") from exc
    except ImportError as exc:
        lock_file.close()
        raise PluginLifecycleError("per-plugin lifecycle locking is unsupported") from exc
    return lock_file


def _extract_bundle(
    archive_path: Path, package_root: Path, wheels_root: Path
) -> tuple[PluginManifest, str]:
    payload: dict[str, Path | bytes] = {}
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_MEMBERS:
            raise PluginLifecycleError("bundle contains too many members")
        seen: set[str] = set()
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = info.external_attr >> 16
            if (
                not name
                or "\x00" in name
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in name
                or (len(path.parts) and ":" in path.parts[0])
            ):
                raise PluginLifecycleError("unsafe bundle member path")
            normalized = str(path).rstrip("/")
            if normalized in seen:
                raise PluginLifecycleError("duplicate bundle member")
            seen.add(normalized)
            if info.is_dir():
                if mode and mode & 0o170000 not in {0, 0o040000}:
                    raise PluginLifecycleError("bundle contains a non-directory special member")
                continue
            if mode and mode & 0o170000 not in {0, 0o100000}:
                raise PluginLifecycleError("bundle contains a link or special file")
            if info.file_size > _MAX_FILE_BYTES:
                raise PluginLifecycleError("bundle member exceeds the file size limit")
            total += info.file_size
            if total > _MAX_TOTAL_UNPACKED:
                raise PluginLifecycleError("bundle exceeds the unpacked size limit")
            if (
                name != "plugin.toml"
                and name != "checksums.sha256"
                and not (name.startswith("package/") or name.startswith("wheels/"))
            ):
                raise PluginLifecycleError("bundle contains an unsupported top-level path")
            if name.endswith(".pyc"):
                raise PluginLifecycleError("precompiled Python bytecode is not supported")
            if "__pycache__" in path.parts:
                raise PluginLifecycleError("Python bytecode cache directories are not supported")
            if name.endswith("/"):
                continue
            if name in {"plugin.toml", "checksums.sha256"}:
                if info.file_size > 2 * 1024 * 1024:
                    raise PluginLifecycleError("bundle metadata exceeds its size limit")
                payload[normalized] = archive.read(info)
            else:
                if name.startswith("package/"):
                    relative = PurePosixPath(name).relative_to("package")
                    target = package_root.joinpath(*relative.parts)
                    root = package_root
                else:
                    relative = PurePosixPath(name).relative_to("wheels")
                    if len(relative.parts) != 1 or not name.endswith(".whl"):
                        raise PluginLifecycleError("only top-level wheel files are supported")
                    target = wheels_root.joinpath(*relative.parts)
                    root = wheels_root
                _stream_extract(archive, info, target, root)
                payload[normalized] = target
    manifest_value = payload.get("plugin.toml")
    checksums_value = payload.get("checksums.sha256")
    manifest_bytes = manifest_value if isinstance(manifest_value, bytes) else None
    checksums = checksums_value if isinstance(checksums_value, bytes) else None
    if manifest_bytes is None or checksums is None:
        raise PluginLifecycleError("bundle requires plugin.toml and checksums.sha256")
    try:
        manifest = PluginManifest.model_validate(tomllib.loads(manifest_bytes.decode("utf-8")))
    except Exception as exc:
        raise PluginLifecycleError(f"invalid bundle manifest: {type(exc).__name__}") from exc
    expected: dict[str, str] = {}
    try:
        checksum_lines = checksums.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise PluginLifecycleError("checksums.sha256 must be ASCII") from exc
    for line in checksum_lines:
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise PluginLifecycleError("invalid checksums.sha256 entry")
        digest, filename = match.groups()
        if filename in expected:
            raise PluginLifecycleError("duplicate checksum entry")
        expected[filename] = digest
    actual_names = set(payload) - {"checksums.sha256"}
    if actual_names != set(expected):
        raise PluginLifecycleError("bundle checksums do not cover the exact payload")
    for filename, item in payload.items():
        if filename == "checksums.sha256":
            continue
        actual = hashlib.sha256(item).hexdigest() if isinstance(item, bytes) else _file_digest(item)
        if actual != expected[filename]:
            raise PluginLifecycleError(f"checksum mismatch for {filename}")
    manifest_target = package_root / "plugin.toml"
    _write_staged(manifest_target, manifest_bytes, package_root)
    if not any(name.startswith("package/") for name in actual_names):
        raise PluginLifecycleError("bundle package is empty")
    digest = _file_digest(archive_path)
    return manifest, digest


def _validate_wheel(path: Path) -> None:
    """Reject wheel traversal, special files and transitive direct URL deps."""
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > _MAX_MEMBERS:
                raise PluginLifecycleError("dependency wheel contains too many members")
            total = 0
            metadata: bytes | None = None
            metadata_files = 0
            for info in infos:
                name = info.filename
                member = PurePosixPath(name)
                mode = info.external_attr >> 16
                if (
                    not name
                    or "\x00" in name
                    or member.is_absolute()
                    or ".." in member.parts
                    or "\\" in name
                    or (member.parts and ":" in member.parts[0])
                ):
                    raise PluginLifecycleError("dependency wheel contains an unsafe path")
                if info.is_dir():
                    continue
                if mode and mode & 0o170000 not in {0, 0o100000}:
                    raise PluginLifecycleError("dependency wheel contains a link or special file")
                total += info.file_size
                if info.file_size > _MAX_FILE_BYTES or total > _MAX_TOTAL_UNPACKED:
                    raise PluginLifecycleError("dependency wheel exceeds extraction limits")
                if (
                    len(member.parts) == 2
                    and member.name == "METADATA"
                    and member.parts[0].endswith(".dist-info")
                ):
                    metadata_files += 1
                    if info.file_size > 1024 * 1024:
                        raise PluginLifecycleError("dependency wheel metadata is too large")
                    metadata = archive.read(info)
            if metadata_files != 1 or metadata is None:
                raise PluginLifecycleError("dependency wheel has invalid distribution metadata")
    except (OSError, zipfile.BadZipFile) as exc:
        raise PluginLifecycleError("dependency file is not a valid wheel archive") from exc
    message = email.message_from_bytes(metadata)
    for raw_requirement in message.get_all("Requires-Dist", []):
        try:
            requirement = Requirement(raw_requirement)
        except InvalidRequirement as exc:
            raise PluginLifecycleError(
                "dependency wheel has invalid Requires-Dist metadata"
            ) from exc
        if requirement.url:
            raise PluginLifecycleError("dependency wheels cannot declare direct URL dependencies")


def _stream_extract(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, root: Path
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not target.resolve().is_relative_to(root.resolve()):
        raise PluginLifecycleError("bundle member escapes staging root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o600)
    size = 0
    with os.fdopen(fd, "wb") as output, archive.open(info) as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > _MAX_FILE_BYTES:
                raise PluginLifecycleError("bundle member exceeds the file size limit")
            output.write(chunk)
    if size != info.file_size:
        raise PluginLifecycleError("bundle member size mismatch")


def _write_staged(target: Path, data: bytes, root: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not target.resolve().is_relative_to(root.resolve()):
        raise PluginLifecycleError("bundle member escapes staging root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            raise PluginLifecycleError("installed package contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8") + b"\x00")
        digest.update(bytes.fromhex(_file_digest(path)))
    return digest.hexdigest()


def verify_installed_package(paths: ArborPressPaths, plugin_id: str, package: Path) -> bool:
    """Verify managed package content; unmanaged development directories remain supported."""
    metadata_path = paths.data / "plugin-installations" / f"{plugin_id}.json"
    if not metadata_path.exists():
        return True
    if metadata_path.is_symlink() or not metadata_path.is_file():
        return False
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        expected = metadata.get("package_sha256") if isinstance(metadata, dict) else None
        return isinstance(expected, str) and _directory_digest(package) == expected
    except OSError, PluginLifecycleError, ValueError, json.JSONDecodeError:
        return False


def _run_plugin_self_check(package: Path, manifest: PluginManifest) -> None:
    """Exercise the actual isolated startup handshake without starting jobs/events."""
    from arborpress.plugins.process import PluginProcessManager
    from arborpress.plugins.registry import PluginRecord, PluginSource

    record = PluginRecord(manifest, package, source=PluginSource.THIRD_PARTY)

    async def check() -> None:
        manager = PluginProcessManager(startup_timeout=10, request_timeout=10)
        manager.lifecycle_self_check = True
        try:
            await manager.start(record)
            await manager.ping(manifest.id)
        finally:
            await manager.shutdown()

    try:
        asyncio.run(check())
    except Exception as exc:
        raise PluginLifecycleError("plugin host self-check failed") from exc


def _ensure_child(path: Path, root: Path) -> None:
    if not path.resolve(strict=False).is_relative_to(root.resolve()):
        raise PluginLifecycleError("plugin path escapes the instance root")


def _assert_instance_root(root: Path, instance: Path) -> None:
    if root.is_symlink() or not root.resolve(strict=False).is_relative_to(instance.resolve()):
        raise PluginLifecycleError("plugin lifecycle base path escapes the instance root")


def _remove_tree(path: Path, root: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise PluginLifecycleError("refusing to remove a plugin path outside its root")
    shutil.rmtree(path)


def _write_json_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".plugin-install-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=True, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _write_bytes_atomic(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".plugin-install-rollback-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _pid_is_running(path: Path) -> bool:
    if path.is_symlink():
        return True
    if not path.exists():
        return False
    if not path.is_file():
        return True
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        pid = value.get("pid") if isinstance(value, dict) else None
        if pid is None:
            return False
        if not isinstance(pid, int) or pid <= 1:
            return True
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError, UnicodeError, ValueError, json.JSONDecodeError:
        return True
