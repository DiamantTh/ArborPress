from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest

from arborpress.core.cache import FileBackend, get_backend
from arborpress.core.config import LoggingSettings, get_settings, reset_settings
from arborpress.logging.config import setup_logging
from arborpress.runtime.paths import get_runtime_paths


def _write_config(text: str) -> None:
    paths = get_runtime_paths()
    paths.config.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(text, encoding="utf-8")
    reset_settings()


def test_default_file_cache_uses_instance_cache_directory() -> None:
    paths = get_runtime_paths()
    _write_config('[cache]\nbackend = "file"\n')

    settings = get_settings()
    backend = get_backend()

    assert settings.cache.file_dir == paths.cache
    assert isinstance(backend, FileBackend)
    assert backend._dir == paths.cache
    asyncio.run(backend.set("path-test", {"ok": True}, 30))
    assert list(paths.cache.glob("*.cache"))


def test_relative_cache_override_is_instance_cache_relative() -> None:
    paths = get_runtime_paths()
    _write_config('[cache]\nbackend = "file"\nfile_dir = "custom/cache"\n')

    settings = get_settings()
    backend = get_backend()

    assert settings.cache.file_dir == paths.cache / "custom" / "cache"
    assert isinstance(backend, FileBackend)
    assert backend._dir == paths.cache / "custom" / "cache"


def test_absolute_cache_override_is_preserved(tmp_path: Path) -> None:
    explicit = tmp_path / "operator-cache"
    _write_config(
        f'[cache]\nbackend = "file"\nfile_dir = "{explicit}"\n'
    )

    settings = get_settings()
    backend = get_backend()

    assert settings.cache.file_dir == explicit
    assert isinstance(backend, FileBackend)
    assert backend._dir == explicit


def test_relative_cache_override_cannot_escape_instance_cache() -> None:
    _write_config('[cache]\nfile_dir = "../outside"\n')

    with pytest.raises(ValueError, match="Relative cache paths"):
        get_settings()


def test_relative_app_and_audit_logs_use_instance_log_directory() -> None:
    paths = get_runtime_paths()
    _write_config(
        '[logging]\nfile = "app/service.log"\naudit_file = "audit.log"\n'
    )

    settings = get_settings()
    assert settings.logging.file == paths.log / "app" / "service.log"
    assert settings.logging.audit_file == paths.log / "audit.log"

    setup_logging(settings.logging)

    assert settings.logging.file.is_file()
    assert settings.logging.audit_file.is_file()
    assert paths.log.is_dir()


def test_direct_relative_log_paths_are_instance_scoped_and_traversal_is_rejected() -> None:
    from arborpress.logging.config import _resolve_log_path

    paths = get_runtime_paths()
    assert _resolve_log_path(Path("service.log")) == paths.log / "service.log"
    with pytest.raises(ValueError, match="Relative log paths"):
        _resolve_log_path(Path("../outside.log"))


def test_absolute_log_paths_remain_absolute(tmp_path: Path) -> None:
    explicit = tmp_path / "external" / "app.log"
    setup_logging(LoggingSettings(file=explicit, audit_log=False))

    assert explicit.is_file()
    assert any(
        isinstance(handler, logging.handlers.WatchedFileHandler)
        and Path(handler.baseFilename) == explicit
        for handler in logging.getLogger("arborpress").handlers
    )
