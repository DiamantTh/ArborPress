from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


def _write_instance_config(paths: ArborPressPaths) -> None:
    ensure_instance_layout(paths)
    paths.config_file.write_text(
        textwrap.dedent(
            '''\
            [db]
            url = "sqlite+aiosqlite:///arborpress.db"

            [cache]
            backend = "file"

            [logging]
            file = "arborpress.log"
            audit_file = "audit.log"
            '''
        ),
        encoding="utf-8",
    )


def _cli(cwd: Path, prefix: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    # Let each subprocess exercise only its explicit prefix and checked-in
    # instance config, not ambient operator overrides from the test runner.
    for name in tuple(environment):
        if name.startswith("ARBORPRESS_"):
            environment.pop(name)
    return subprocess.run(  # noqa: S603 - fixed interpreter/module; arguments are test-owned
        [sys.executable, "-m", "arborpress.cli.main", "--prefix", str(prefix), *args],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _is_installed_subprocess(cwd: Path, prefix: Path) -> bool:
    environment = os.environ.copy()
    environment["ARBORPRESS_PREFIX"] = str(prefix)
    code = (
        "from arborpress.core.config import is_installed; "
        "print('yes' if is_installed() else 'no')"
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and constant test snippet
        [sys.executable, "-c", code],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip() == "yes"


def test_two_prefixes_keep_database_and_instance_state_isolated(
    tmp_path: Path,
) -> None:
    prefix_a = tmp_path / "arborpress-a"
    prefix_b = tmp_path / "arborpress-b"
    paths_a = ArborPressPaths.from_prefix(prefix_a)
    paths_b = ArborPressPaths.from_prefix(prefix_b)
    _write_instance_config(paths_a)
    _write_instance_config(paths_b)

    foreign_cwd = tmp_path / "foreign-cwd"
    foreign_cwd.mkdir()
    (foreign_cwd / "config").mkdir()
    (foreign_cwd / "config" / "config.toml").write_text(
        '[db]\nurl = "sqlite+aiosqlite:///wrong.db"\n', encoding="utf-8"
    )
    (foreign_cwd / "config" / ".installed").write_text(
        "foreign marker\n", encoding="utf-8"
    )
    (foreign_cwd / ".installed").write_text("foreign marker\n", encoding="utf-8")
    (foreign_cwd / "media").mkdir()
    (foreign_cwd / "content" / "themes").mkdir(parents=True)
    (foreign_cwd / "content" / "themes" / "wrong-theme").mkdir()

    # Migrate each DB through the public CLI in independent processes.
    for prefix, paths in ((prefix_a, paths_a), (prefix_b, paths_b)):
        upgraded = _cli(foreign_cwd, prefix, "db", "upgrade")
        assert upgraded.returncode == 0, upgraded.stdout + upgraded.stderr
        assert "schema is current" in upgraded.stdout
        assert (paths.data / "arborpress.db").is_file()

    # The same explicit prefix resolves identically from the source tree,
    # the prefix itself and an unrelated working directory.
    repository_root = Path(__file__).resolve().parents[1]
    prefix_outputs: dict[str, list[dict[str, str]]] = {}
    for name, prefix, paths in (("a", prefix_a, paths_a), ("b", prefix_b, paths_b)):
        path_outputs = []
        for cwd in (repository_root, prefix, foreign_cwd):
            result = _cli(cwd, prefix, "paths", "--json")
            assert result.returncode == 0, result.stdout + result.stderr
            path_outputs.append(json.loads(result.stdout))
            checked = _cli(cwd, prefix, "db", "check")
            assert checked.returncode == 0, checked.stdout + checked.stderr
            assert "schema is current" in checked.stdout
            current = _cli(cwd, prefix, "db", "current")
            assert current.returncode == 0, current.stdout + current.stderr
            assert "Status:           current" in current.stdout
        assert path_outputs[0] == path_outputs[1] == path_outputs[2]
        assert path_outputs[0]["prefix"] == str(paths.prefix)
        assert path_outputs[0]["config_file"] == str(paths.config_file)
        prefix_outputs[name] = path_outputs
    for field in (
        "config",
        "data",
        "media",
        "themes",
        "plugins",
        "backups",
        "cache",
        "log",
        "run",
        "tmp",
    ):
        assert prefix_outputs["a"][0][field] != prefix_outputs["b"][0][field]

    # Each independently migrated SQLite database accepts distinct data.
    for database, value in (
        (paths_a.data / "arborpress.db", "only-a"),
        (paths_b.data / "arborpress.db", "only-b"),
    ):
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE isolation_probe (value TEXT NOT NULL)")
            connection.execute("INSERT INTO isolation_probe VALUES (?)", (value,))
    with sqlite3.connect(paths_a.data / "arborpress.db") as connection:
        assert connection.execute("SELECT value FROM isolation_probe").fetchone() == (
            "only-a",
        )
    with sqlite3.connect(paths_b.data / "arborpress.db") as connection:
        assert connection.execute("SELECT value FROM isolation_probe").fetchone() == (
            "only-b",
        )

    (paths_a.config / ".installed").write_text("installed\n", encoding="utf-8")
    assert _is_installed_subprocess(foreign_cwd, prefix_a)
    assert not _is_installed_subprocess(foreign_cwd, prefix_b)
    (paths_a.config / ".installed").unlink()
    (paths_b.config / ".installed").write_text("installed\n", encoding="utf-8")
    assert not _is_installed_subprocess(foreign_cwd, prefix_a)
    assert _is_installed_subprocess(foreign_cwd, prefix_b)


def test_external_config_override_does_not_relocate_prefix_state(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "override-prefix"
    paths = ArborPressPaths.from_prefix(prefix)
    ensure_instance_layout(paths)
    external_config = tmp_path / "private-config" / "override.toml"
    external_config.parent.mkdir()
    external_config.write_text(
        '[db]\nurl = "sqlite+aiosqlite:///override.db"\n', encoding="utf-8"
    )

    upgraded = subprocess.run(  # noqa: S603 - fixed interpreter/module and test-owned args
        [
            sys.executable,
            "-m",
            "arborpress.cli.main",
            "--prefix",
            str(prefix),
            "--config",
            str(external_config),
            "db",
            "upgrade",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert upgraded.returncode == 0, upgraded.stdout + upgraded.stderr
    assert (paths.data / "override.db").is_file()
    assert not (external_config.parent / "override.db").exists()


def test_web_factory_initializes_prefix_layout_before_runtime_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.core.config import reset_settings
    from arborpress.logging.config import reset_logging_for_tests
    from arborpress.runtime.paths import initialize_runtime
    from arborpress.themes.manifest import get_theme_registry, reset_theme_registry_for_tests
    from arborpress.web.app import create_app
    from arborpress.web.routes.api import _write_upload

    paths = initialize_runtime(tmp_path / "web-prefix", override=True)
    paths.config_file.parent.mkdir(parents=True)
    paths.config_file.write_text(
        '[web]\nport = 8123\n[logging]\nfile = "web.log"\n', encoding="utf-8"
    )
    foreign_cwd = tmp_path / "web-cwd"
    (foreign_cwd / "config").mkdir(parents=True)
    (foreign_cwd / "config" / "config.toml").write_text(
        "[web]\nport = 8999\n", encoding="utf-8"
    )
    (foreign_cwd / ".installed").write_text("not this prefix\n", encoding="utf-8")
    (foreign_cwd / "media").mkdir()
    (foreign_cwd / "media" / "foreign.txt").write_text("foreign", encoding="utf-8")
    foreign_theme = foreign_cwd / "content" / "themes" / "cwd-only"
    foreign_theme.mkdir(parents=True)
    (foreign_theme / "theme.toml").write_text(
        '[theme]\nid = "cwd-only"\nname = "Wrong CWD theme"\n', encoding="utf-8"
    )
    monkeypatch.chdir(foreign_cwd)
    reset_settings()
    reset_logging_for_tests()
    reset_theme_registry_for_tests()

    app = create_app()

    from arborpress.core.config import get_settings

    settings = get_settings()
    assert settings.web.port == 8123
    assert app.secret_key == settings.web.secret_key.get_secret_value()
    assert settings.web.media_dir == paths.media
    assert paths.cache.is_dir()
    assert paths.log.is_dir()
    assert not (foreign_cwd / "arborpress.log").exists()
    assert get_theme_registry().get("cwd-only") is None
    assert get_theme_registry().get("default") is not None

    media_target = paths.media / "working-directory-check.txt"
    _write_upload(paths.media, media_target, b"prefix-owned")
    assert media_target.read_bytes() == b"prefix-owned"
    assert not (foreign_cwd / "media" / media_target.name).exists()

    # An uninstalled prefix starts its own token flow during lifespan, without
    # treating a marker in the working directory as an installed instance.
    async def start_uninstalled_instance() -> None:
        async with app.test_app():
            async with app.test_client() as client:
                response = await client.get("/_health")
                assert response.status_code == 200
                assert await response.get_json() == {"status": "ok"}
                install_page = await client.get("/install")
                assert install_page.status_code == 200
                assert b"instance/config/install.token" in await install_page.get_data()

    asyncio.run(start_uninstalled_instance())
    assert (paths.config / "install.token").is_file()
    assert (foreign_cwd / "config" / "config.toml").resolve() != paths.config_file.resolve()


def test_theme_plugin_media_cache_and_logs_are_scoped_to_each_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.core.cache import FileBackend, get_backend, reset_backend_for_tests
    from arborpress.core.config import get_settings, reset_settings
    from arborpress.logging.config import reset_logging_for_tests, setup_logging
    from arborpress.plugins.registry import PluginRegistry
    from arborpress.runtime.paths import reset_runtime_for_tests
    from arborpress.themes.manifest import get_theme_registry, reset_theme_registry_for_tests
    from arborpress.web.routes.api import _write_upload

    for name in ("a", "b"):
        paths = ArborPressPaths.from_prefix(tmp_path / f"blog-{name}")
        _write_instance_config(paths)
        theme_dir = paths.themes / f"theme-{name}"
        theme_dir.mkdir()
        (theme_dir / "theme.toml").write_text(
            f'[theme]\nid = "theme-{name}"\nname = "Theme {name}"\n',
            encoding="utf-8",
        )
        plugin_dir = paths.plugins / f"plugin-{name}"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.toml").write_text(
            textwrap.dedent(
                f"""\
                [plugin]
                id = "plugin-{name}"
                name = "Plugin {name}"
                version = "1.0.0"
                min_core = "0.1.0"
                capabilities = ["importer"]

                [entry_points]
                importer = "arborpress.plugins.registry:PluginRegistry"
                """
            ),
            encoding="utf-8",
        )

    registries: dict[str, tuple[set[str], set[str]]] = {}
    for name in ("a", "b"):
        paths = ArborPressPaths.from_prefix(tmp_path / f"blog-{name}")
        reset_runtime_for_tests(paths.prefix)
        reset_settings()
        reset_backend_for_tests()
        reset_logging_for_tests()
        reset_theme_registry_for_tests()

        settings = get_settings()
        themes = get_theme_registry()
        plugins = PluginRegistry()
        for directory in settings.plugin_dirs():
            plugins.load_directory(directory)
        assert themes.get("default") is not None
        registries[name] = (
            {theme.theme.id for theme in themes.all()},
            {plugin.id for plugin in plugins.all()},
        )

        media_file = paths.media / f"{name}.bin"
        _write_upload(paths.media, media_file, name.encode())
        assert media_file.read_bytes() == name.encode()

        backend = get_backend()
        assert isinstance(backend, FileBackend)
        assert backend._dir == paths.cache
        asyncio.run(backend.set("instance-probe", name, 60))
        assert list(paths.cache.glob("*.cache"))

        setup_logging(settings.logging)
        assert (paths.log / "arborpress.log").is_file()
        assert (paths.log / "audit.log").is_file()

    assert "theme-a" in registries["a"][0]
    assert "theme-b" not in registries["a"][0]
    assert "theme-b" in registries["b"][0]
    assert "theme-a" not in registries["b"][0]
    assert registries["a"][1] == {"plugin-a"}
    assert registries["b"][1] == {"plugin-b"}
