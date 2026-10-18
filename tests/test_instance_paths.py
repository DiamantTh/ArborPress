from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from quart import Quart

from arborpress.core.config import get_settings, reset_settings
from arborpress.plugins.registry import PluginRegistry
from arborpress.runtime.paths import ensure_instance_layout, initialize_runtime
from arborpress.themes.manifest import get_theme_registry, reset_theme_registry_for_tests


def _prefix(tmp_path: Path):
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    reset_settings()
    reset_theme_registry_for_tests()
    return paths


def test_default_media_root_is_instance_scoped_and_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prefix(tmp_path)
    foreign_cwd = tmp_path / "foreign"
    (foreign_cwd / "media").mkdir(parents=True)
    monkeypatch.chdir(foreign_cwd)

    assert get_settings().web.media_dir == paths.media


def test_explicit_absolute_media_root_is_preserved(tmp_path: Path) -> None:
    paths = _prefix(tmp_path)
    custom_media = tmp_path / "external-media"
    paths.config_file.write_text(
        f'[web]\nmedia_dir = "{custom_media}"\n', encoding="utf-8"
    )
    reset_settings()

    assert get_settings().web.media_dir == custom_media


@pytest.mark.asyncio
async def test_media_storage_and_serving_use_the_instance_default(
    tmp_path: Path,
) -> None:
    paths = _prefix(tmp_path)
    year, month, filename = 2026, 10, "stored.bin"
    directory = paths.media / str(year) / f"{month:02d}"
    file_path = directory / filename
    payload = b"instance media"

    from arborpress.web.routes.api import _write_upload
    from arborpress.web.routes.public import media_serve

    _write_upload(directory, file_path, payload)
    app = Quart("media-path-test")
    async with app.test_request_context(f"/media/{year}/{month}/{filename}"):
        response = await media_serve(year, month, filename)
        assert await response.get_data() == payload


def test_relative_media_override_cannot_escape_instance(tmp_path: Path) -> None:
    paths = _prefix(tmp_path)
    paths.config_file.write_text('[web]\nmedia_dir = "../outside"\n', encoding="utf-8")
    reset_settings()

    with pytest.raises(ValueError, match="Relative media paths"):
        get_settings()


def test_external_themes_use_instance_themes_and_builtins_remain_package_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prefix(tmp_path)
    operator_theme = paths.themes / "operator"
    operator_theme.mkdir()
    (operator_theme / "theme.toml").write_text(
        textwrap.dedent(
            """
            name = "Operator Theme"
version = "1.0.0"
type = "public"
requires_arborpress = ">=0.1.0"
            """
        ),
        encoding="utf-8",
    )
    colliding_theme = paths.themes / "default"
    colliding_theme.mkdir()
    (colliding_theme / "theme.toml").write_text(
        'name = "External Override"\nversion = "1.0.0"\ntype = "public"\n',
        encoding="utf-8",
    )
    foreign = tmp_path / "foreign" / "content" / "themes" / "cwd-theme"
    foreign.mkdir(parents=True)
    (foreign / "theme.toml").write_text(
        'name = "CWD Theme"\nversion = "1.0.0"\ntype = "public"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path / "foreign")

    registry = get_theme_registry()

    assert registry.get("operator") is not None
    assert registry.get("default") is not None
    assert registry.get("default").theme.name == "ArborPress Default"
    assert registry.record("default").status == "valid"
    assert any(
        record.id == "default" and record.status == "duplicate_id"
        for record in registry.records()
    )
    assert registry.get("cwd-theme") is None
    assert registry.get("operator").theme_dir == operator_theme


def test_plugin_paths_include_instance_root_after_configured_roots(tmp_path: Path) -> None:
    paths = _prefix(tmp_path)
    (paths.config_file).write_text(
        '[plugins]\ndirs = ["../shared-plugins"]\n', encoding="utf-8"
    )
    reset_settings()

    configured, canonical = get_settings().plugin_dirs()

    assert configured == (paths.instance / "shared-plugins").resolve()
    assert canonical == paths.plugins


def test_instance_plugins_take_precedence_over_configured_duplicate_ids(
    tmp_path: Path,
) -> None:
    paths = _prefix(tmp_path)
    extra_root = paths.instance / "shared-plugins"
    canonical_plugin = paths.plugins / "sample"
    extra_plugin = extra_root / "sample"
    canonical_plugin.mkdir(parents=True)
    extra_plugin.mkdir(parents=True)
    manifest = textwrap.dedent(
        """
        [plugin]
        id = "sample"
        name = "Sample"
        version = "1.0.0"
        min_core = "0.1.0"
        capabilities = ["importer"]

        [entry_points]
        importer = "arborpress.plugins.registry:PluginRegistry"
        """
    )
    (extra_plugin / "manifest.toml").write_text(manifest, encoding="utf-8")
    (canonical_plugin / "manifest.toml").write_text(manifest, encoding="utf-8")
    paths.config_file.write_text(
        '[plugins]\ndirs = ["../shared-plugins"]\n', encoding="utf-8"
    )
    reset_settings()
    registry = PluginRegistry()

    for directory in get_settings().plugin_dirs():
        registry.load_directory(directory)

    assert registry.get("sample") is not None
    assert registry.get("sample").directory == canonical_plugin
