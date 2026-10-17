from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from arborpress.runtime.paths import (
    ArborPressPaths,
    ensure_instance_layout,
    get_runtime_paths,
    initialize_runtime,
    reset_runtime_for_tests,
    resolve_prefix,
)


def test_paths_derive_the_complete_layout_from_an_absolute_prefix(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "blog")

    assert paths.prefix == (tmp_path / "blog").resolve()
    assert paths.root_launcher == paths.prefix / "arborpress"
    assert paths.app == paths.prefix / "app"
    assert paths.app_bin == paths.app / "bin"
    assert paths.app_runtime == paths.app / "runtime"
    assert paths.app_assets == paths.app / "assets"
    assert paths.app_releases == paths.app / "releases"
    assert paths.app_current == paths.app / "current"
    assert paths.config_file == paths.instance / "config" / "config.toml"
    assert paths.data == paths.instance / "data"
    assert paths.media == paths.instance / "media"
    assert paths.themes == paths.instance / "themes"
    assert paths.plugins == paths.instance / "plugins"
    assert paths.backups == paths.instance / "backups"
    assert paths.cache == paths.var / "cache"
    assert paths.log == paths.var / "log"
    assert paths.run == paths.var / "run"
    assert paths.tmp == paths.var / "tmp"


def test_relative_prefix_is_resolved_once_and_unaffected_by_chdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin = tmp_path / "origin"
    other = tmp_path / "other"
    origin.mkdir()
    other.mkdir()
    monkeypatch.chdir(origin)

    paths = ArborPressPaths.from_prefix("relative-instance")
    monkeypatch.chdir(other)

    assert paths.prefix == (origin / "relative-instance").resolve()
    assert paths.config_file == origin / "relative-instance/instance/config/config.toml"


def test_tilde_prefix_is_expanded_and_symlink_is_canonicalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    real = tmp_path / "real-prefix"
    home.mkdir()
    real.mkdir()
    link = tmp_path / "prefix-link"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))

    assert ArborPressPaths.from_prefix("~/blog").prefix == home / "blog"
    assert ArborPressPaths.from_prefix(link).prefix == real.resolve()


def test_two_prefixes_have_disjoint_instance_paths(tmp_path: Path) -> None:
    first = ArborPressPaths.from_prefix(tmp_path / "blog-a")
    second = ArborPressPaths.from_prefix(tmp_path / "blog-b")

    assert first.instance != second.instance
    assert first.config_file != second.config_file
    assert first.media != second.media
    assert first.plugins != second.plugins


def test_layout_creation_is_idempotent_and_does_not_create_fake_app_release(
    tmp_path: Path,
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")

    ensure_instance_layout(paths)
    ensure_instance_layout(paths)

    expected = (
        paths.instance,
        paths.config,
        paths.data,
        paths.media,
        paths.themes,
        paths.plugins,
        paths.backups,
        paths.var,
        paths.cache,
        paths.log,
        paths.run,
        paths.tmp,
    )
    assert all(path.is_dir() for path in expected)
    assert not paths.app.exists()
    assert not paths.app_current.exists()
    assert not paths.app_releases.exists()


def test_layout_creation_preserves_existing_files(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    paths.config.mkdir(parents=True)
    marker = paths.config / ".installed"
    marker.write_text("keep-me\n", encoding="utf-8")

    ensure_instance_layout(paths)

    assert marker.read_text(encoding="utf-8") == "keep-me\n"


def test_new_sensitive_instance_directories_are_owner_only_on_posix(
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX mode bits are not portable to this platform")
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")

    ensure_instance_layout(paths)

    assert stat.S_IMODE(paths.config.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.backups.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.run.stat().st_mode) == 0o700


def test_existing_non_directory_prefix_is_rejected(tmp_path: Path) -> None:
    file_prefix = tmp_path / "not-a-directory"
    file_prefix.write_text("x", encoding="utf-8")

    with pytest.raises(NotADirectoryError, match="prefix is not a directory"):
        ArborPressPaths.from_prefix(file_prefix)


def test_prefix_sources_follow_cli_environment_context_priority(tmp_path: Path) -> None:
    cli = tmp_path / "cli"
    environment = tmp_path / "environment"
    context = tmp_path / "context"
    reset_runtime_for_tests(context)

    assert resolve_prefix(cli, environ={"ARBORPRESS_PREFIX": str(environment)}) == cli.resolve()
    assert resolve_prefix(environ={"ARBORPRESS_PREFIX": str(environment)}) == environment.resolve()
    assert resolve_prefix(environ={}) == context.resolve()

    reset_runtime_for_tests()
    with pytest.raises(RuntimeError, match="pass --prefix or set ARBORPRESS_PREFIX"):
        resolve_prefix(environ={})


def test_runtime_context_rejects_uncontrolled_second_prefix(tmp_path: Path) -> None:
    first = tmp_path / "one"
    reset_runtime_for_tests(first)

    assert initialize_runtime(first).prefix == first.resolve()
    with pytest.raises(RuntimeError, match="refusing a second instance"):
        initialize_runtime(tmp_path / "two")
    assert get_runtime_paths().prefix == first.resolve()


def test_runtime_context_lazily_initializes_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "environment-prefix"
    reset_runtime_for_tests()
    monkeypatch.setenv("ARBORPRESS_PREFIX", str(prefix))

    assert get_runtime_paths().prefix == prefix.resolve()


def test_path_access_without_environment_or_context_has_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_runtime_for_tests()
    monkeypatch.delenv("ARBORPRESS_PREFIX", raising=False)

    with pytest.raises(RuntimeError, match="pass --prefix, set ARBORPRESS_PREFIX"):
        get_runtime_paths()
