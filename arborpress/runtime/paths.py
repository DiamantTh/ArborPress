"""Canonical filesystem layout for one ArborPress installation prefix.

The prefix is resolved once (including symlinks) and stored as an absolute
path. Relative prefixes are interpreted against the working directory only at
the point where the operator explicitly initializes the runtime context.
Subsequent path access is independent of ``chdir``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ArborPressPaths:
    """All program and persistent paths derived from exactly one prefix."""

    prefix: Path
    root_launcher: Path
    app: Path
    app_bin: Path
    app_runtime: Path
    app_assets: Path
    app_releases: Path
    app_current: Path
    instance: Path
    config: Path
    config_file: Path
    data: Path
    media: Path
    themes: Path
    plugins: Path
    backups: Path
    var: Path
    cache: Path
    log: Path
    run: Path
    tmp: Path

    @classmethod
    def from_prefix(cls, prefix: str | os.PathLike[str]) -> ArborPressPaths:
        """Build paths from a normalized, canonical absolute prefix.

        Existing symlinks are resolved once. A prefix which already exists as
        a regular file is rejected; a not-yet-created directory is allowed.
        """
        supplied = Path(prefix).expanduser()
        normalized = supplied.resolve(strict=False)
        if normalized.exists() and not normalized.is_dir():
            raise NotADirectoryError(f"ArborPress prefix is not a directory: {normalized}")

        app = normalized / "app"
        instance = normalized / "instance"
        var = instance / "var"
        return cls(
            prefix=normalized,
            root_launcher=normalized / "arborpress",
            app=app,
            app_bin=app / "bin",
            app_runtime=app / "runtime",
            app_assets=app / "assets",
            app_releases=app / "releases",
            app_current=app / "current",
            instance=instance,
            config=instance / "config",
            config_file=instance / "config" / "config.toml",
            data=instance / "data",
            media=instance / "media",
            themes=instance / "themes",
            plugins=instance / "plugins",
            backups=instance / "backups",
            var=var,
            cache=var / "cache",
            log=var / "log",
            run=var / "run",
            tmp=var / "tmp",
        )


_runtime_paths: ArborPressPaths | None = None


def initialize_runtime(
    prefix: str | os.PathLike[str], *, override: bool = False
) -> ArborPressPaths:
    """Initialize the process with one prefix, refusing accidental changes."""
    global _runtime_paths
    paths = ArborPressPaths.from_prefix(prefix)
    if (
        _runtime_paths is not None
        and _runtime_paths.prefix != paths.prefix
        and not override
    ):
        raise RuntimeError(
            "ArborPress runtime is already initialized for prefix "
            f"{_runtime_paths.prefix}; refusing a second instance in one process"
        )
    _runtime_paths = paths
    return paths


def resolve_prefix(
    cli_prefix: str | os.PathLike[str] | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> Path:
    """Resolve CLI, environment, then initialized-context prefix priority."""
    if cli_prefix is not None:
        return ArborPressPaths.from_prefix(cli_prefix).prefix
    environment = os.environ if environ is None else environ
    configured = environment.get("ARBORPRESS_PREFIX")
    if configured:
        return ArborPressPaths.from_prefix(configured).prefix
    if _runtime_paths is not None:
        return _runtime_paths.prefix
    raise RuntimeError(
        "ArborPress prefix is not set; pass --prefix or set ARBORPRESS_PREFIX"
    )


def get_runtime_paths() -> ArborPressPaths:
    """Return initialized paths, lazily honoring the process prefix environment."""
    global _runtime_paths
    if _runtime_paths is None and os.environ.get("ARBORPRESS_PREFIX"):
        return initialize_runtime(os.environ["ARBORPRESS_PREFIX"])
    if _runtime_paths is None:
        raise RuntimeError(
            "ArborPress prefix is not initialized; pass --prefix, set "
            "ARBORPRESS_PREFIX, or initialize the runtime context explicitly"
        )
    return _runtime_paths


def reset_runtime_for_tests(prefix: str | os.PathLike[str] | None = None) -> None:
    """Reset runtime identity for isolated tests and controlled CLI invocations."""
    global _runtime_paths
    _runtime_paths = None
    if prefix is not None:
        initialize_runtime(prefix)


def ensure_instance_layout(paths: ArborPressPaths) -> None:
    """Create the persistent instance layout without touching existing data.

    New directories default to owner-only access. Existing directory modes,
    files and contents are never changed. The replaceable ``app`` tree is not
    created here; in particular no synthetic release or ``app/current`` is
    introduced.
    """
    directories = (
        paths.prefix,
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
    for directory in directories:
        _mkdir_secure(directory)


def _mkdir_secure(directory: Path) -> None:
    """Create each missing path component with owner-only permissions."""
    if directory.exists():
        if not directory.is_dir():
            raise NotADirectoryError(f"Instance path is not a directory: {directory}")
        return
    parent = directory.parent
    if parent != directory:
        _mkdir_secure(parent)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        if not directory.is_dir():
            raise NotADirectoryError(
                f"Instance path is not a directory: {directory}"
            ) from None
