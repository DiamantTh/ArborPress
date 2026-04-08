"""Infrastructure configuration – config.toml and environment variables.

Contains only settings required BEFORE the database starts:
  [db]       – Database connection
  [web]      – Bind address, secret key, base URL, admin path
  [auth]     – Session TTLs, WebAuthn UV, step-up (security infrastructure)
  [logging]  – Log level and file paths
  [plugins]  – Plugin directories

All content-related settings (mail, comments, captcha, theme, federation,
search, general blog settings) are read via arborpress.core.site_settings
from the database and managed in the admin interface under /admin/settings.

Configuration sources (load order):
  1.  --config ./config/    – directory: loads config/config.toml
  2.  --config config.toml  – single file
  3.  config/               – auto-discover: directory in cwd
  4.  config.toml           – auto-discover: single file in cwd
  5.  Defaults + env vars   – ARBORPRESS_SECTION__KEY=value

include directive:
  include = ["secrets.toml"]   # relative to the file's directory
  Additional files in the same folder are merged (override semantics).
  Includes may themselves contain include directives (recursive).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# TOML loading helpers
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursive dict merge; override wins on scalar conflicts.

    TOML tables are merged rather than replaced, so that
    ``[db] pool_size = 5`` in one file does not drop ``url = "..."``
    from another file.
    """
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_toml_file(path: Path) -> dict:
    """Load a TOML file and process optional ``include`` directives.

    ``include = ["secrets.toml"]``

    Relative paths are resolved relative to the file's directory,
    i.e. the same folder. Includes may themselves contain include
    directives (recursive).
    """
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    includes: list[str] = data.pop("include", [])
    base_dir = path.parent
    for inc in includes:
        inc_path = Path(inc) if Path(inc).is_absolute() else base_dir / inc
        if not inc_path.exists():
            raise FileNotFoundError(
                f"Config include not found: {inc_path}"
                f" (referenced in {path})"
            )
        data = _deep_merge(data, _load_toml_file(inc_path))

    return data


def _load_config_dir(directory: Path) -> tuple[dict, Path]:
    """Load ``config.toml`` from a configuration directory.

    The directory is the config root. The main file (``config.toml``)
    optionally contains `include = ["secrets.toml"]` – all included
    files are resolved relative to the directory (i.e. the same folder).
    """
    main = directory / "config.toml"
    if not main.exists():
        raise FileNotFoundError(
            f"No config.toml found in configuration directory: {directory}"
        )
    data = _load_toml_file(main)
    return data, main.resolve()


class DatabaseSettings(BaseSettings):
    """Database connection.

    Supported URL schemes:
      postgresql+asyncpg://...   – PostgreSQL (production default)
      mysql+aiomysql://...       – MariaDB / MySQL
      sqlite+aiosqlite:///...    – SQLite (dev/test; no pool_size)
      sqlite+aiosqlite:///:memory:  – in-memory SQLite (tests only)
    """
    url: str = "postgresql+asyncpg://arborpress:changeme@localhost/arborpress"
    pool_size: int = 10
    echo: bool = False

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")


class WebSettings(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 8080
    secret_key: SecretStr = SecretStr("CHANGE_ME_IN_PRODUCTION")
    base_url: str = "http://localhost:8080"
    trusted_proxies: int = 0
    admin_path: str = "/admin"
    default_lang: str = "de"
    i18n_mode: Literal["single", "prefix"] = "single"
    # Media storage
    media_dir: Path = Path("media")


class AuthSettings(BaseSettings):
    require_uv: bool = False
    legacy_password_enabled: bool = False
    stepup_ttl: int = 900
    admin_session_ttl: int = 3600
    auth_rate_limit: str = "10/minute"
    # §2 Account lockout – credential-stuffing protection
    # Operator-tunable; set lockout_threshold=0 to disable.
    lockout_threshold: int = 5      # failed attempts before temporary lock
    lockout_duration: int = 900     # lock duration in seconds (default: 15 min)
    # Dedicated key-encryption key for actor keypairs (§5).
    # Separate from web.secret_key so that session key rotation does
    # NOT invalidate AP keys.
    # Generate: arborpress federation kek-init
    # Format: 32-byte base64url-encoded value (expected by Fernet)
    actor_key_enc_key: SecretStr | None = None


class LoggingSettings(BaseSettings):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    file: Path | None = None
    access_log: bool = False
    audit_log: bool = True
    audit_file: Path | None = None
    # §16 Opt-in: persist audit events as rows in the ``audit_events`` DB table.
    # Requires the 0003 schema migration to have been applied (or a fresh install).
    # Enables searchable / exportable audit trail in the admin UI.
    db_audit_log: bool = False


class CacheSettings(BaseSettings):
    """Cache backend configuration.

    Backends: memory (default) | redis | memcached | file | none

    memory:     In-process dict with TTL – no external service required.
    redis:      redis-py async. Extra dep: pip install 'redis[hiredis]'
    memcached:  aiomcache. Extra dep: pip install aiomcache
    file:       JSON files on disk – no rebuild needed after restart.
    none:       Cache disabled (always cache-miss).
    """
    backend: Literal["memory", "redis", "memcached", "file", "none"] = "memory"
    ttl: int = 300           # default TTL in seconds
    prefix: str = "ap:"      # key prefix
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    # Memcached
    memcached_host: str = "localhost"
    memcached_port: int = 11211
    # File
    file_dir: str = "/tmp/arborpress_cache"  # noqa: S108


class PluginSettings(BaseSettings):
    dirs: list[Path] = Field(default_factory=list)

    def resolved_dirs(self, config_file: Path) -> list[Path]:
        """Return all dirs as absolute paths.

        Relative paths are resolved relative to the config file's
        directory (not relative to cwd).
        """
        base = config_file.parent
        return [
            d if d.is_absolute() else (base / d).resolve()
            for d in self.dirs
        ]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARBORPRESS_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    db:      DatabaseSettings = Field(default_factory=DatabaseSettings)
    web:     WebSettings      = Field(default_factory=WebSettings)
    auth:    AuthSettings     = Field(default_factory=AuthSettings)
    logging: LoggingSettings  = Field(default_factory=LoggingSettings)
    plugins: PluginSettings   = Field(default_factory=PluginSettings)
    cache:   CacheSettings    = Field(default_factory=CacheSettings)

    @classmethod
    def from_path(cls, path: Path) -> Settings:
        """Load settings from a file or directory.

        File:       TOML file, optionally with ``include`` directive.
        Directory:  all ``*.toml`` alphabetically sorted and merged.
        """
        if path.is_dir():
            data, anchor = _load_config_dir(path)
        else:
            data = _load_toml_file(path)
            anchor = path.resolve()
        obj = cls.model_validate(data)
        obj._config_file = anchor
        return obj

    @classmethod
    def from_file(cls, path: Path) -> Settings:
        """Backwards-compatible – delegates to from_path."""
        return cls.from_path(path)

    def plugin_dirs(self) -> list[Path]:
        """Plugin directories as resolved absolute paths.

        Relative paths are resolved relative to the config file,
        not relative to the working directory.
        """
        cfg = getattr(self, "_config_file", None)
        if cfg is not None:
            return self.plugins.resolved_dirs(cfg)
        return [d.resolve() for d in self.plugins.dirs]


_settings: Settings | None = None


def get_config_dir() -> Path:
    """Return the directory where sidecar files live (install.token, .installed).

    Corresponds to the loaded config file's directory, or ``config/`` as fallback.
    """
    cfg_file = getattr(_settings, "_config_file", None) if _settings else None
    if cfg_file is not None:
        return Path(cfg_file).parent
    if Path("config").is_dir():
        return Path("config")
    return Path(".")


def install_token_path() -> Path:
    """Path to the file containing the one-time installation token."""
    return get_config_dir() / "install.token"


def installed_marker_path() -> Path:
    """Path to the marker file indicating a completed installation."""
    return get_config_dir() / ".installed"


def is_installed() -> bool:
    """True if the instance has already been set up."""
    return installed_marker_path().exists()


def get_settings(config_path: Path | None = None) -> Settings:
    """Singleton – load order: config/ → config.toml → env vars → defaults.

    ``config_path`` can be a file or a directory.
    Auto-discover (when None): first ``config/``, then ``config.toml``.
    """
    global _settings
    if _settings is None:
        if config_path is None:
            if (Path("config") / "config.toml").is_file():
                config_path = Path("config")
            else:
                config_path = Path("config.toml")
        if config_path.exists():
            _settings = Settings.from_path(config_path)
        else:
            _settings = Settings()
    return _settings
