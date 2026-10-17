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
  1.  --config PATH         – explicit file or configuration directory
  2.  PREFIX/instance/config/config.toml
  3.  Defaults + env vars   – ARBORPRESS_SECTION__KEY=value

include directive:
  include = ["secrets.toml"]   # relative to the file's directory
  Additional files in the same folder are merged (override semantics).
  Includes may themselves contain include directives (recursive).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import Field, PrivateAttr, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from arborpress.runtime.paths import ArborPressPaths, get_runtime_paths

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
    directory = directory.expanduser().resolve()
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
    port: int = 8066
    secret_key: SecretStr = SecretStr("CHANGE_ME_IN_PRODUCTION")
    base_url: str = "http://localhost:8066"
    trusted_proxies: int = 0
    admin_path: str = "/admin"
    default_lang: str = "de-DE"
    i18n_mode: Literal["single", "prefix"] = "single"
    # Media storage
    media_dir: Path = Path("media")
    # Admin Markdown editor. Only statically bundled ArborPress entries are
    # loaded; unknown legacy values leave the server-rendered textarea intact.
    # "builtin" is the default split-view editor; "tiptap" enables TipTap.
    admin_editor: str = "builtin"


class AuthSettings(BaseSettings):
    require_uv: bool = False
    legacy_password_enabled: bool = False
    legacy_password_min_length: int = Field(default=16, ge=8, le=256)
    legacy_password_max_length: int = Field(default=128, ge=16, le=1024)
    legacy_password_min_score: int = Field(default=3, ge=0, le=4)
    # Have I Been Pwned (k-Anonymity) – optional breach lookup for
    # *manually entered* passwords. Generated passwords skip this check
    # since EFF/Diceware and 24-char random strings are statistically
    # absent from breach corpora and the round-trip is wasted effort.
    hibp_enabled: bool = False
    hibp_timeout: float = Field(default=3.0, ge=0.5, le=30.0)
    hibp_fail_open: bool = True
    hibp_max_count: int = Field(default=0, ge=0)
    stepup_ttl: int = 300
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

    @model_validator(mode="after")
    def validate_legacy_password_limits(self) -> AuthSettings:
        if self.legacy_password_max_length < self.legacy_password_min_length:
            raise ValueError(
                "auth.legacy_password_max_length must be greater than or equal to "
                "auth.legacy_password_min_length"
            )
        return self


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

    Backends: memory (default) | redis | valkey | memcached | file | none

    memory:     In-process dict mit TTL – kein externer Service erforderlich.
    redis:      redis-py async. Extra dep: pip install 'redis[hiredis]'
    valkey:     Valkey (FOSS Redis-Fork, BSD-3). Extra dep: pip install 'valkey[libvalkey]'
    memcached:  aiomcache. Extra dep: pip install aiomcache
    file:       JSON-Dateien auf Disk – Cache überlebt Neustarts.
    none:       Cache deaktiviert (immer Cache-Miss).
    """
    backend: Literal["memory", "redis", "valkey", "memcached", "file", "none"] = "memory"
    ttl: int = 300           # default TTL in seconds
    prefix: str = "ap:"      # key prefix
    # L1-Cache (in-process, vor externem Backend)
    # Nur wirksam wenn backend in {redis, valkey, memcached, file}
    l1_enabled: bool = False  # Zwei-Ebenen-Cache aktivieren
    l1_ttl: int = 30          # L1-TTL in Sekunden (kurz, damit L2-Updates zeitnah wirken)
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    # Valkey (FOSS Redis-Fork, gleiche URL-Syntax)
    valkey_url: str = "valkey://localhost:6379/0"
    # Memcached
    memcached_host: str = "localhost"
    memcached_port: int = 11211
    # File cache defaults to the active instance's var/cache directory.
    file_dir: Path | None = None


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
    _config_file: Path | None = PrivateAttr(default=None)

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
        path = path.expanduser().resolve()
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
        """Return configured plugin roots followed by the canonical instance root.

        Additional relative paths are anchored to the active config file (which
        may be an explicit override), never to the working directory. The
        canonical instance directory is loaded last and therefore takes
        precedence when plugin IDs collide.
        """
        paths = get_runtime_paths()
        config_file = self._config_file or paths.config_file
        directories = [*self.plugins.resolved_dirs(config_file), paths.plugins]
        return list(dict.fromkeys(directories))


_settings: Settings | None = None
_settings_key: tuple[Path, Path] | None = None


def reset_settings() -> None:
    """Clear the process settings cache for controlled CLI/test reinitialization."""
    global _settings, _settings_key
    _settings = None
    _settings_key = None


def get_config_dir() -> Path:
    """Return the prefix-owned directory for install sidecar files."""
    return get_runtime_paths().config


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
    """Load prefix configuration, optionally from an explicit override.

    An explicit override is kept independent from prefix identity and may be a
    TOML file or directory. Without it, only the active prefix's canonical
    ``instance/config/config.toml`` is considered; the working directory is
    never searched.
    """
    global _settings, _settings_key
    paths = get_runtime_paths()
    if (
        config_path is None
        and _settings is not None
        and _settings_key is not None
        and _settings_key[0] == paths.prefix
    ):
        return _settings
    resolved_config = (
        paths.config_file
        if config_path is None
        else Path(config_path).expanduser().resolve()
    )
    key = (paths.prefix, resolved_config)
    if _settings is None or _settings_key != key:
        if resolved_config.exists():
            _settings = Settings.from_path(resolved_config)
        else:
            _settings = Settings()
            _settings._config_file = resolved_config
        _resolve_instance_paths(_settings, paths)
        _settings_key = key
    return _settings


def _resolve_instance_paths(settings: Settings, paths: ArborPressPaths) -> None:
    """Resolve local paths which have instance-relative config semantics."""
    settings.web.media_dir = _resolve_relative_instance_path(
        paths.instance, settings.web.media_dir, "media"
    )
    if settings.cache.file_dir is None:
        settings.cache.file_dir = paths.cache
    else:
        settings.cache.file_dir = _resolve_relative_instance_path(
            paths.cache, settings.cache.file_dir, "cache"
        )
    if settings.logging.file is not None:
        settings.logging.file = _resolve_relative_instance_path(
            paths.log, settings.logging.file, "log"
        )
    if settings.logging.audit_file is not None:
        settings.logging.audit_file = _resolve_relative_instance_path(
            paths.log, settings.logging.audit_file, "audit log"
        )

    url = make_url(settings.db.url)
    database = url.database
    if (
        url.drivername.startswith("sqlite")
        and database is not None
        and database != ""
        and database != ":memory:"
        and not Path(database).is_absolute()
    ):
        data_root = paths.data.resolve(strict=False)
        database_path = (data_root / Path(database)).resolve(strict=False)
        if not database_path.is_relative_to(data_root):
            raise ValueError(
                "Relative SQLite database paths must remain inside instance/data"
            )
        settings.db.url = url.set(database=str(database_path)).render_as_string(
            hide_password=False
        )


def _resolve_relative_instance_path(base: Path, value: Path, label: str) -> Path:
    """Resolve a relative local path under a fixed instance-owned root."""
    candidate = value.expanduser()
    if candidate.is_absolute():
        return candidate
    root = base.resolve(strict=False)
    resolved = (root / candidate).resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError(f"Relative {label} paths must remain inside {root}")
    return resolved
