"""Infrastruktur-Konfiguration – config.toml und Umgebungsvariablen.

Enthält nur Einstellungen, die VOR dem Datenbankstart benötigt werden:
  [db]       – Datenbankverbindung
  [web]      – Bind-Adresse, Secret-Key, Base-URL, Admin-Pfad
  [auth]     – Session-TTLs, WebAuthn-UV, Step-up (Sicherheitsinfrastruktur)
  [logging]  – Log-Level und Dateipfade
  [plugins]  – Plugin-Verzeichnisse

Alle inhaltlichen Einstellungen (Mail, Kommentare, Captcha, Theme, Federation,
Suche, allgemeine Blog-Einstellungen) werden über arborpress.core.site_settings
aus der Datenbank gelesen und im Admin-Interface unter /admin/settings gepflegt.

Konfigurationsquellen (Ladereihenfolge, spätere überschreiben frühere):
  1.  --config /pfad/zu/config.toml  – einzelne Datei
  2.  --config /pfad/zu/conf.d/      – alle *.toml im Verzeichnis (sortiert)
  3.  conf.d/                         – lokales Verzeichnis (auto-discover)
  4.  config.toml                     – einzelne Datei (auto-discover)
  5.  Defaults + Umgebungsvariablen   – ARBORPRESS_SECTION__KEY=value

include-Direktive (in jeder TOML-Datei verwendbar):
  include = ["secrets.toml", "/etc/arborpress/db.toml"]
  Relative Pfade werden relativ zum Verzeichnis der enthaltenden Datei
  aufgelöst. Includes unterstützen selbst wieder include (rekursiv).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# TOML-Lade-Hilfsfunktionen
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """Rekursives Dict-Merge; Override gewinnt bei skalaren Konflikten.

    TOML-Tabellen werden zusammengeführt statt ersetzt, so dass
    ``[db] pool_size = 5`` in einer Datei ``url = "..."`` aus einer
    anderen Datei nicht löscht.
    """
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_toml_file(path: Path) -> dict:
    """Lädt eine TOML-Datei und verarbeitet optionale ``include``-Direktiven.

    ``include = ["secrets.toml", "/etc/arborpress/db.toml"]``

    Relative Pfade werden relativ zum Verzeichnis der Datei aufgelöst.
    Includes werden auf die Hauptdatei gemergt (Override-Semantik).
    Includes dürfen selbst include-Direktiven enthalten (rekursiv).
    """
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    includes: list[str] = data.pop("include", [])
    base_dir = path.parent
    for inc in includes:
        inc_path = Path(inc) if Path(inc).is_absolute() else base_dir / inc
        if not inc_path.exists():
            raise FileNotFoundError(
                f"Config-Include nicht gefunden: {inc_path}"
                f" (referenziert in {path})"
            )
        data = _deep_merge(data, _load_toml_file(inc_path))

    return data


def _load_config_dir(directory: Path) -> tuple[dict, Path]:
    """Lädt alle ``*.toml``-Dateien aus einem Verzeichnis (alphabetisch sortiert).

    Gibt das gemergete Dict und den ``_config_file``-Ankerpfad zurück
    (wird für relative Pfadauflösung benötigt; bevorzugt ``config.toml``
    im Verzeichnis, sonst die erste geladene Datei).
    """
    files = sorted(directory.glob("*.toml"))
    if not files:
        raise FileNotFoundError(
            f"Kein *.toml im Konfig-Verzeichnis gefunden: {directory}"
        )
    merged: dict = {}
    for toml_file in files:
        merged = _deep_merge(merged, _load_toml_file(toml_file))

    # Ankerpfad für relative Pfadauflösung

    anchor = directory / "config.toml"
    if not anchor.exists():
        anchor = files[0]
    return merged, anchor.resolve()


class DatabaseSettings(BaseSettings):
    """Datenbankverbindung.

    Unterstützte URL-Schemata:
      postgresql+asyncpg://...   – PostgreSQL (Prod-Default)
      mysql+aiomysql://...       – MariaDB / MySQL
      sqlite+aiosqlite:///...    – SQLite (Dev/Test; kein pool_size)
      sqlite+aiosqlite:///:memory:  – In-Memory-SQLite (nur Tests)
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
    # Medienspeicher
    media_dir: Path = Path("media")


class AuthSettings(BaseSettings):
    require_uv: bool = False
    legacy_password_enabled: bool = False
    stepup_ttl: int = 900
    admin_session_ttl: int = 3600
    auth_rate_limit: str = "10/minute"
    # Dedizierter Key-Encryption-Key für Actor-Keypairs (§5).
    # Getrennt von web.secret_key, damit Session-Key-Rotation die
    # AP-Schlüssel NICHT unbrauchbar macht.
    # Generieren: arborpress federation kek-init
    # Format: 32-Byte base64url-kodierter Wert (von Fernet erwartet)
    actor_key_enc_key: SecretStr | None = None


class LoggingSettings(BaseSettings):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    file: Path | None = None
    access_log: bool = False
    audit_log: bool = True
    audit_file: Path | None = None


class CacheSettings(BaseSettings):
    """Cache-Backend-Konfiguration.

    Backends: memory (default) | redis | memcached | file | none

    memory:     In-Process-Dict mit TTL – kein externer Dienst nötig.
    redis:      redis-py async. Zusatz-Dep: pip install 'redis[hiredis]'
    memcached:  aiomcache. Zusatz-Dep: pip install aiomcache
    file:       JSON-Dateien auf Disk – kein Rebuild nach Neustart.
    none:       Cache deaktiviert (immer Cache-Miss).
    """
    backend: Literal["memory", "redis", "memcached", "file", "none"] = "memory"
    ttl: int = 300           # Standard-TTL in Sekunden
    prefix: str = "ap:"      # Key-Präfix
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
        """Gibt alle dirs als absolute Pfade zurück.

        Relative Pfade werden relativ zum Verzeichnis der Config-Datei
        aufgelöst (nicht relativ zum cwd).
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
        """Lädt Settings aus einer Datei oder einem Verzeichnis.

        Datei:       TOML-Datei, optional mit ``include``-Direktive.
        Verzeichnis: alle ``*.toml`` alphabetisch sortiert und gemergt.
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
        """Rückwärtskompatibel – delegiert an from_path."""
        return cls.from_path(path)

    def plugin_dirs(self) -> list[Path]:
        """Plugin-Verzeichnisse als aufgelöste absolute Pfade.

        Relative Pfade werden relativ zur Config-Datei aufgelöst,
        nicht relativ zum Arbeitsverzeichnis.
        """
        cfg = getattr(self, "_config_file", None)
        if cfg is not None:
            return self.plugins.resolved_dirs(cfg)
        return [d.resolve() for d in self.plugins.dirs]


_settings: Settings | None = None


def get_settings(config_path: Path | None = None) -> Settings:
    """Singleton – Ladereihenfolge: conf.d/ → config.toml → Env-Vars → Defaults.

    ``config_path`` kann eine Datei oder ein Verzeichnis sein.
    Auto-Discover (wenn None): erst ``conf.d/``, dann ``config.toml``.
    """
    global _settings
    if _settings is None:
        if config_path is None:
            if Path("conf.d").is_dir():
                config_path = Path("conf.d")
            else:
                config_path = Path("config.toml")
        if config_path.exists():
            _settings = Settings.from_path(config_path)
        else:
            _settings = Settings()
    return _settings
