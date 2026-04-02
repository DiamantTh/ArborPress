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
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    def from_file(cls, path: Path) -> Settings:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        return cls.model_validate(data)


_settings: Settings | None = None


def get_settings(config_path: Path | None = None) -> Settings:
    """Singleton – Ladereihenfolge: config.toml → Env-Vars → Defaults."""
    global _settings
    if _settings is None:
        if config_path is None:
            config_path = Path("config.toml")
        if config_path.exists():
            _settings = Settings.from_file(config_path)
        else:
            _settings = Settings()
    return _settings
