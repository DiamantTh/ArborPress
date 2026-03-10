"""DB-Capability-Detection (§12).

Erkennt Motor und Version beim Start und setzt Feature-Flags.

Unterstützte FTS-Provider (in Priorität):
  pg_fts              PostgreSQL ts_vector / ts_query (nativ)
  mariadb_fulltext    MariaDB/MySQL FULLTEXT-Index (nativ)
  sqlite_fts5         SQLite FTS5 (virtuelle Tabellen, nativ)
  meilisearch         Externer Dienst – Dep: meilisearch-python-sdk
  typesense           Externer Dienst – Dep: typesense
  elasticsearch       Externer Dienst – Dep: elasticsearch[async]
  manticore           ManticoreSearch (MySQL-Protokoll)
  fallback            ILIKE/LIKE-Suche (immer verfügbar)

Externe FTS-Engine-Konfiguration via config.toml [search]:
  provider            = "auto"         # auto erkennt nativ; explizit überschreiben
  meilisearch_url     = "http://localhost:7700"
  meilisearch_api_key = ""
  typesense_host      = "localhost"
  typesense_port      = 8108
  typesense_api_key   = ""
  elasticsearch_url   = "http://localhost:9200"
  manticore_url       = "mysql://localhost:9306"
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncEngine

log = logging.getLogger("arborpress.db.capabilities")

# ---------------------------------------------------------------------------
# Capability-Datenklasse
# ---------------------------------------------------------------------------


@dataclass
class DBCapabilities:
    """Runtime-Capability-Flags der Datenbank."""

    engine_name: str = ""        # "postgresql" | "mysql" | "sqlite"
    version_string: str = ""
    major: int = 0
    minor: int = 0

    # Feature-Flags
    fts_available: bool = False
    fts_provider: str = "fallback"  # siehe Modul-Docstring
    json_ops: bool = False
    generated_cols: bool = False
    window_funcs: bool = True

    # Externe FTS-Engine (falls konfiguriert)
    external_fts: str = ""       # "meilisearch" | "typesense" | "elasticsearch" | ""

    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Capability-Detection
# ---------------------------------------------------------------------------


async def detect_capabilities(engine: AsyncEngine) -> DBCapabilities:
    """Fragt Datenbankversion ab und setzt Feature-Flags (§12).

    Erkennt zusätzlich konfigurierte externe FTS-Engines.
    """
    from sqlalchemy import text as sa_text

    caps = DBCapabilities()
    caps.engine_name = engine.dialect.name  # "postgresql" | "mysql" | "sqlite"

    async with engine.connect() as conn:
        # -------------------------------------------------------------------
        # PostgreSQL
        # -------------------------------------------------------------------
        if caps.engine_name == "postgresql":
            row = await conn.execute(sa_text("SELECT version()"))
            caps.version_string = row.scalar_one()
            m = re.search(r"PostgreSQL (\d+)\.(\d+)", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))

            # pg_fts ab PG 9, unsere Baseline ist PG 14+
            caps.fts_available = caps.major >= 14
            caps.fts_provider = "pg_fts" if caps.fts_available else "fallback"
            caps.json_ops = caps.major >= 14
            caps.generated_cols = caps.major >= 12

        # -------------------------------------------------------------------
        # MariaDB / MySQL
        # -------------------------------------------------------------------
        elif caps.engine_name == "mysql":
            row = await conn.execute(sa_text("SELECT VERSION()"))
            caps.version_string = row.scalar_one()
            m = re.match(r"(\d+)\.(\d+)", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))

            is_mariadb = "MariaDB" in caps.version_string
            if is_mariadb and caps.major >= 10:
                caps.fts_available = True
                caps.fts_provider = "mariadb_fulltext"
                caps.json_ops = True
                caps.generated_cols = caps.major >= 10
            elif not is_mariadb and caps.major >= 8:
                # MySQL 8 – FULLTEXT vorhanden, aber ohne Ranking wie MariaDB
                caps.fts_available = True
                caps.fts_provider = "mariadb_fulltext"
                caps.json_ops = True
                caps.generated_cols = True

        # -------------------------------------------------------------------
        # SQLite
        # -------------------------------------------------------------------
        elif caps.engine_name == "sqlite":
            row = await conn.execute(sa_text("SELECT sqlite_version()"))
            caps.version_string = row.scalar_one()
            m = re.match(r"(\d+)\.(\d+)", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))

            # FTS5 ist seit SQLite 3.9 verfügbar (released 2015)
            # Prüfen ob FTS5-Extension tatsächlich kompiliert ist
            fts5_available = False
            try:
                await conn.execute(sa_text(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_check "
                    "USING fts5(content)"
                ))
                await conn.execute(sa_text("DROP TABLE IF EXISTS _fts5_check"))
                fts5_available = True
            except Exception:
                pass

            caps.fts_available = fts5_available
            caps.fts_provider = "sqlite_fts5" if fts5_available else "fallback"
            # SQLite hat native JSON-Funktionen ab 3.38 (json_each etc.)
            caps.json_ops = caps.major >= 3 and caps.minor >= 38
            # Generated Columns ab SQLite 3.31
            caps.generated_cols = caps.major >= 3 and caps.minor >= 31
            # Window Functions ab SQLite 3.25
            caps.window_funcs = caps.major >= 3 and caps.minor >= 25

    # -----------------------------------------------------------------------
    # Externe FTS-Engine erkennen (optional, überschreibt nativen Provider)
    # -----------------------------------------------------------------------
    caps.external_fts = await _detect_external_fts()
    if caps.external_fts:
        caps.fts_available = True
        caps.fts_provider = caps.external_fts

    log.info(
        "DB-Capabilities: engine=%s version=%s fts=%s(%s) external_fts=%r",
        caps.engine_name,
        caps.version_string,
        caps.fts_available,
        caps.fts_provider,
        caps.external_fts,
    )
    return caps


async def _detect_external_fts() -> str:
    """Prüft konfigurierte externe FTS-Engine auf Erreichbarkeit.

    Gibt den Provider-Namen zurück oder "" wenn keine konfiguriert/erreichbar.
    """
    try:
        from arborpress.core.site_settings import get_cached, get_defaults
        search = get_cached("search") or get_defaults("search")
        provider = search.get("provider", "auto")

        if provider == "auto":
            return ""  # Nativ wird in detect_capabilities() gesetzt

        if provider == "meilisearch":
            return await _check_meilisearch(search)
        if provider == "typesense":
            return await _check_typesense(search)
        if provider == "elasticsearch":
            return await _check_elasticsearch(search)
        if provider == "manticore":
            return "manticore"  # Kein HTTP-Check hier (MySQL-Protokoll)
    except Exception as exc:
        log.debug("Externe FTS-Erkennung fehlgeschlagen: %s", exc)
    return ""


async def _check_meilisearch(cfg: dict) -> str:
    url = cfg.get("meilisearch_url", "http://localhost:7700")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{url}/health")
            if r.status_code == 200:
                return "meilisearch"
    except Exception:
        log.debug("Meilisearch nicht erreichbar: %s", url)
    return ""


async def _check_typesense(cfg: dict) -> str:
    host = cfg.get("typesense_host", "localhost")
    port = cfg.get("typesense_port", 8108)
    api_key = cfg.get("typesense_api_key", "")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(
                f"http://{host}:{port}/health",
                headers={"X-TYPESENSE-API-KEY": api_key},
            )
            if r.status_code == 200:
                return "typesense"
    except Exception:
        log.debug("Typesense nicht erreichbar: %s:%s", host, port)
    return ""


async def _check_elasticsearch(cfg: dict) -> str:
    url = cfg.get("elasticsearch_url", "http://localhost:9200")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(url)
            if r.status_code == 200:
                return "elasticsearch"
    except Exception:
        log.debug("Elasticsearch nicht erreichbar: %s", url)
    return ""


# ---------------------------------------------------------------------------
# Runtime-Singleton
# ---------------------------------------------------------------------------

_caps: DBCapabilities | None = None


def get_capabilities() -> DBCapabilities:
    """Gibt gecachte Capabilities zurück (nach detect_capabilities() initialisiert)."""
    if _caps is None:
        raise RuntimeError(
            "DB-Capabilities noch nicht initialisiert. detect_capabilities() aufrufen."
        )
    return _caps


def set_capabilities(caps: DBCapabilities) -> None:
    global _caps
    _caps = caps
