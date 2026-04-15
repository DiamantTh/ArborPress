"""DB capability detection (§12).

Detects engine and version at startup and sets feature flags.

Supported backends (FOSS only):
  postgresql          PostgreSQL 16+  (PostgreSQL Licence)
  mariadb             MariaDB 11.4+   (GPL-2.0)
  sqlite              SQLite 3.38+    (Public Domain – Dev/Test only)

Supported FTS providers (by priority):
  pg_fts              PostgreSQL ts_vector / ts_query (native)
  mariadb_fulltext    MariaDB FULLTEXT index (native)
  sqlite_fts5         SQLite FTS5 (virtual tables, native)
  meilisearch         External service – dep: meilisearch-python-sdk
  typesense           External service – dep: typesense
  elasticsearch       External service – dep: elasticsearch[async]
  manticore           ManticoreSearch (MySQL protocol)
  fallback            ILIKE/LIKE search (always available)

External FTS engine configuration via config.toml [search]:
  provider            = "auto"         # auto detects natively; override explicitly
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
    """Runtime capability flags of the database."""

    engine_name: str = ""        # "postgresql" | "mysql" (MariaDB) | "sqlite"
    version_string: str = ""
    major: int = 0
    minor: int = 0
    patch: int = 0               # Patch-/Maintenance-Version

    # Feature-Flags (Baseline)
    fts_available: bool = False
    fts_provider: str = "fallback"  # siehe Modul-Docstring
    json_ops: bool = False           # JSON-Funktionen: PG 16+, MariaDB 11.4+, SQLite 3.38+
    generated_cols: bool = False     # Generated/Virtual Columns
    window_funcs: bool = True        # Window Functions (alle Baseline-Versionen)

    # Feature-Flags (neuere Versionen)
    returning: bool = False          # RETURNING in INSERT/UPDATE/DELETE
    merge_stmt: bool = False         # MERGE / INSERT … ON CONFLICT DO UPDATE
    json_table: bool = False         # json_table() / JSON_TABLE() Tabellenfunktion: PG 17+, MariaDB 10.6+
    uuid_type: bool = False          # Nativer UUID-Typ / gen_random_uuid(): PG 16+ (builtin), MariaDB 11.4+
    vector_ops: bool = False         # Vektor/Embedding-Support: pgvector-Extension, MariaDB 11.6+

    # Externe FTS-Engine (falls konfiguriert)
    external_fts: str = ""       # "meilisearch" | "typesense" | "elasticsearch" | ""

    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Capability-Detection
# ---------------------------------------------------------------------------


async def detect_capabilities(engine: AsyncEngine) -> DBCapabilities:
    """Queries the database version and sets feature flags (§12).

    Also detects configured external FTS engines.
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
                caps.patch = caps.minor   # Bei PG 10+ ist minor der Patch-Release
            if caps.major < 16:
                log.warning(
                    "PostgreSQL %d.%d liegt unterhalb der unterstützten Baseline (PG 16+).",
                    caps.major, caps.minor,
                )

            # pg_fts ab PG 9, unsere Baseline ist PG 16+
            caps.fts_available = caps.major >= 16
            caps.fts_provider = "pg_fts" if caps.fts_available else "fallback"
            caps.json_ops = caps.major >= 16
            caps.generated_cols = caps.major >= 16

            # Baseline 16+: RETURNING + MERGE + gen_random_uuid() immer verfügbar
            caps.returning = True
            caps.merge_stmt = True           # MERGE: PG 15+
            caps.uuid_type = True            # gen_random_uuid() builtin: PG 13+
            # json_table() (SQL/JSON): PG 17+
            caps.json_table = caps.major >= 17
            # pgvector: Extension-Check (schlägt still fehl wenn nicht installiert)
            try:
                result = await conn.execute(sa_text(
                    "SELECT 1 FROM pg_type WHERE typname = 'vector' LIMIT 1"
                ))
                caps.vector_ops = result.fetchone() is not None
            except Exception:
                log.debug("pgvector nicht verfügbar", exc_info=True)

        # -------------------------------------------------------------------
        # MariaDB / MySQL
        # -------------------------------------------------------------------
        elif caps.engine_name == "mysql":
            row = await conn.execute(sa_text("SELECT VERSION()"))
            caps.version_string = row.scalar_one()
            m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))
                caps.patch = int(m.group(3)) if m.group(3) else 0

            is_mariadb = "MariaDB" in caps.version_string
            # Baseline: MariaDB 11.4 LTS (neueste 11er LTS, EOL Mai 2029)
            _mariadb_ok = (
                caps.major > 11 or (caps.major == 11 and caps.minor >= 4)
            )
            if is_mariadb and not _mariadb_ok:
                log.warning(
                    "MariaDB %d.%d liegt unterhalb der unterstützten Baseline (11.4+).",
                    caps.major, caps.minor,
                )
            if is_mariadb and _mariadb_ok:
                caps.fts_available = True
                caps.fts_provider = "mariadb_fulltext"
                caps.json_ops = True
                caps.generated_cols = True

                # Ab 11.4 Baseline: RETURNING + MERGE + UUID immer vorhanden
                caps.returning = True        # RETURNING: MariaDB 11.4+
                caps.merge_stmt = True       # MERGE: MariaDB 10.3+
                caps.uuid_type = True        # UUID-Typ: MariaDB 11.4+
                # JSON_TABLE: ab MariaDB 11.4 → bei Baseline 11.4+ immer True
                caps.json_table = True
                # VECTOR-Typ: MariaDB 11.6+
                caps.vector_ops = (
                    caps.major > 11 or (caps.major == 11 and caps.minor >= 6)
                )
            elif not is_mariadb:
                log.error(
                    "Nicht-MariaDB MySQL wird nicht unterstützt. "
                    "Bitte PostgreSQL 16+, MariaDB 11.4+ oder SQLite (Dev) verwenden."
                )

        # -------------------------------------------------------------------
        # SQLite
        # -------------------------------------------------------------------
        elif caps.engine_name == "sqlite":
            row = await conn.execute(sa_text("SELECT sqlite_version()"))
            caps.version_string = row.scalar_one()
            m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))
                caps.patch = int(m.group(3)) if m.group(3) else 0

            # FTS5 has been available since SQLite 3.9 (released 2015)
            # Check whether FTS5 extension is actually compiled
            fts5_available = False
            try:
                await conn.execute(sa_text(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_check "
                    "USING fts5(content)"
                ))
                await conn.execute(sa_text("DROP TABLE IF EXISTS _fts5_check"))
                fts5_available = True
            except Exception:
                log.debug("SQLite FTS5 not available", exc_info=True)

            caps.fts_available = fts5_available
            caps.fts_provider = "sqlite_fts5" if fts5_available else "fallback"
            # SQLite ist immer major=3; Checks nur auf minor
            # JSON-Funktionen (json_each etc.): 3.38+
            caps.json_ops = caps.minor >= 38
            # Generated Columns: 3.31+
            caps.generated_cols = caps.minor >= 31
            # Window Functions: 3.25+
            caps.window_funcs = caps.minor >= 25
            # RETURNING: 3.35+
            caps.returning = caps.minor >= 35
            # SQLite hat kein echtes MERGE; kein json_table(), kein UUID-Typ, kein Vector
            caps.merge_stmt = False
            caps.json_table = False
            caps.uuid_type = False
            caps.vector_ops = False

    # -----------------------------------------------------------------------
    # Detect external FTS engine (optional, overrides native provider)
    # -----------------------------------------------------------------------
    caps.external_fts = await _detect_external_fts()
    if caps.external_fts:
        caps.fts_available = True
        caps.fts_provider = caps.external_fts

    log.info(
        "DB-Capabilities: engine=%s version=%s fts=%s(%s) external_fts=%r "
        "json_ops=%s json_table=%s returning=%s merge=%s uuid=%s vector=%s",
        caps.engine_name,
        caps.version_string,
        caps.fts_available,
        caps.fts_provider,
        caps.external_fts,
        caps.json_ops,
        caps.json_table,
        caps.returning,
        caps.merge_stmt,
        caps.uuid_type,
        caps.vector_ops,
    )
    return caps


async def _detect_external_fts() -> str:
    """Checks configured external FTS engine for reachability.

    Returns the provider name or "" if none configured/reachable.
    """
    try:
        from arborpress.core.site_settings import get_cached, get_defaults
        search = get_cached("search") or get_defaults("search")
        provider = search.get("provider", "auto")

        if provider == "auto":
            return ""  # Native is set in detect_capabilities()

        if provider == "meilisearch":
            return await _check_meilisearch(search)
        if provider == "typesense":
            return await _check_typesense(search)
        if provider == "elasticsearch":
            return await _check_elasticsearch(search)
        if provider == "manticore":
            return "manticore"  # No HTTP check here (MySQL protocol)
    except Exception as exc:
        log.debug("External FTS detection failed: %s", exc)
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
        log.debug("Meilisearch not reachable: %s", url)
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
        log.debug("Typesense not reachable: %s:%s", host, port)
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
        log.debug("Elasticsearch not reachable: %s", url)
    return ""


# ---------------------------------------------------------------------------
# Runtime-Singleton
# ---------------------------------------------------------------------------

_caps: DBCapabilities | None = None


def get_capabilities() -> DBCapabilities:
    """Returns cached capabilities (initialised after detect_capabilities())."""
    if _caps is None:
        raise RuntimeError(
            "DB capabilities not yet initialised. Call detect_capabilities() first."
        )
    return _caps


def set_capabilities(caps: DBCapabilities) -> None:
    global _caps
    _caps = caps
