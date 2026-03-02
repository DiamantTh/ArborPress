"""DB-Capability-Detection (§12).

Erkennt Motor und Version beim Start und setzt Feature-Flags.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncEngine

log = logging.getLogger("arborpress.db.capabilities")


@dataclass
class DBCapabilities:
    """Runtime-Capability-Flags der Datenbank."""

    engine_name: str = ""        # "postgresql" | "mysql"
    version_string: str = ""
    major: int = 0
    minor: int = 0

    # Feature-Flags
    fts_available: bool = False   # Full-Text-Search nativ
    fts_provider: str = "fallback"  # "pg_fts" | "mariadb_fulltext" | "fallback"
    json_ops: bool = False        # JSON-Operatoren
    generated_cols: bool = False  # Generated/Computed Columns
    window_funcs: bool = True     # Fast immer vorhanden

    extra: dict = field(default_factory=dict)


async def detect_capabilities(engine: AsyncEngine) -> DBCapabilities:
    """Fragt Datenbankversion ab und setzt Feature-Flags (§12)."""
    caps = DBCapabilities()
    caps.engine_name = engine.dialect.name  # "postgresql" oder "mysql"

    async with engine.connect() as conn:
        if caps.engine_name == "postgresql":
            row = await conn.execute(
                # type: ignore[arg-type]
                __import__("sqlalchemy").text("SELECT version()")
            )
            caps.version_string = row.scalar_one()
            # Beispiel: "PostgreSQL 16.3 on ..."
            m = re.search(r"PostgreSQL (\d+)\.(\d+)", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))

            if caps.major >= 16:
                caps.fts_available = True
                caps.fts_provider = "pg_fts"
                caps.json_ops = True
                caps.generated_cols = True

        elif caps.engine_name == "mysql":
            row = await conn.execute(
                __import__("sqlalchemy").text("SELECT VERSION()")
            )
            caps.version_string = row.scalar_one()
            # MariaDB: "11.x.x-MariaDB" | MySQL: "8.x.x"
            m = re.match(r"(\d+)\.(\d+)", caps.version_string)
            if m:
                caps.major, caps.minor = int(m.group(1)), int(m.group(2))

            is_mariadb = "MariaDB" in caps.version_string
            if is_mariadb and caps.major >= 11:
                caps.fts_available = True
                caps.fts_provider = "mariadb_fulltext"
                caps.json_ops = True
                caps.generated_cols = caps.major >= 11

    log.info(
        "DB-Capabilities: engine=%s version=%s fts=%s(%s)",
        caps.engine_name,
        caps.version_string,
        caps.fts_available,
        caps.fts_provider,
    )
    return caps


# Runtime-Singleton
_caps: DBCapabilities | None = None


def get_capabilities() -> DBCapabilities:
    """Gibt gecachte Capabilities zurück (nach detect_capabilities() initialisiert)."""
    if _caps is None:
        raise RuntimeError("DB-Capabilities noch nicht initialisiert. detect_capabilities() aufrufen.")
    return _caps


def set_capabilities(caps: DBCapabilities) -> None:
    global _caps
    _caps = caps
