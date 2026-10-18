"""Streaming, backend-neutral logical database snapshots for backup sets."""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import enum
import json
import math
import os
import sqlite3
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.sql.sqltypes import JSON

from arborpress.backups.compression import (
    CompressionBackend,
    CompressionSettings,
    open_compressed_writer,
)

DATABASE_STREAM_VERSION = 1
DATABASE_HEADER_KIND = "arborpress.database"
DATABASE_ROW_KIND = "row"
DATABASE_FETCH_SIZE = 500


@dataclass(frozen=True, slots=True)
class DatabaseExportResult:
    database_system: str
    alembic_revisions: tuple[str, ...]
    tables: tuple[str, ...]
    row_counts: dict[str, int]
    uncompressed_size_bytes: int
    consistency_mode: str


def encode_value(value: object, *, json_column: bool = False) -> dict[str, Any]:
    """Encode a SQLAlchemy scalar with an explicit stable type tag."""
    if value is None:
        return {"t": "null"}
    if json_column:
        return {"t": "json", "v": value}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "integer", "v": str(value)}
    if isinstance(value, float):
        if math.isfinite(value):
            return {"t": "float", "v": value.hex()}
        return {"t": "float", "v": repr(value)}
    if isinstance(value, str):
        return {"t": "string", "v": value}
    if isinstance(value, bytes | bytearray | memoryview):
        return {"t": "bytes", "v": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, decimal.Decimal):
        return {"t": "decimal", "v": str(value)}
    if isinstance(value, dt.datetime):
        return {"t": "datetime", "v": value.isoformat()}
    if isinstance(value, dt.date):
        return {"t": "date", "v": value.isoformat()}
    if isinstance(value, dt.time):
        return {"t": "time", "v": value.isoformat()}
    if isinstance(value, uuid.UUID):
        return {"t": "uuid", "v": str(value)}
    if isinstance(value, enum.Enum):
        return {"t": "enum", "v": encode_value(value.value)}
    raise TypeError(f"Unsupported database value type: {type(value).__qualname__}")


def decode_value(value: object) -> object:
    """Validate and decode a value encoded by :func:`encode_value`."""
    if not isinstance(value, dict) or not isinstance(value.get("t"), str):
        raise ValueError("Malformed database value codec")
    kind = value["t"]
    if kind == "null":
        if set(value) != {"t"}:
            raise ValueError("Malformed null database value")
        return None
    if kind == "json":
        if "v" not in value:
            raise ValueError("Malformed JSON database value")
        return value["v"]
    if kind == "bool":
        if type(value.get("v")) is not bool:
            raise ValueError("Malformed boolean database value")
        return value["v"]
    raw = value.get("v")
    if not isinstance(raw, str):
        raise ValueError(f"Malformed {kind} database value")
    if kind == "integer":
        return int(raw)
    if kind == "float":
        return float.fromhex(raw) if raw not in {"nan", "inf", "-inf"} else float(raw)
    if kind == "string":
        return raw
    if kind == "bytes":
        return base64.b64decode(raw, validate=True)
    if kind == "decimal":
        return decimal.Decimal(raw)
    if kind == "datetime":
        return dt.datetime.fromisoformat(raw)
    if kind == "date":
        return dt.date.fromisoformat(raw)
    if kind == "time":
        return dt.time.fromisoformat(raw)
    if kind == "uuid":
        return uuid.UUID(raw)
    if kind == "enum":
        return decode_value(value.get("v"))
    raise ValueError(f"Unknown database value codec tag: {kind!r}")


def validate_database_stream(path: Path, backend: CompressionBackend) -> dict[str, Any]:
    """Parse every NDJSON line, validating the version header and row codecs."""
    import io

    from arborpress.backups.compression import open_compressed_reader

    with open_compressed_reader(path, backend) as compressed:
        text = io.TextIOWrapper(compressed, encoding="utf-8", newline="\n")
        try:
            first = text.readline()
            if not first:
                raise ValueError("Database export is empty")
            header = json.loads(first)
            if (
                not isinstance(header, dict)
                or header.get("kind") != DATABASE_HEADER_KIND
                or header.get("format_version") != DATABASE_STREAM_VERSION
            ):
                raise ValueError("Unsupported database stream header")
            tables = header.get("tables")
            if not isinstance(tables, list):
                raise ValueError("Database stream header has no table list")
            columns: dict[str, int] = {}
            for table in tables:
                if not isinstance(table, dict) or not isinstance(table.get("name"), str):
                    raise ValueError("Malformed table declaration in database stream")
                table_name = table["name"]
                declared_columns = table.get("columns")
                if not isinstance(declared_columns, list) or table_name in columns:
                    raise ValueError("Malformed or duplicate table declaration")
                if any(
                    not isinstance(column, dict) or not isinstance(column.get("name"), str)
                    for column in declared_columns
                ):
                    raise ValueError("Malformed column declaration in database stream")
                columns[table_name] = len(declared_columns)
            row_count = 0
            while line := text.readline():
                record = json.loads(line)
                if not isinstance(record, dict) or record.get("kind") != DATABASE_ROW_KIND:
                    raise ValueError("Malformed database row record")
                table_name = record.get("table")
                values = record.get("values")
                if (
                    table_name not in columns
                    or not isinstance(values, list)
                    or len(values) != columns[table_name]
                ):
                    raise ValueError("Database row does not match its table declaration")
                for value in values:
                    decode_value(value)
                row_count += 1
            return {"header": header, "row_count": row_count}
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Malformed database NDJSON stream: {exc}") from exc
        finally:
            # Do not close the compressed stream twice through TextIOWrapper.
            text.detach()


async def export_database(
    engine: AsyncEngine,
    output_path: Path,
    *,
    compression: CompressionSettings,
    temporary_root: Path,
) -> DatabaseExportResult:
    """Write a compressed logical export from a consistent backend snapshot."""
    temporary_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if engine.dialect.name == "sqlite":
        return await _export_sqlite_snapshot(
            engine,
            output_path,
            compression=compression,
            temporary_root=temporary_root,
        )
    return await _export_transactional_snapshot(engine, output_path, compression)


async def _export_sqlite_snapshot(
    engine: AsyncEngine,
    output_path: Path,
    *,
    compression: CompressionSettings,
    temporary_root: Path,
) -> DatabaseExportResult:
    with tempfile.TemporaryDirectory(prefix="backup-sqlite-", dir=temporary_root) as directory:
        snapshot_path = Path(directory) / "snapshot.sqlite3"
        async with engine.connect() as source:
            raw = await source.get_raw_connection()
            source_driver = raw.driver_connection
            if source_driver is None:
                raise RuntimeError("SQLite source connection does not expose its driver connection")
            # aiosqlite schedules the SQLite Backup API on the configured source
            # connection. The stdlib target uses check_same_thread=False because
            # the source connection's worker thread invokes sqlite3.backup().
            with sqlite3.connect(snapshot_path, check_same_thread=False) as target:
                await source_driver.backup(target)
        snapshot_engine = create_async_engine(f"sqlite+aiosqlite:///{snapshot_path}")
        try:
            async with snapshot_engine.connect() as connection:
                async with connection.begin():
                    result = await _write_export(connection, output_path, compression)
            return DatabaseExportResult(
                database_system="sqlite",
                alembic_revisions=result["revisions"],
                tables=result["tables"],
                row_counts=result["row_counts"],
                uncompressed_size_bytes=result["uncompressed_size_bytes"],
                consistency_mode="sqlite-backup-api-snapshot; stable-file-reads",
            )
        finally:
            await snapshot_engine.dispose()


async def _export_transactional_snapshot(
    engine: AsyncEngine,
    output_path: Path,
    compression: CompressionSettings,
) -> DatabaseExportResult:
    dialect = engine.dialect.name
    if dialect not in {"postgresql", "mysql", "mariadb"}:
        raise ValueError(f"Unsupported database snapshot backend: {dialect}")
    async with engine.connect() as original_connection:
        connection = original_connection
        if dialect in {"mysql", "mariadb"}:
            connection = await original_connection.execution_options(isolation_level="AUTOCOMMIT")
            await connection.exec_driver_sql(
                "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ"
            )
            await connection.exec_driver_sql(
                "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"
            )
            try:
                await _assert_transactional_mariadb_tables(connection)
                server_version = str(await connection.scalar(sa.text("SELECT VERSION()")) or "")
                system = "mariadb" if "mariadb" in server_version.lower() else "mysql"
                result = await _write_export(
                    connection,
                    output_path,
                    compression,
                    database_system=system,
                )
                await connection.exec_driver_sql("COMMIT")
            except Exception:
                await connection.exec_driver_sql("ROLLBACK")
                raise
        else:
            connection = await original_connection.execution_options(
                isolation_level="REPEATABLE READ"
            )
            async with connection.begin():
                await connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                result = await _write_export(connection, output_path, compression)
            system = "postgresql"
    return DatabaseExportResult(
        database_system=system,
        alembic_revisions=result["revisions"],
        tables=result["tables"],
        row_counts=result["row_counts"],
        uncompressed_size_bytes=result["uncompressed_size_bytes"],
        consistency_mode=_transactional_consistency_mode(system),
    )


def _transactional_consistency_mode(system: str) -> str:
    if system == "postgresql":
        return "postgresql-repeatable-read-read-only-transaction; stable-file-reads"
    if system == "mariadb":
        return "mariadb-consistent-snapshot-read-only-transaction; stable-file-reads"
    return "mysql-consistent-snapshot-read-only-transaction; stable-file-reads"


async def _assert_transactional_mariadb_tables(connection: AsyncConnection) -> None:
    """Refuse a claimed consistent snapshot if application tables are nontransactional."""
    import arborpress.models  # noqa: F401 - register all ArborPress tables
    from arborpress.core.db import Base

    result = await connection.execute(
        sa.text(
            "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = DATABASE()"
        )
    )
    engines = {str(row[0]): str(row[1] or "").lower() for row in result}
    required = {table.name for table in Base.metadata.sorted_tables}
    missing = required - engines.keys()
    if missing:
        raise RuntimeError(
            "Cannot establish a consistent database backup; application tables are missing: "
            + ", ".join(sorted(missing))
        )
    unsupported = sorted(name for name in required if engines[name] != "innodb")
    if unsupported:
        raise RuntimeError(
            "MariaDB/MySQL consistent snapshots require transactional InnoDB tables; "
            "unsupported tables: " + ", ".join(unsupported)
        )


async def _write_export(
    connection: AsyncConnection,
    output_path: Path,
    compression: CompressionSettings,
    *,
    database_system: str | None = None,
) -> dict[str, Any]:
    from alembic.runtime.migration import MigrationContext

    import arborpress.models  # noqa: F401 - register all ArborPress tables
    from arborpress.core.db import Base

    revisions = tuple(
        await connection.run_sync(
            lambda sync_connection: tuple(
                sorted(MigrationContext.configure(sync_connection).get_current_heads())
            )
        )
    )
    tables = tuple(Base.metadata.sorted_tables)
    table_headers = [
        {
            "name": table.name,
            "schema": table.schema,
            "columns": [
                {
                    "name": column.name,
                    "type": type(column.type).__name__,
                    "nullable": column.nullable,
                    "primary_key": column.primary_key,
                }
                for column in table.columns
            ],
        }
        for table in tables
    ]
    header = {
        "kind": DATABASE_HEADER_KIND,
        "format_version": DATABASE_STREAM_VERSION,
        "database_system": database_system or connection.dialect.name,
        "alembic_revisions": list(revisions),
        "tables": table_headers,
    }
    temporary_path = output_path.with_name(output_path.name + ".part")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    row_counts: dict[str, int] = {}
    uncompressed_size = 0
    try:
        with open_compressed_writer(temporary_path, compression) as stream:
            uncompressed_size += _write_json_line(stream, header)
            for table in tables:
                row_counts[table.name] = 0
                statement = sa.select(table)
                if table.primary_key.columns:
                    statement = statement.order_by(*table.primary_key.columns)
                result = await connection.stream(
                    statement.execution_options(yield_per=DATABASE_FETCH_SIZE)
                )
                try:
                    async for row in result.mappings():
                        values = [
                            encode_value(
                                row[column.name], json_column=isinstance(column.type, JSON)
                            )
                            for column in table.columns
                        ]
                        uncompressed_size += _write_json_line(
                            stream,
                            {"kind": DATABASE_ROW_KIND, "table": table.name, "values": values},
                        )
                        row_counts[table.name] += 1
                finally:
                    await result.close()
        with temporary_path.open("rb") as compressed_file:
            os.fsync(compressed_file.fileno())
        os.replace(temporary_path, output_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return {
        "revisions": revisions,
        "tables": tuple(table.name for table in tables),
        "row_counts": row_counts,
        "uncompressed_size_bytes": uncompressed_size,
    }


def _write_json_line(stream: Any, value: object) -> int:
    encoded = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    stream.write(encoded)
    return len(encoded)
