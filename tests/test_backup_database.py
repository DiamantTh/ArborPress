from __future__ import annotations

import datetime as dt
import decimal
import math
import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from arborpress.backups.compression import CompressionSettings
from arborpress.backups.database import (
    DATABASE_HEADER_KIND,
    decode_value,
    encode_value,
    export_database,
    validate_database_stream,
)


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        42,
        -4,
        1.5,
        float("nan"),
        "ArborPress",
        b"binary\x00data",
        decimal.Decimal("123.4500"),
        dt.datetime(2026, 10, 18, 12, 30, tzinfo=dt.UTC),
        dt.date(2026, 10, 18),
        dt.time(12, 30, 45, tzinfo=dt.UTC),
        uuid.UUID("12345678-1234-5678-1234-567812345678"),
    ],
)
def test_typed_database_codec_roundtrips_supported_values(value: object) -> None:
    decoded = decode_value(encode_value(value))
    if isinstance(value, float) and math.isnan(value):
        assert isinstance(decoded, float) and math.isnan(decoded)
    else:
        assert decoded == value


def test_json_column_is_explicitly_typed() -> None:
    encoded = encode_value({"a": [1, True, None]}, json_column=True)

    assert encoded == {"t": "json", "v": {"a": [1, True, None]}}
    assert decode_value(encoded) == {"a": [1, True, None]}


def test_database_codec_rejects_unknown_or_malformed_tags() -> None:
    with pytest.raises(ValueError, match="Malformed database value codec"):
        decode_value("not-a-cell")
    with pytest.raises(ValueError, match="Unknown database value codec tag"):
        decode_value({"t": "python-pickle", "v": "payload"})


@pytest.mark.asyncio
async def test_sqlite_backup_api_snapshot_exports_streamed_database(tmp_path: Path) -> None:
    database_path = tmp_path / "source.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    output = tmp_path / "database.ndjson.bz2"
    try:
        import arborpress.models  # noqa: F401
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(engine)
        result = await export_database(
            engine,
            output,
            compression=CompressionSettings(),
            temporary_root=tmp_path / "tmp",
        )
    finally:
        await engine.dispose()

    assert output.is_file()
    assert result.database_system == "sqlite"
    assert result.consistency_mode.startswith("sqlite-backup-api-snapshot")
    assert "users" in result.tables
    parsed = validate_database_stream(output, "bz2")
    assert parsed["header"]["kind"] == DATABASE_HEADER_KIND
    assert parsed["header"]["format_version"] == 1
    assert parsed["header"]["database_system"] == "sqlite"
    assert parsed["header"]["tables"]
    table_names = {table["name"] for table in parsed["header"]["tables"]}
    assert "users" in table_names
    assert "alembic_version" not in table_names
