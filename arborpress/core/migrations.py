"""ArborPress-owned Alembic API and schema-state checks.

This module deliberately depends only on configuration, SQLAlchemy and the
packaged Alembic environment. It does not initialize Quart or other services.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy.engine import Connection, Inspector
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

import arborpress.models  # noqa: F401 - register every ORM table before status checks
from arborpress.core.db import Base, get_engine

log = logging.getLogger("arborpress.migrations")

BASELINE_REVISION = "0001_pre_alembic_baseline"
_LOCK_NAME = "arborpress:schema-migrations"
_POSTGRES_LOCK_KEY = 4_701_642_468_615_832_403

SchemaState = Literal[
    "current",
    "behind",
    "empty",
    "legacy",
    "unknown_legacy",
    "unknown_revision",
    "invalid_version",
    "multiple_heads",
    "history_mismatch",
    "schema_mismatch",
]


class MigrationError(RuntimeError):
    """A database cannot safely be migrated or served by this ArborPress build."""


class MigrationLockError(MigrationError):
    """Another process holds the database migration lock past the timeout."""


@dataclass(frozen=True, slots=True)
class SchemaStatus:
    state: SchemaState
    current_revisions: tuple[str, ...]
    head_revision: str | None
    detail: str

    @property
    def is_current(self) -> bool:
        return self.state == "current"


def _config() -> Config:
    ini_file = Path(__file__).parent.parent / "migrations" / "alembic.ini"
    return Config(str(ini_file))


def _scripts(config: Config | None = None) -> ScriptDirectory:
    return ScriptDirectory.from_config(config or _config())


def _run_command(
    connection: Connection,
    operation: Callable[..., object],
    *args: object,
) -> object:
    config = _config()
    config.attributes["connection"] = connection
    return operation(config, *args)


async def _command(
    connection: AsyncConnection,
    operation: Callable[..., object],
    *args: object,
) -> object:
    return await connection.run_sync(
        lambda sync_connection: _run_command(sync_connection, operation, *args)
    )


@asynccontextmanager
async def _migration_lock(
    connection: AsyncConnection,
    *,
    timeout: float = 30.0,
) -> AsyncIterator[None]:
    """Serialize migrations across hosts using a lock owned by the database."""
    dialect = connection.dialect.name
    lock_acquired = False
    try:
        if dialect == "postgresql":
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                lock_acquired = bool(
                    await connection.scalar(
                        sa.text("SELECT pg_try_advisory_lock(:key)"),
                        {"key": _POSTGRES_LOCK_KEY},
                    )
                )
                if lock_acquired:
                    break
                await asyncio.sleep(min(0.2, max(deadline - time.monotonic(), 0)))
        elif dialect in {"mysql", "mariadb"}:
            lock_acquired = (
                await connection.scalar(
                    sa.text("SELECT GET_LOCK(:name, :timeout)"),
                    {"name": _LOCK_NAME, "timeout": max(0, int(timeout))},
                )
                == 1
            )
        elif dialect == "sqlite":
            await connection.exec_driver_sql(f"PRAGMA busy_timeout = {max(0, int(timeout * 1000))}")
            try:
                await connection.exec_driver_sql("BEGIN EXCLUSIVE")
            except sa.exc.OperationalError as exc:
                raise MigrationLockError(
                    f"Could not acquire the database migration lock within {timeout:g} seconds."
                ) from exc
            lock_acquired = True
        else:
            raise MigrationError(f"Unsupported database backend for migration locking: {dialect}")

        if not lock_acquired:
            raise MigrationLockError(
                f"Could not acquire the database migration lock within {timeout:g} seconds."
            )
        yield
        if connection.in_transaction():
            await connection.commit()
    except Exception:
        if connection.in_transaction():
            await connection.rollback()
        raise
    finally:
        if lock_acquired and dialect == "postgresql":
            await connection.scalar(
                sa.text("SELECT pg_advisory_unlock(:key)"),
                {"key": _POSTGRES_LOCK_KEY},
            )
        elif lock_acquired and dialect in {"mysql", "mariadb"}:
            await connection.scalar(sa.text("SELECT RELEASE_LOCK(:name)"), {"name": _LOCK_NAME})


def _table_names(inspector: Inspector) -> set[str]:
    return set(inspector.get_table_names())


def _normalized_action(value: object) -> str | None:
    return str(value).upper() if value is not None else None


def _expected_schema_errors(
    connection: Connection,
    *,
    allow_extra_tables: bool = True,
) -> list[str]:
    """Check the model's core structural contract without trying to diff SQL."""
    inspector = sa.inspect(connection)
    actual_tables = _table_names(inspector)
    errors: list[str] = []
    expected_table_names = {table.name for table in Base.metadata.sorted_tables}
    if not allow_extra_tables:
        for table_name in sorted(actual_tables - expected_table_names):
            errors.append(f"unexpected table {table_name}")

    for table in Base.metadata.sorted_tables:
        if table.name not in actual_tables:
            errors.append(f"missing table {table.name}")
            continue

        actual_columns = {column["name"]: column for column in inspector.get_columns(table.name)}
        expected_columns = {column.name: column for column in table.columns}
        for column_name in sorted(expected_columns.keys() - actual_columns.keys()):
            errors.append(f"missing column {table.name}.{column_name}")
        for column_name in sorted(actual_columns.keys() - expected_columns.keys()):
            errors.append(f"unexpected column {table.name}.{column_name}")
        for column_name in expected_columns.keys() & actual_columns.keys():
            expected = expected_columns[column_name]
            actual = actual_columns[column_name]
            if bool(actual["nullable"]) != bool(expected.nullable):
                errors.append(f"nullability mismatch for {table.name}.{column_name}")
            expected_type = expected.type
            actual_type = actual["type"]
            if isinstance(expected_type, sa.Enum):
                actual_enums = getattr(actual_type, "enums", None)
                if actual_enums is not None:
                    if list(actual_enums) != list(expected_type.enums):
                        errors.append(f"enum values mismatch for {table.name}.{column_name}")
                else:
                    try:
                        affinity_matches = (
                            actual_type._type_affinity is expected_type._type_affinity
                        )
                    except AttributeError:
                        affinity_matches = type(actual_type) is type(expected_type)
                    if not affinity_matches:
                        errors.append(f"type mismatch for {table.name}.{column_name}")
                    if getattr(actual_type, "length", None) != expected_type.length:
                        errors.append(f"length mismatch for {table.name}.{column_name}")
            elif isinstance(expected_type, sa.Boolean) and connection.dialect.name == "mysql":
                # MariaDB/MySQL reflect SQL BOOLEAN as TINYINT(1).
                if not (
                    isinstance(actual_type, sa.Integer)
                    and getattr(actual_type, "display_width", None) == 1
                ):
                    errors.append(f"type mismatch for {table.name}.{column_name}")
            elif (
                isinstance(expected_type, sa.JSON)
                and connection.dialect.name == "mysql"
                and getattr(connection.dialect, "is_mariadb", False)
            ):
                # MariaDB implements JSON as LONGTEXT plus JSON_VALID CHECK.
                if type(actual_type).__name__ != "LONGTEXT":
                    errors.append(f"type mismatch for {table.name}.{column_name}")
            else:
                try:
                    affinity_matches = actual_type._type_affinity is expected_type._type_affinity
                except AttributeError:
                    affinity_matches = type(actual_type) is type(expected_type)
                if not affinity_matches:
                    errors.append(f"type mismatch for {table.name}.{column_name}")
                if isinstance(expected_type, sa.String) and expected_type.length is not None:
                    if getattr(actual_type, "length", None) != expected_type.length:
                        errors.append(f"length mismatch for {table.name}.{column_name}")

        expected_pk = tuple(column.name for column in table.primary_key.columns)
        actual_pk = tuple(inspector.get_pk_constraint(table.name).get("constrained_columns") or ())
        if actual_pk != expected_pk:
            errors.append(f"primary key mismatch for {table.name}")

        expected_uniques = {
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }
        actual_uniques = {
            tuple(constraint.get("column_names") or ())
            for constraint in inspector.get_unique_constraints(table.name)
        }
        if actual_uniques != expected_uniques:
            errors.append(f"unique constraint mismatch for {table.name}")

        expected_foreign_keys = {
            (
                (foreign_key.parent.name,),
                foreign_key.column.table.name,
                (foreign_key.column.name,),
                _normalized_action(foreign_key.ondelete),
            )
            for foreign_key in table.foreign_keys
        }
        actual_foreign_keys = {
            (
                tuple(foreign_key.get("constrained_columns") or ()),
                foreign_key.get("referred_table"),
                tuple(foreign_key.get("referred_columns") or ()),
                _normalized_action((foreign_key.get("options") or {}).get("ondelete")),
            )
            for foreign_key in inspector.get_foreign_keys(table.name)
        }
        if actual_foreign_keys != expected_foreign_keys:
            errors.append(f"foreign key mismatch for {table.name}")

        expected_indexes = {
            (tuple(column.name for column in index.columns), bool(index.unique))
            for index in table.indexes
        }
        actual_indexes = {
            (tuple(index.get("column_names") or ()), bool(index.get("unique")))
            for index in inspector.get_indexes(table.name)
        }
        if not expected_indexes <= actual_indexes:
            errors.append(f"index mismatch for {table.name}")

    return errors


def _is_supported_pre_comment_schema(connection: Connection) -> bool:
    """Recognize the published pre-7A schema for safe legacy adoption.

    The comment-core and moderation Alembic upgrades own the structural
    differences. This deliberately checks that no unrelated table/column drift
    is being hidden by the relaxed comparison.
    """
    inspector = sa.inspect(connection)
    expected = {table.name for table in Base.metadata.sorted_tables}
    actual = _table_names(inspector)
    if actual != expected - {
        "comment_revisions",
        "comment_votes",
        "moderation_decisions",
        "comment_moderation_appeals",
        "post_author_relations",
        "object_relations",
        "plugin_storage_entries",
        "plugin_jobs",
    }:
        return False
    allowed_columns = {
        "comments": {
            "author_user_id",
            "confirmation_token_hash",
            "confirmation_expires_at",
            "confirmation_sent_at",
            "published_at",
            "edited_at",
            "parent_id",
        },
        "posts": {"comments_enabled", "guest_confirmation_required", "comment_moderation_mode"},
        "users": {"comment_trusted"},
    }
    errors = _expected_schema_errors(connection, allow_extra_tables=False)
    for error in errors:
        if error in {
            "missing table comment_revisions",
            "missing table comment_votes",
            "missing table moderation_decisions",
            "missing table comment_moderation_appeals",
            "missing table post_author_relations",
            "missing table object_relations",
            "missing table plugin_storage_entries",
            "missing table plugin_jobs",
        }:
            continue
        if error == "unexpected column comments.confirmation_token":
            continue
        if error.startswith("missing column "):
            _, qualified = error.split("missing column ", 1)
            table, column = qualified.split(".", 1)
            if column in allowed_columns.get(table, set()):
                continue
        if error in {
            "nullability mismatch for comments.author_email",
            "enum values mismatch for comments.status",
            "length mismatch for comments.status",
            "foreign key mismatch for comments",
            "index mismatch for comments",
        }:
            continue
        return False
    # These are intentionally removed by 7A and converted through Alembic.
    comment_columns = {column["name"] for column in inspector.get_columns("comments")}
    return {"confirmation_token", "confirmed_at", "approved_at", "quote_of_id"} <= comment_columns


async def _inspect_status(connection: AsyncConnection) -> SchemaStatus:
    config = _config()
    script = _scripts(config)
    heads = tuple(script.get_heads())
    if len(heads) != 1:
        return SchemaStatus(
            "multiple_heads", (), None, f"Expected one migration head, found {len(heads)}."
        )
    head = heads[0]

    def inspect(sync_connection: Connection) -> SchemaStatus:
        inspector = sa.inspect(sync_connection)
        tables = _table_names(inspector)
        has_version = "alembic_version" in tables
        app_tables = tables - {"alembic_version"}
        if not app_tables and not has_version:
            return SchemaStatus("empty", (), head, "Database has no tables or Alembic version.")
        if not has_version:
            errors = _expected_schema_errors(sync_connection, allow_extra_tables=False)
            if errors:
                if _is_supported_pre_comment_schema(sync_connection):
                    return SchemaStatus(
                        "legacy",
                        (),
                        head,
                        "Matches the supported pre-7A comment schema; Alembic will upgrade it.",
                    )
                detail = "; ".join(errors[:8])
                return SchemaStatus("unknown_legacy", (), head, detail)
            return SchemaStatus("legacy", (), head, "Matches the supported pre-Alembic schema.")

        current = tuple(MigrationContext.configure(sync_connection).get_current_heads())
        if not current:
            if not app_tables:
                return SchemaStatus(
                    "empty", (), head, "Database has no application tables or revision."
                )
            return SchemaStatus(
                "invalid_version", (), head, "Alembic version table has no revision."
            )
        if len(current) != 1:
            return SchemaStatus(
                "multiple_heads", current, head, "Database has multiple current revisions."
            )
        current_revision = current[0]
        try:
            known_revision = script.get_revision(current_revision)
        except CommandError:
            known_revision = None
        if known_revision is None:
            return SchemaStatus(
                "unknown_revision",
                current,
                head,
                "Database revision is not present in this ArborPress release.",
            )
        if current_revision == head:
            errors = _expected_schema_errors(sync_connection)
            if errors:
                return SchemaStatus("schema_mismatch", current, head, "; ".join(errors[:8]))
            return SchemaStatus("current", current, head, "Database schema is at the current head.")

        known_revisions = {revision.revision for revision in script.walk_revisions("base", head)}
        if current_revision not in known_revisions:
            return SchemaStatus(
                "history_mismatch",
                current,
                head,
                "Database revision is not an ancestor of the current migration head.",
            )
        return SchemaStatus("behind", current, head, "Database requires an Alembic upgrade.")

    return await connection.run_sync(inspect)


async def schema_status(engine: AsyncEngine | None = None) -> SchemaStatus:
    """Read-only classification of the database schema."""
    async_engine = engine or get_engine()
    async with async_engine.connect() as connection:
        return await _inspect_status(connection)


async def _backfill_legacy_transports(connection: AsyncConnection) -> None:
    result = await connection.execute(
        sa.text(
            "SELECT id, transport FROM webauthn_credentials "
            "WHERE transports IS NULL AND transport IS NOT NULL"
        )
    )
    for credential_id, transport in result.fetchall():
        value = str(transport).strip()
        if value:
            await connection.execute(
                sa.text("UPDATE webauthn_credentials SET transports = :transports WHERE id = :id"),
                {"transports": json.dumps([value]), "id": credential_id},
            )


async def _adopt_legacy(connection: AsyncConnection, status: SchemaStatus) -> None:
    if status.state != "legacy":
        raise MigrationError(f"Legacy adoption refused: {status.detail}")
    log.info("Adopting validated pre-Alembic database as revision %s", BASELINE_REVISION)
    await _backfill_legacy_transports(connection)
    await _command(connection, command.stamp, BASELINE_REVISION)


async def adopt_legacy_database(engine: AsyncEngine | None = None) -> None:
    """Validate a supported pre-Alembic schema, stamp its baseline, then upgrade."""
    async_engine = engine or get_engine()
    async with async_engine.connect() as connection:
        async with _migration_lock(connection):
            status = await _inspect_status(connection)
            if status.state != "legacy":
                raise MigrationError(f"Legacy adoption refused: {status.detail}")
            await _adopt_legacy(connection, status)
            await _command(connection, command.upgrade, "head")
    final_status = await schema_status(async_engine)
    if final_status.state != "current":
        raise MigrationError(
            f"Adopted database did not reach the current head: {final_status.detail}"
        )


async def upgrade_database(engine: AsyncEngine | None = None) -> SchemaStatus:
    """Adopt a verified legacy schema if necessary, then upgrade to head."""
    async_engine = engine or get_engine()
    log.info("Starting ArborPress schema upgrade on backend %s", async_engine.dialect.name)
    async with async_engine.connect() as connection:
        async with _migration_lock(connection):
            status = await _inspect_status(connection)
            log.info("Migration source state: %s (%s)", status.state, status.detail)
            if status.state == "legacy":
                await _adopt_legacy(connection, status)
            elif status.state not in {"empty", "behind", "current"}:
                raise MigrationError(
                    f"Cannot upgrade database in state {status.state}: {status.detail}"
                )
            if status.state != "current":
                await _command(connection, command.upgrade, "head")
    final_status = await schema_status(async_engine)
    if final_status.state != "current":
        raise MigrationError(f"Upgrade did not reach the current head: {final_status.detail}")
    log.info("Database schema is current at revision %s", final_status.head_revision)
    return final_status


async def downgrade_database(
    target: str,
    engine: AsyncEngine | None = None,
) -> None:
    """Run an explicitly requested downgrade; ArborPress never calls this automatically."""
    async_engine = engine or get_engine()
    async with async_engine.connect() as connection:
        async with _migration_lock(connection):
            status = await _inspect_status(connection)
            if status.state not in {"current", "behind"}:
                raise MigrationError(
                    f"Cannot downgrade database in state {status.state}: {status.detail}"
                )
            await _command(connection, command.downgrade, target)


def migration_history() -> list[tuple[str, str, str | None]]:
    """Return packaged revisions newest-first for the ArborPress CLI."""
    history = []
    for revision in _scripts().walk_revisions():
        down_revision = revision.down_revision
        if isinstance(down_revision, (list, tuple)):
            down_revision = ", ".join(down_revision)
        history.append((revision.revision, revision.doc or "", down_revision))
    return history
