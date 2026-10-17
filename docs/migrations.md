# Database migrations

Alembic is ArborPress's only regular database schema migration system. The
revision scripts in `arborpress/migrations/versions/` are packaged with the
application and are run through Alembic's Python API using ArborPress's existing
`DatabaseSettings`. `alembic.ini` contains no DSN or credentials. A system
Alembic executable and Poetry are not runtime requirements.

## Operator commands

Run `arborpress db upgrade` before starting the web process. It upgrades an
empty database to the packaged head and upgrades a database with a recognized
revision. For an unversioned database, it first checks compatibility with the
supported pre-Alembic ArborPress schema; only that exact structural contract is
adopted. The explicit `arborpress db adopt-legacy` command performs the same
validation and stamps the baseline without attempting any unrecognized schema
repair. Unknown or incomplete schemas are left unchanged and rejected.

`arborpress db current` reports the installed revision and status;
`arborpress db history` lists revisions in this distribution; and
`arborpress db check` is read-only and exits successfully only when the schema
is compatible and current. `arborpress db downgrade <revision>` is an explicit
administrator/developer action, requires confirmation, and is never run
automatically. Downgrades may lose data; take and verify a database backup
before migrations that may be destructive or before a downgrade.

The normal web startup does not change the schema. It checks that the database
is at the revision head understood by the running ArborPress release and exits
with an instruction to run `arborpress db upgrade` otherwise. The container
entrypoint performs that upgrade exactly once before it starts Hypercorn
workers. If an upgrade fails, the entrypoint does not start the web server.

PostgreSQL and MariaDB/MySQL are supported production backends. SQLite is for
development, tests, and demo use. Migration attempts are serialized by a
database-owned advisory lock on PostgreSQL, a named lock on MariaDB/MySQL, or an
exclusive write lock on SQLite. Lock acquisition has a bounded timeout. Some
MySQL/MariaDB DDL implicitly commits, so a failed migration may require an
operator to inspect the database before retrying; ArborPress does not claim
that all migration failures are automatically reversible.

## Developer workflow

1. Change the SQLAlchemy model.
2. Generate a candidate revision with
   `poetry run alembic -c arborpress/migrations/alembic.ini revision --autogenerate -m "describe change"`.
3. Manually review the generated operations, revision identifier, dependencies,
   constraints, indexes, and `downgrade()` implementation. Autogenerate is a
   proposal, never an unquestioned source of truth.
4. Test the revision on an empty SQLite database and on supported PostgreSQL
   and MariaDB versions. Also consider existing-data and downgrade behavior.
5. Commit the model and its reviewed Alembic revision together.

Do not rely on `Base.metadata.create_all()` or ad hoc `ALTER TABLE` statements
for installs or upgrades. New schema changes belong in a reviewed Alembic
revision. The current baseline, `0001_pre_alembic_baseline`, records the
pre-Phase-2 model schema without invoking `metadata.create_all()` from inside
the revision.
