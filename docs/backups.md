# Local backup sets

Phase 6A adds local backup creation and read-only verification. A backup is a
directory containing separately described components, not one unbounded
archive:

```text
PREFIX/instance/backups/YYYYMMDD-HHMMSS[-NN]/
├── manifest.toml
├── checksums.sha256
├── database/database-<id>.ndjson.bz2
├── config/config-<id>.tar.bz2
├── data/data-<id>.tar.bz2
├── themes/themes-<id>.tar.bz2
├── plugins/plugins-<id>.tar.bz2
└── media/media-<id>-0001.tar.bz2
```

The manifest is format version 1. It records the UTC backup ID and exact
ISO-8601 UTC creation time, ArborPress and Python versions, database engine
and Alembic heads when included, consistency mode, compression backend and
profile, encryption state (`none`), component-relative paths, sizes, SHA-256
digests, archive format, member inventory, media segment numbers, omitted
sensitive paths, warnings, and the final `complete` status. It contains no
connection URL, password, token, master secret, or key. `checksums.sha256` is
also emitted in the conventional `SHA256  relative/path` format.

Creation writes to a private `.incomplete-*` directory, verifies the finished
components, manifest, and checksums, then renames the set into its final name.
If another set already uses the same UTC second, deterministic `-01`, `-02`, …
suffixes are chosen; existing sets are never replaced. An instance-scoped
advisory lock lives at `instance/var/run/backup.lock` and records the owner PID
and start time for diagnostics. A crashed process releases the OS lock; stale
text in the lock file does not prevent a later run.

## Components and consistency

The available components are `database`, `config`, `data`, `themes`,
`plugins`, and `media`. `data` excludes the configured SQLite database and its
WAL/SHM/journal sidecars when they are located under the instance data root.
The database is exported only through the database component. Backups,
`instance/var/cache`, `var/log`, `var/run`, and `var/tmp` are not recursively
archived. Theme revision data under `instance/data/theme-revisions/` remains in
the ordinary `data` component, while runtime themes and plugins are their own
components.

Database rows are a deterministic, streaming NDJSON logical export with
explicit typed values (format version 1), ordered by ArborPress table metadata
and primary keys. It exports registered ArborPress application tables only;
the Alembic revision is captured as metadata and `alembic_version` is not
copied as user data. SQLite uses its Backup API to create a temporary
consistent snapshot. PostgreSQL uses a read-only repeatable-read transaction;
MariaDB/MySQL uses a read-only repeatable-read consistent snapshot. If the
backend cannot establish its requested snapshot, creation fails.

File components are PAX TAR archives built through Python's `tarfile` API.
Special files are rejected. Relative symlinks are retained only when their
resolved target stays within the source component root; absolute and escaping
links fail the component. Individual regular files are staged and checked
before and after reading, with up to three attempts. This guarantees stable
per-file reads, **not** a globally atomic filesystem snapshot; the distinction
is recorded in the manifest.

Media uses independent valid TAR archives, each planned against a default
2 GiB uncompressed payload limit. A single file larger than the limit gets a
segment of its own. The manifest records each segment and its member paths,
uncompressed payload size, compressed size, and SHA-256 digest.

## Compression

The default is Python standard-library BZip2. Profiles map to compression
levels 1 (`fast`), 6 (`medium`, default), and 9 (`strong`); `custom` accepts a
level from 1 to 9. BZip2 is not parallelized. Optional BZip3 support uses the
Python `bzip3` binding and its thread API; it is installed only with the
`backup-bz3` Poetry extra. BZip3 offers `auto` or an explicit thread count
from 1 to 64. Its Fast/Medium/Strong profiles select configured block sizes; the custom
level selects a block size, not a BZip2 level. If the optional binding is
absent, a BZip3 request fails clearly. No external compression or archive
executable is used as a fallback.

## Sensitive configuration

These sets are unencrypted in Phase 6A and may contain sensitive database and
user data. The CLI prints a warning before creation. To avoid silently
publishing credentials, configuration files in the bootstrap `config`
component are omitted in full; their relative paths are listed under
`omitted_sensitive`, and the manifest warns that the set is not a complete
configuration restore. Other components remain unencrypted and should be
stored with appropriate local access controls. Encryption and full-secret
backup are later work; this format does not claim either.

## Commands

Run each command with the intended explicit instance prefix (or the configured
`ARBORPRESS_PREFIX`):

```sh
arborpress --prefix ~/ArborPress backup create
arborpress --prefix ~/ArborPress backup create --component database --component media
arborpress --prefix ~/ArborPress backup create --compression bz2 --profile strong
arborpress --prefix ~/ArborPress backup create --compression bz3 --threads auto
arborpress --prefix ~/ArborPress backup list
arborpress --prefix ~/ArborPress backup inspect 20261018-120000
arborpress --prefix ~/ArborPress backup verify 20261018-120000
```

`backup list` shows complete sets whose manifest is valid. `inspect` reports
metadata and a verification result; `verify` checks the manifest, exact set
inventory, checksums, compressed stream, PAX TAR members, media ordering, and
database NDJSON records without extracting anything. JSON output is available
with `--json` for read-only diagnostics.

Phase 6A does not implement restore, encryption, retention/pruning, remote
storage, scheduling, incremental backups, or plugin backup hooks. It never
starts `tar`, `bzip2`, `pg_dump`, `mysqldump`, `sqlite3`, or another external
backup utility; all export, compression, checksumming, and verification use
Python/library APIs.
