# Local backup sets

Phase 6A adds local backup creation and read-only verification; Phase 6B adds
verified restore planning and offline application. A backup is a
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

Manifest format version 1 remains readable for existing sets; new sets use
format version 2. The manifest records the UTC backup ID and exact
ISO-8601 UTC creation time, ArborPress and Python versions, database engine
and Alembic heads when included, consistency mode, compression backend and
profile, encryption state, component-relative paths, sizes, SHA-256
digests, archive format, member inventory, media segment numbers, omitted
sensitive paths, `secrets_included`, warnings, and the final `complete`
status. It contains no connection URL, password, token, master secret, or key.
`checksums.sha256` uses the conventional `SHA256  relative/path` format and
covers final component bytes (ciphertext for encrypted sets).

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

## Encryption and key handling

Each compressed component file is encrypted independently; each media segment
therefore has its own envelope and nonce. Encrypted names end in `.apenc`,
while the manifest remains readable. Format 2 declares AES-256-GCM envelope
version 1 and records the key source, a random 16-byte KDF salt, Scrypt
parameters (for passphrases), and the fixed `manifest.auth` path. The
`manifest.auth` sidecar is an HMAC-SHA-256 over the exact final manifest bytes.
Retention state is stored separately and never modifies the authenticated
manifest.

The binary component envelope is, in order: 8-byte magic (hex
`41 50 45 4e 43 0d 0a 1a`),
1-byte envelope version, 1-byte algorithm ID (`1` = AES-256-GCM), 12-byte
random nonce, ciphertext of the compressed component, then the 16-byte GCM
authentication tag. Associated data binds the backup ID, manifest-relative
component path, envelope version, and manifest format version. HKDF-SHA-256
derives distinct per-component and manifest-authentication keys from the
backup master material. Passphrases use Scrypt (N=32768, r=8, p=1, 16-byte
random salt, 32-byte output); keyfiles contain independent random 256-bit
material. The instance master secret is never used as a backup key.

Generate an automation keyfile outside the instance/config tree:

```sh
arborpress backup key generate /secure/location/arborpress-backup.apkey
arborpress backup create --encrypt --keyfile /secure/location/arborpress-backup.apkey
```

On POSIX, keyfiles are created mode 0600, must be regular non-symlink files,
and are rejected if group/other permission bits are set. The generated format
is the ASCII bytes `APKEY01` plus a line feed, followed by Base64 of exactly
32 bytes and a final line feed.
The CLI refuses to overwrite an existing file unless `--force` is given.
Alternatively, `backup create --encrypt` prompts twice for a passphrase using
`getpass`; passphrases are not accepted as command-line values or saved in
configuration. Keep the key separately from the backup and instance. Losing
it makes encrypted data unrecoverable. ArborPress never derives a backup key
from the instance master secret.

Use `--include-secrets` with `--encrypt` to include the complete config tree,
including secret-bearing bootstrap files. `--include-secrets` without
encryption is rejected. Without that option, all files in the bootstrap
`config` component are omitted (both encrypted and unencrypted); the manifest
reports only `secrets_included = false` and omitted paths, never secret
values. A keyfile inside the included config tree is rejected. Even without
bootstrap secrets, an unencrypted database backup contains sensitive
application and user data and must be protected.

Verification has two explicit levels. Without a key, ArborPress performs
`structural-only` verification: it parses the manifest and envelope headers,
checks ciphertext checksums and set inventory, but cannot authenticate or
inspect compressed plaintext. With a key, `backup verify` checks the manifest
HMAC, every AEAD tag, decompression, and TAR/DB stream structure
(`full-cryptographic`). Encrypted restore always requires the key and repeats
full verification before staging or applying. Authentication failures use a
generic error and do not expose plaintext.

## Commands

Run each command with the intended explicit instance prefix (or the configured
`ARBORPRESS_PREFIX`):

```sh
arborpress --prefix ~/ArborPress backup create
arborpress --prefix ~/ArborPress backup create --component database --component media
arborpress --prefix ~/ArborPress backup create --compression bz2 --profile strong
arborpress --prefix ~/ArborPress backup create --compression bz3 --threads auto
arborpress --prefix ~/ArborPress backup create --encrypt
arborpress --prefix ~/ArborPress backup create --encrypt --include-secrets --keyfile /secure/location/arborpress-backup.apkey
arborpress --prefix ~/ArborPress backup list
arborpress --prefix ~/ArborPress backup inspect 20261018-120000
arborpress --prefix ~/ArborPress backup verify 20261018-120000
arborpress --prefix ~/ArborPress backup verify 20261018-120000 --keyfile /secure/location/arborpress-backup.apkey
arborpress --prefix ~/ArborPress backup pin 20261018-120000
arborpress --prefix ~/ArborPress backup unpin 20261018-120000
arborpress --prefix ~/ArborPress backup prune --keep-last 10 --keep-days 30
arborpress --prefix ~/ArborPress backup prune --keep-last 10 --apply
arborpress --prefix ~/ArborPress backup cleanup-incomplete
arborpress --prefix ~/ArborPress restore plan 20261018-120000
arborpress --prefix ~/ArborPress restore plan 20261018-120000 --component media --json
arborpress --prefix ~/ArborPress restore plan 20261018-120000 --keyfile /secure/location/arborpress-backup.apkey
arborpress --prefix ~/ArborPress restore apply 20261018-120000 --all --offline --keyfile /secure/location/arborpress-backup.apkey
arborpress --prefix ~/ArborPress restore apply 20261018-120000 --component media --offline
arborpress --prefix ~/ArborPress restore apply 20261018-120000 --all --offline --dry-run
arborpress --prefix ~/ArborPress restore recover --offline
```

`backup list` shows complete sets whose manifest is valid. `inspect` reports
metadata and the verification level. `verify` checks the manifest, exact set
inventory, checksums, compressed stream, PAX TAR members, media ordering, and
database NDJSON records without extracting anything when a key is supplied;
otherwise encrypted sets are reported as `structural-only`. JSON output is
available with `--json` for read-only diagnostics.

## Restore safety

`restore plan` is read-only: it verifies the complete set, checks its format,
database backend and exact Alembic revision compatibility, reports selected
component targets and estimated staging space, and identifies partial config
coverage. It does not apply anything. `restore apply --dry-run` additionally
extracts and validates the selected contents in temporary staging, then removes
that staging without changing live files or database rows. Apply always repeats
full verification; there is no checksum bypass.

Apply requires both an explicit component selection (or `--all`) and
`--offline`. Stop every ArborPress web worker first. ArborPress cannot quiesce
arbitrary ASGI workers itself. While applying, an instance maintenance marker
makes any still-running worker return `503` with `Cache-Control: no-store`, and
a newly starting worker refuses startup. Backup and restore operations share
the instance lock at `instance/var/run/backup.lock`.

Selected file components are extracted by a checked Python TAR reader into
private staging under `instance/var/tmp/` (or a same-filesystem sibling under
`instance/` when needed). Absolute paths, traversal, special files, escaping
links, hardlinks, and conflicting members are rejected. Components are swapped
as roots with rollback siblings and a journal under `instance/var/run/`.
Multi-root filesystems do not provide a single transaction: ArborPress attempts
rollback on failure and leaves maintenance enabled if recovery is required.
Run `restore recover --offline` only while web workers remain stopped. The
recovery path is rollback-first before a server-database commit; after a
server-database commit, manual review may be required. Restore reports are
stored in `instance/data/restore-history/`.

Components can be restored selectively. Unselected roots are not removed. A
selected directory root (`config`, `data`, `themes`, `plugins`, or `media`) is
replaced as a whole. `data` does not include `var/` or the separately managed
SQLite database. When a database file is inside `data` and the database
component is not selected, its live file and sidecars are preserved. Media
segments are reconstructed and verified in staging before the live media root
is swapped.

Sets omit all bootstrap config files unless encrypted creation explicitly used
`--include-secrets`. When
`restore plan` reports partial configuration, apply preserves the current
local config tree and overlays only files present in the backup. This is not a
complete disaster-recovery configuration restore. No secrets are inferred or
reconstructed.

Database restores use the Phase 6A typed NDJSON format and known ArborPress
tables only. The target and backup must use the same backend and exactly the
same known Alembic revision. An empty SQLite target may be migrated in staging
to this release's Alembic head before rows are imported; no live schema
migration is run as a hidden restore side effect. SQLite is built and checked
in a replacement file before it is swapped into place. PostgreSQL DML uses one
transaction; MariaDB/MySQL must use InnoDB tables, with auto-increment DDL
handled separately after the row transaction. Cross-backend restore is not
supported. The journal records server-database commit intent before the
transaction commits. If the connection fails at that boundary and the commit
outcome is uncertain, ArborPress keeps maintenance enabled and refuses an
automatic filesystem rollback; inspect the restore report and database while
the service remains offline. `--safety-backup` optionally creates a complete
backup of current state before applying; it is opt-in and uses the same lock
without reacquiring it.

Retention is local and explicit. `backup pin` protects a set; `unpin` removes
that protection. `backup prune --keep-last N` and/or `--keep-days D` first
print a dry-run plan; deletion requires `--apply` and confirmation (or
`--yes`). Keep rules combine as a union, pinned sets are always kept, and the
newest valid complete set is protected. Unknown directories, symlinks, and
`.incomplete-*` directories are not ordinary prune candidates.
`backup cleanup-incomplete` is a separate age-gated operation (minimum 24
hours) for ArborPress-owned incomplete staging sets; it also defaults to a
read-only listing. Retention sidecars live below
`instance/var/backup-local-state/`, outside authenticated backup manifests.

The supported database restore path remains same-backend and exact known
Alembic revision. SQLite replacement is staged and integrity-checked;
PostgreSQL and MariaDB/MySQL use their Phase 6B transactional import paths.
Cross-backend restore is not supported. Snapshot guarantees remain backend
specific and file components are stable per-file reads rather than a globally
atomic filesystem snapshot. Restore requires offline operation; ArborPress
does not promise a global database-plus-filesystem transaction.

The system uses Python and library APIs only. It never starts `tar`, `bzip2`,
`pg_dump`, `mysqldump`, `sqlite3`, or another external backup utility; export,
compression, encryption, checksumming, verification, and restoration use
Python/library APIs. Remote storage, schedules, incrementals, and plugin
backup hooks are not implemented.
