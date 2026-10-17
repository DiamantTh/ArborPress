# ArborPress Prefix and Instance Paths

ArborPress identifies one installation instance by one explicit prefix. A
second independent instance uses a second prefix; the process working
directory is not an instance identity and is never searched for a default
configuration file.

```text
PREFIX/
├── arborpress                 reserved root launcher path
├── app/                       replaceable program area
│   ├── bin/
│   ├── runtime/
│   ├── assets/
│   ├── releases/
│   └── current                 reserved release pointer
└── instance/                  persistent state for this prefix
    ├── config/
    │   ├── config.toml
    │   ├── install.token
    │   └── .installed
    ├── data/
    ├── media/
    ├── themes/
    ├── plugins/
    ├── backups/                reserved; no backup engine is provided here
    └── var/
        ├── cache/
        ├── log/
        ├── run/
        └── tmp/
```

The source checkout remains in its existing repository layout (`arborpress/`,
`tests/`, and other source directories); it is not physically reorganized into
`app/` and `instance/`. The app/release locations are modeled for the eventual
installed-program layout, but this phase does not implement a launcher,
release downloads, switching, or rollback.

## Choosing a prefix

The normal recommended installation is under the executing user's home:

```text
~/arborpress/
├── arborpress
├── app/
└── instance/
```

Here `~` means that user's home directory. ArborPress is not tied to a
system-wide location such as `/srv`, `/opt`, or `/var/lib`; an operator may
still explicitly choose another suitable prefix. The current working directory
never selects the instance.

The prefix source priority is:

1. global CLI `--prefix`;
2. `ARBORPRESS_PREFIX`;
3. an explicitly initialized in-process runtime context.

Without one of these sources, path access fails with an actionable error; it
does not silently use the current working directory. `~` is expanded, a
relative explicit prefix is resolved against the working directory at the
moment it is supplied, and the stored prefix is absolute and canonical (an
existing symlink is resolved once). Later `chdir()` calls do not change it.

```sh
poetry run arborpress --prefix ~/arborpress-a paths
ARBORPRESS_PREFIX=~/arborpress-a poetry run arborpress paths --json
```

The CLI prefix wins if both `--prefix` and `ARBORPRESS_PREFIX` are set. The
read-only `paths` command prints the resolved layout and does not start the web
application or connect to the database.

## Configuration and local paths

The default bootstrap configuration is
`PREFIX/instance/config/config.toml`. A foreign `config.toml` in the current
working directory is ignored. `--config PATH` remains an explicit file or
configuration-directory override; it does not change the selected prefix or
move install markers, media, extensions, or other instance data. Relative
include paths inside TOML remain relative to the including config file.

Relative SQLite database filenames are resolved under
`PREFIX/instance/data/`. An explicit absolute SQLite filename is preserved;
PostgreSQL and MariaDB connection URLs are not path-rewritten.

Local media defaults to `PREFIX/instance/media/`. An explicitly configured
relative media path is relative to `instance/`, while an absolute override is
preserved. Packaged built-in themes remain part of the ArborPress package;
operator themes are loaded from `instance/themes/`. Third-party plugins in
`instance/plugins/` are always considered. Additional configured plugin roots
are loaded first, and relative extra roots are anchored to the active config
file's directory; the canonical instance plugin root has precedence for ID
collisions.

The file cache defaults to `instance/var/cache/`. A relative cache override is
anchored within that cache root; an absolute override is preserved. Relative
application and audit log filenames are anchored under `instance/var/log/`;
absolute log paths remain absolute. New instance directories are created with
owner-only permissions where supported, and existing directory permissions
are not rewritten.

`instance/backups/`, `instance/var/run/`, and `instance/var/tmp/` are reserved
locations. This phase does not add a backup system, PID/socket manager, or
general-purpose temporary-file framework.

## Development example

Use a disposable explicit prefix instead of writing instance state into the
source tree:

```sh
PREFIX=/tmp/arborpress-dev
mkdir -p "$PREFIX/instance/config"
cp config/config.example.toml "$PREFIX/instance/config/config.toml"
poetry run arborpress --prefix "$PREFIX" paths
poetry run arborpress --prefix "$PREFIX" db upgrade
poetry run arborpress --prefix "$PREFIX" serve --dev
```

The `Makefile` uses `/tmp/arborpress-dev` by default for its `run` and
`db-upgrade` targets; set `PREFIX=/path/to/instance` to select another one.

## Runtime and multiple instances

The CLI callback selects and initializes the prefix before commands load
configuration or open the database. The Quart application factory requires
that initialized context and ensures the persistent layout before setting up
logging, themes, or other runtime services. An ASGI server started directly
must receive `ARBORPRESS_PREFIX`; without a CLI option, environment variable,
or explicitly initialized embedding context, startup fails instead of
guessing from its current working directory.

The ordinary web startup is schema-read-only. For an installed instance it
checks the configured database against the packaged Alembic head and refuses
to serve if an upgrade is needed. It does not migrate automatically. Apply
schema changes explicitly with the matching prefix, then start the web
process:

```sh
arborpress --prefix ~/arborpress-a db upgrade
arborpress --prefix ~/arborpress-a db check
arborpress --prefix ~/arborpress-a serve --workers 2
```

Each process owns one effective prefix. Multiple sites therefore use separate
prefixes and configurations rather than a hidden global site directory. The
database URL is loaded from that prefix's bootstrap configuration (or an
explicit `--config` override), while SQLite relative filenames, media,
themes, plugins, cache, and relative logs remain scoped to the selected
instance. A custom config file does not relocate those paths.

## Container runtime

The Compose examples run as the non-root `arborpress` user with home
`/home/arborpress` and set the absolute container prefix to
`/home/arborpress` (the container equivalent of `~`, since this runtime user's
home is itself the selected prefix).
The absolute form is deliberate: environment variables and exec-form
entrypoints do not promise shell tilde expansion. The only application-state
volume is mounted at `/home/arborpress/instance`; a host bind-mount
may store that volume anywhere the operator chooses and does not define the
container prefix. In the image, `app/bin/arborpress` is the CLI entry and
`app/runtime/` exposes the image-installed virtual environment and CPython;
these paths are image-owned symlinks to runtime layers and are replaced with
the image, not persisted as state. The entrypoint passes the same explicit
prefix to one `db upgrade` invocation before starting Hypercorn. A failed
migration exits before the web server starts. Container logging remains on
stdout/stderr by default; enabling relative file logging places files under
`instance/var/log/`.

The runtime image contains the installed ArborPress wheel and its runtime
dependencies. Poetry is used only in the image build stage, and Node is not a
runtime requirement. The Dockerfile working directory is `/` and does not
select an instance. A container config file, when used instead of environment
settings, belongs at
`/home/arborpress/instance/config/config.toml`; the CLI's explicit
`--config` option overrides only the file for that command and does not
relocate the instance.

`app/releases/<version>/` and `app/current` are reserved for a future release
layout. No release download, pointer switching, update, or rollback behavior
is implemented. `instance/backups/` is the reserved local backup root; no
backup creation or restore engine is implemented.

Existing source-checkout directories such as `config/`, `media/`, or
`content/themes/` are not automatically copied or moved. Operators must place
state in the selected instance or configure explicit overrides.
