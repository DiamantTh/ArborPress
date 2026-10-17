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
poetry run arborpress --prefix /srv/arborpress-a paths
ARBORPRESS_PREFIX=/srv/arborpress-a poetry run arborpress paths --json
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
