# Third-party plugin runtime (Phase 8A)

## Boundary and current scope

ArborPress core and built-in integrations remain ordinary ArborPress modules in
the main process. A discovered third-party plugin is metadata until an
administrator enables it. Each enabled third-party plugin runs in its own
child process. Threads, Quart blueprints, in-process hooks and plugin-provided
CLI commands are not third-party extension APIs.

Phase 8A establishes discovery, lifecycle RPC, an SDK context, and a
per-plugin-interpreter foundation. Capability grants, Storage/Data APIs,
events, core-scheduled jobs, declarative admin UI, package installation and
crash-loop policy are later work. In particular, `PluginContext.rpc.call`
currently reports that core RPC methods are unavailable; no ArborPress data
API is exposed yet. A plugin may request known capabilities in its manifest,
but requests are not grants and the runtime currently grants none.

Process separation is always active; it is not a complete sandbox. Without an
OS sandbox, Python code running under the ArborPress OS account can still
access files, environment-independent OS resources, or networks that account
can reach. ArborPress passes a deliberately small environment and no database,
mail, session, WebAuthn, instance-master, or backup credentials, but same-user
filesystem/network isolation is not guaranteed. Linux-specific defense in
depth is planned separately.

## Layout

For the active prefix, the canonical locations are:

```text
instance/plugins/<plugin-id>/                 plugin package and plugin.toml
instance/data/plugins/<plugin-id>/            persistent plugin-owned data
instance/var/run/plugins/<plugin-id>/         runtime coordination files
instance/var/cache/plugins/<plugin-id>/        disposable plugin cache
instance/var/plugins/<plugin-id>/venv/         optional isolated interpreter
instance/data/plugin-state.toml                locally enabled plugin IDs
```

All paths derive from `ArborPressPaths`; discovery does not use the process CWD.
Operator-configured plugin roots remain supported and are anchored by the
existing settings loader. Colliding IDs are marked invalid instead of
shadowing one another. A plugin directory's name must match its manifest ID.
Built-in ArborPress modules are not discovered as third-party packages and
cannot be replaced by them.

## `plugin.toml`

The manifest is TOML, version 1, with unknown fields rejected:

```toml
manifest_version = 1
id = "sample-plugin"
name = "Sample Plugin"
version = "1.0.0"
author = "Example Author"
license = "MIT"
description = "A lifecycle-only example."
requires_arborpress = ">=0.1.0,<1.0.0"
python = ">=3.14,<3.15"
entrypoint = "sample_plugin.worker:plugin"
requested_capabilities = ["importer"]
required_capabilities = []
events = []
tasks = []
```

`manifest_version`, `id`, `name`, `version`, `author`, `license`,
`requires_arborpress`, and `entrypoint` are required. `description`, `python`,
requested/required capabilities, events, tasks, and a reserved declarative
`admin_ui` descriptor are optional. IDs use lowercase ASCII letters/digits
with single hyphen separators. Versions use PEP 440 parsing and compatibility
fields use version specifiers. Required capabilities must also be requested;
unknown names are rejected. An invalid or incompatible package remains
visible in diagnostics but cannot start. The supported file is `plugin.toml`;
old `manifest.toml` directories are shown as legacy-invalid and never imported.

The entrypoint is a Python `module:object` reference. Its imported module must
resolve inside that plugin's package root. The object may be an instance or a
class with optional `initialize(context)`, `ping()`, and `shutdown()` methods;
sync and async lifecycle methods are accepted. It is imported only inside the
plugin process. It is not a shell command or ArborPress in-process hook.

## Private lifecycle RPC v1

Core creates a POSIX Unix `socketpair`; there is no TCP listener, HTTP server,
public port, or filesystem socket. Only the child endpoint is inherited.
Frames contain a 4-byte unsigned network-order length and a UTF-8 JSON object,
limited to 1 MiB. Pickle and arbitrary Python serialization are not used.

Requests have `protocol`, `id`, `method`, and object-valued `params`; responses
have the matching protocol/id and either `result` or a structured `error`.
The initial `runtime.initialize` request carries plugin identity, ArborPress
and runtime versions, and an empty granted-capability list. The child host
returns `ready=true` and matching ID/version after the plugin's initialize
callback succeeds; only then does the Core mark it `running`.
`runtime.ping` and `runtime.shutdown` are the only lifecycle methods currently
dispatched. Unknown methods fail closed. RPC error responses do not include
Python tracebacks.

Default startup timeout is 10 seconds, request timeout 30 seconds, and graceful
shutdown timeout 3 seconds, followed by process-group terminate/kill fallback.
Separate stdout/stderr pipes are drained and output is bounded in ArborPress
logs. A child exit is tracked and marked failed unless shutdown was requested.
An enabled plugin failing to start does not prevent normal Core startup.
Automatic restart/disable policy belongs to Phase 8C.

The child is started without `shell=True`, with an explicit plugin working
directory, closed unrelated file descriptors, a new process session, and a
minimal environment. `PATH`, locale, plugin ID/protocol and the installed
ArborPress package/plugin roots are the only passed environment values.
This is credential hygiene, not an OS sandbox.

## Interpreter isolation and controls

An empty plugin venv can be created without network access using:

```text
arborpress plugins runtime create sample-plugin
```

The runtime uses `instance/var/plugins/<id>/venv/bin/python` when present;
otherwise it uses the current ArborPress Python interpreter. No dependencies
are installed or resolved by Phase 8A. A plugin venv uses the ArborPress SDK
bootstrap from the installed ArborPress release through an explicit package
path. Installing plugin dependencies is not yet a supported installer flow.

Available metadata-only diagnostics are `arborpress plugins list [--json]`,
`inspect <id> [--json]`, `check <id>`, and `validate <directory>`. CLI enable and
disable update local state for the next server startup. The existing protected
Admin action starts/stops the process in the current server process after
step-up and CSRF checks. New plugins default to disabled. There are no plugin
routes, Quart blueprints, plugin-defined CLI commands, arbitrary Admin JS, or
automatic downloads.
