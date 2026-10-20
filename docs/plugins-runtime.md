# Third-party plugin runtime (Phases 8A–8C)

## Boundary and current scope

ArborPress core and built-in integrations remain ordinary ArborPress modules in
the main process. A discovered third-party plugin is metadata until an
administrator enables it. Each enabled third-party plugin runs in its own
child process. Threads, Quart blueprints, in-process hooks and plugin-provided
CLI commands are not third-party extension APIs.

Phase 8A establishes discovery, lifecycle RPC, an SDK context, and a
per-plugin-interpreter foundation. Phase 8B adds local capability grants,
Core-mediated KV storage and safe read-only DTOs, best-effort events,
Core-scheduled jobs, and declarative server-rendered plugin settings. Phase 8C
adds local bundle installation, staged updates/rollback, data-preserving
uninstall, a bounded process supervisor, and optional Linux hardening.

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
instance/data/plugin-grants.toml                locally granted capabilities
instance/data/plugin-installations/<id>.json    managed bundle digest/version
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
requested_capabilities = ["storage.kv", "data.content.read"]
required_capabilities = []
subscriptions = []
tasks = []
dependencies = []
```

`manifest_version`, `id`, `name`, `version`, `author`, `license`,
`requires_arborpress`, and `entrypoint` are required. `description`, `python`,
requested/required capabilities, event subscriptions, task names, and a
declarative `admin_ui` descriptor are optional. IDs use lowercase ASCII letters/digits
with single hyphen separators. Versions use PEP 440 parsing and compatibility
fields use version specifiers. Required capabilities must also be requested;
unknown names are rejected. Subscriptions require `events.subscribe`, tasks
require `jobs.schedule`, and `admin_ui` requires `admin.declarative`. An invalid or incompatible package remains
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
and runtime versions, and the locally granted capabilities. Required
capabilities must be granted before start. Grants live outside the manifest in
instance-local `plugin-grants.toml`; the plugin process cannot change them.
Grant/revoke uses Admin auth, CSRF and existing step-up protection. Every Core
RPC checks the live grant file before validating params, so revocation applies
to subsequent calls. The child host
returns `ready=true` and matching ID/version after the plugin's initialize
callback succeeds; only then does the Core mark it `running`.
`runtime.ping` and `runtime.shutdown` remain lifecycle methods. Plugin-to-Core
methods use a static capability-enforced dispatcher, not arbitrary attribute
lookup: `core.storage.{get,set,delete,list}`, `core.data.content.{get,list}`,
`core.data.comments.list`, and `core.jobs.schedule`. No SQL, ORM, credentials,
or general DB API exists. RPC errors do not include Python tracebacks.

Default startup timeout is 10 seconds, request timeout 30 seconds, and graceful
shutdown timeout 3 seconds, followed by process-group terminate/kill fallback.
Separate stdout/stderr pipes are drained and output is bounded in ArborPress
logs. A child exit is tracked and marked failed unless shutdown was requested.
An enabled plugin failing to start does not prevent normal Core startup. The
Phase 8C supervisor applies bounded restart and auto-disable policy.

The child is started without `shell=True`, with an explicit plugin working
directory, closed unrelated file descriptors, a new process session, and a
minimal environment. `PATH`, locale, plugin ID/protocol and the installed
ArborPress package/plugin roots are the only passed environment values.
This is credential hygiene, not an OS sandbox.

## Storage, Data, Events, Jobs and declarative Admin

`PluginContext.storage` wraps Core-managed JSON KV storage. Rows are scoped by
the plugin ID attached to the private process channel, never a caller-provided
owner ID. Keys and JSON values are bounded, writes support optimistic
revisions, and per-plugin entry/total quotas are enforced. Persistent rows are
in `plugin_storage_entries`.

Read APIs return DTOs only: published public posts and approved comments on
published public posts. Drafts/private content, author email, account data,
moderation notes, confirmation tokens and other internal fields are excluded.

`post.published` and `comment.approved` notifications are best-effort,
at-most-once for a running plugin and use a bounded per-process queue. They
may be dropped on overflow or while a plugin is stopped; this is not a durable event bus. Durable/retryable
work belongs in the Core-owned `plugin_jobs` queue. Jobs use declared task
names, JSON payload limits, optional idempotency keys, leases and bounded
backoff retries. Execution is at-least-once-like, not exactly-once. A stopped
plugin's jobs are deferred without consuming attempts.

Declarative Admin accepts only bounded pages, text/textarea/number/boolean/
select/readonly fields and declared action IDs. ArborPress renders with its own
Jinja templates and validates POST values server-side. Raw HTML, JavaScript,
CSS, secret fields and plugin routes are not supported. Action results are
structured JSON and rendered escaped; audit records contain action IDs, not
submitted values.

`storage.files` and `network.http` remain recognized request names but are not
grantable in 8B: this release exposes no file RPC and no SSRF-safe Core HTTP
proxy. Direct same-user filesystem/network access by Python code is not blocked
by process separation alone. There is no database, Python, shell, or arbitrary
host-filesystem capability.

Alembic revision `0005_plugin_capabilities_storage_jobs` creates the KV and job
tables. Grant state stays instance-local TOML (`plugin-grants.toml`) and is not
part of the portable plugin package.

## Interpreter isolation and controls

An empty plugin venv can be created without network access using:

```text
arborpress plugins runtime create sample-plugin
```

The runtime uses `instance/var/plugins/<id>/venv/bin/python` when present;
otherwise it uses the current ArborPress Python interpreter. No dependencies
are installed or resolved by Phase 8A. A plugin venv uses the ArborPress SDK
bootstrap from the installed ArborPress release through an explicit package
path. Plugin dependencies are installed only by the local installer, into a
new per-plugin venv. It accepts prebuilt wheel files from the bundle, invokes
the exact staged venv interpreter with `--no-index`, `--find-links` and
`--only-binary=:all:`, and rejects direct URL dependencies and source
distributions. It never edits the ArborPress environment or resolves from the
internet. `plugins runtime create` remains useful for development but does not
install third-party dependencies.

Available diagnostics are `arborpress plugins list [--json]`,
`inspect <id> [--json]`, `check <id>`, and `validate <directory>`. Local
lifecycle commands are:

```text
arborpress plugins install ./sample-plugin.zip
arborpress plugins update sample-plugin ./sample-plugin-2.zip
arborpress plugins uninstall sample-plugin
arborpress plugins purge sample-plugin --yes
```

The ZIP bundle has one root containing `plugin.toml`, `checksums.sha256`, a
`package/` tree and optionally a `wheels/` directory. The manifest must identify
the same plugin as the target. Checksum verification is integrity diagnostics,
not publisher authentication or a digital signature. Archive paths, symlinks,
duplicate members, file types, sizes, and wheel metadata are validated before
staging. Installation uses same-instance staging and atomic package/runtime
swaps; a successful install remains disabled until an administrator enables
it. Dependencies must be provided as compatible local wheels. URLs, remote
indexes, and sdists are rejected.

An update requires the same ID and a newer version. It stages a separate
package and venv and requires the ArborPress instance to be stopped before the
switch. It restores the old package/runtime if the candidate fails its isolated
initialize/handshake/ping self-check. Existing persistent plugin data is preserved. New capability
requests are never automatically granted; if a required capability is missing,
the new version is installed but left disabled. Grants no longer requested are
removed. A package digest mismatch is surfaced in discovery/inspect and blocks
managed startup. Because the CLI cannot control another ArborPress server
process, operators must stop the running ArborPress instance before update or
uninstall; the per-plugin process lock rejects concurrent lifecycle changes.
Manual edits are not a supported production update mechanism.

`uninstall` stops and removes the managed package, generated runtime and local
enable/grant state, but preserves `instance/data/plugins/<id>` and diagnostic
history. `purge` is a separate destructive operation and explicitly removes
only that plugin's persistent data. Built-in plugins cannot be installed,
updated, uninstalled, or purged through the third-party lifecycle.

The supervisor checks health periodically, retries unexpected exits with a
bounded rolling-window policy (three restarts in ten minutes, with 1/5/30
second backoff), and marks a plugin `auto_disabled` once the budget is
exhausted. Manual re-enable clears the auto-disable state. Repeated heartbeat
failures can trigger a restart; an individual ordinary RPC error does not.
Other plugins and ArborPress core continue independently. Pending jobs remain
persisted while a plugin is unavailable.

On POSIX, child startup applies a restrictive umask, disables core dumps,
limits open descriptors, and on Linux attempts `PR_SET_NO_NEW_PRIVS`. The
active process manager reports which features were applied. These are
defense-in-depth controls, not a hostile-code sandbox: absent namespaces,
seccomp, or another OS isolation boundary, plugin code running as the same OS
user may still access resources that user can access directly. `network.http`
is not currently grantable, and there is no generic host-filesystem API.
Process isolation, sanitized environment, Core-mediated API enforcement, and
optional OS hardening must not be represented as complete direct network or
filesystem isolation.

The Admin plugin overview shows installation integrity, runtime health, PID,
restart/error diagnostics, capability state, and pending/dead job counts. It
supports the existing protected enable/disable operations and a protected
restart action. Bundle install/update/uninstall/purge are CLI-only; there is no
large-bundle upload endpoint. Built-in integrations remain in-process Core
modules, and there are still no plugin routes, Quart blueprints, plugin-defined
CLI commands, arbitrary Admin JS, Marketplace, or automatic downloads.
