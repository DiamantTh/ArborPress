# ArborPress theme runtime (Phase 5A)

ArborPress themes are presentation resources loaded by the Python/Quart
runtime. Jinja remains the only server-side template engine. Built-in themes
are package resources in `arborpress/themes/`; operator-installed themes are
discovered only below the active prefix's `instance/themes/`. The checkout's
`content/themes/` directory is reference material and is never scanned.

Public and Admin are separate theme types with independent selections. The
default Public theme is `default`; the default Admin theme is `arbor-admin`.
The existing `site_settings` row stores these as `theme.active` and
`theme.admin_active`, respectively. No schema migration is needed. Invalid,
incompatible, missing, or wrong-type selections fall back to the corresponding
built-in theme and are logged. A Public theme failure does not change Admin
selection.

## Directory and manifest

An instance theme has this shape:

```text
instance/themes/<theme-id>/
├── theme.toml
├── templates/                 # optional, explicitly allowlisted overrides
└── static/                     # optional, declared local assets
    ├── style.css
    ├── images/
    └── fonts/
```

The directory name is the stable theme ID. IDs match
`[a-z0-9]+(?:-[a-z0-9]+)*`; the manifest does not contain a second ID.
Human-readable names may contain Unicode. A minimal Public theme is:

```toml
name = "Example Theme"
version = "1.0.0"
type = "public"
author = "Example Author"
license = "MIT"
description = "A local ArborPress theme."
requires_arborpress = ">=0.1.0"
tested_with = "0.1.0"
capabilities = ["styles"]

[assets]
css = ["static/style.css"]

[entry_points]
public_css = "static/style.css"
```

`name`, `version`, and `type` are required. `type` is exactly `public` or
`admin`. `version` and `tested_with` use comparable PEP 440 versions;
`requires_arborpress` is a PEP 440 version specifier and must include the
running ArborPress version. `author`, `license`, `description`, `tested_with`,
`parent`, `dark_companion`, `light_companion`, `preview`, `features`,
`capabilities`, `assets`, `entry_points`, and `templates` are optional. If
`preview` is present, it is a `static/` path declared in `assets.images` or
`assets.icons`.
`tested_with` is informative, not a compatibility guarantee.

The existing feature flags remain under `[features]`:

```toml
[features]
dark_mode_toggle = false
code_highlight = true
reading_time = true
table_of_contents = false
```

The supported capabilities are `templates`, `styles`, and `public_assets`.
CSS requires `styles`; fonts, images, and icons require `public_assets`.
Static paths must be normalized relative paths under `static/`, declared in
the manifest, and resolve to files within the theme root. The only supported
theme asset entry points in this phase are `entry_points.public_css` for
Public themes and `entry_points.admin_css` for Admin themes; each must refer
to an item declared in `assets.css`. Assets are served same-origin at
`/static/themes/<theme-id>/<path-under-static>` and can fall back through the
parent chain. There is no theme JavaScript entry point: ArborPress does not
load arbitrary theme JS, and Admin themes cannot inject scripts. Third-party
themes bring any prebuilt assets with them; installing a theme never runs
Node, npm, pnpm, yarn, or Vite.

Theme templates are listed as root-level `templates` paths, for example:

```toml
capabilities = ["templates"]
templates = ["post.html", "index.html"]
```

Phase 5A permits Public overrides only for `index.html`, `post.html`,
`page.html`, `tag.html`, `search.html`, and `comment_confirmed.html`. Admin
overrides are limited to `admin/dashboard.html`, `admin/posts.html`,
`admin/post_edit.html`, `admin/pages.html`, `admin/media.html`,
`admin/comments.html`, `admin/plugins.html`, `admin/settings.html`, and
`admin/captcha.html`. Base layouts, authentication, installation, users,
sessions, WebAuthn, and security templates are not theme-overridable.
Declared template files must exist beneath the theme's `templates/` directory.

Unknown manifest fields, capabilities, entry points, or override names are
validation errors. Absolute paths, traversal, URL-like paths, and symlinks
escaping the theme root are rejected. A malformed theme remains visible in
registry diagnostics but cannot be selected or used as a render source.

## Parent themes and lookup

`parent = "<theme-id>"` selects one parent. A theme has at most one direct
parent; longer chains are allowed up to eight levels including the active
theme. Public themes can inherit only from Public themes, and Admin only from
Admin. Self-cycles, multi-theme cycles, missing parents, invalid parent
chains, and excessive depth prevent activation.

For a declared template or asset, resolution checks the active child first,
then each parent, then ArborPress's core package resources (templates only).
There is no copying of parent files. Package theme IDs cannot be shadowed by
instance themes; an ID collision is reported as `duplicate_id` and the
package theme remains authoritative.

## Runtime and diagnostics

The Jinja loader is `arborpress.themes.jinja.ThemeTemplateLoader`. It chooses
Public versus Admin from the Quart endpoint, uses the active prefix's
`instance/themes`, and wraps Jinja's cache validity check so changing theme
selection or request type cannot reuse another theme's compiled template.
Core routing, authentication, CSRF, permissions, and business logic remain in
ArborPress. The global `config` value exposed to Jinja is a small presentation
mapping containing only `web.base_url`, `web.admin_editor`, and
`auth.legacy_password_enabled`; it is not the runtime `Settings` object and
does not expose database credentials or signing keys. Themes receive only the
context required by the selected core route and cannot replace authentication,
installation, user, session, WebAuthn, or security templates. Phase 5B will
add the explicit Trust Tier policy and deeper sandbox/resource restrictions
before any theme-editing UI exists.

Read-only CLI diagnostics:

```sh
arborpress --prefix ~/ArborPress themes list
arborpress --prefix ~/ArborPress themes list --json
arborpress --prefix ~/ArborPress themes inspect example-theme
```

The list reports ID, name, version, type, source, parent, status, diagnostics,
and active Public/Admin selection. It reads saved site settings when the DB is
available and uses defaults otherwise. Registry status values include
`valid`, `invalid`, `incompatible`, `missing_parent`, `cyclic_parent`, and
`duplicate_id`.

## Not implemented in Phase 5A

There is no Theme upload/install/delete UI, file editor, preview session,
derived-theme generation, options schema/UI, revision/reset workflow, remote
theme store, Trust Tier management, or resource-limited template sandbox yet.
These are Phase 5B work. Themes are local filesystem content; do not treat a
theme manifest as a trust declaration. In particular, no `trusted = true`
manifest field exists or is honored.
