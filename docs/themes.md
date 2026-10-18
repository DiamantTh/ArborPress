# ArborPress theme runtime and administration (Phase 5)

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
does not expose database credentials or signing keys. Theme templates receive
`theme_options`, a small `theme` metadata view, and the presentation context
required by their route. SQLAlchemy model relationships and private/secret
attributes are not template-readable; mapped scalar columns used for display
remain available. Do not pass sessions, engines, service objects, or arbitrary
callables into a template context.

The runtime environment is `ArborPressSandboxedEnvironment` from
`arborpress.themes.sandbox`. It denies private/dunder and secret-named
attributes, limits callable object methods, and restricts mapped ORM access to
scalar columns. The normal tier is the default for every instance theme.
An administrator can locally mark an instance theme trusted in the current
instance's `theme.trusted_themes` setting; no manifest field can grant trust.
The trusted tier currently adds only the explicit `theme_asset_url()` helper
for same-origin, manifest-declared local assets. Built-in package themes are
trusted as ArborPress program resources. Neither tier grants Python imports,
filesystem access, networking, shell/process execution, SQL, or direct ORM
sessions. Jinja's sandbox is a defense-in-depth boundary, not a process
sandbox.

Hard limits currently enforced by the theme management/runtime paths are:

- at most eight themes in a parent chain;
- 256 KiB per editable/overridden template;
- 512 KiB per editable CSS file;
- 32 KiB per edited manifest;
- 1 MiB (approximately) per stored revision record.

Theme templates are syntax-checked before save and render with autoescaping.
The runtime falls through to a parent/core template for a missing, invalid
syntax, oversized, or escaping override. Admin render exceptions also clear
the Admin preview and retry with the built-in Admin theme. There is no hard
render-time timeout, output-byte cap, or general include-count limit; the
system does not claim to safely terminate hostile Python execution because
themes cannot execute Python in the first place.

## Options, local trust, and editing

Options are declared as tables under `[options.<key>]` in `theme.toml` and are
stored per instance in the existing `site_settings` row (`key = "theme"`):

```toml
[options.accent]
type = "color"
label = "Accent color"
description = "The main decorative color."
default = "#3659A2"
required = true

[options.posts_per_page]
type = "integer"
label = "Posts per page"
default = 10
minimum = 1
maximum = 40
```

Supported types are `string`, `text`, `boolean`, `integer`, `number`,
`select`, `color`, `url`, and `asset`. Definitions also support `choices`,
`minimum`, and `maximum` where appropriate. Keys use
`[a-z][a-z0-9_]{0,63}`. String, text, URL, and asset values have respective
4 KiB, 64 KiB, 2 KiB, and 512-byte limits. Colors must be `#RRGGBB`; URLs must
be absolute HTTP(S) URLs without embedded credentials; asset values must name
a declared asset in the effective parent chain. Child themes inherit parent
defaults and can override a key only without changing its type (or a select's
choices). Persisted values are instance-owned under `theme.option_values`,
keyed by theme ID; removing values returns to defaults/inherited values.
Templates receive only the resolved options mapping as `theme_options`.

The server-rendered Admin UI is available at `/admin/themes` and
`/admin/themes/<theme-id>`. It shows Public and Admin selections separately,
configured/effective IDs, status, compatibility diagnostics, local trust, and
parent dependents. POST actions use the existing Admin session/role gate and
CSRF protection. Trust changes additionally require the target-bound
`trust_theme` step-up action. Theme selection, trust, options, derived-theme
creation, override edits/resets, manifest changes, and revision restores are
written to the existing audit event stream without storing full file contents
in audit details.

Editing a package or instance parent does not modify that parent. ArborPress
creates a local child under `instance/themes/` with a deterministic
`<parent-id>-local` ID (a validated numeric suffix is used for collisions),
`derived = true`, and `parent = "<parent-id>"`. Only local overrides are
stored there. The editor currently permits the manifest-declared template
allowlist and CSS files; it is not a general filesystem editor. Template,
CSS, and manifest changes are UTF-8-only, size-limited, hash-checked for
concurrent edits, validated, and written through same-directory temporary
files followed by atomic replacement. Symlink escapes and paths outside the
active `instance/themes` root are rejected. Reset removes only a local
override; it never deletes a parent resource. Manifest edits cannot change a
derived theme's parent, type, or derived marker and may declare only files
already present in that child. Asset upload/management is not provided.

File and option revisions are stored as ArborPress instance data at
`instance/data/theme-revisions/<theme-id>/<revision-id>.json`. A revision
records timestamp, actor, resource/option kind, before/after state, and hashes;
editable content remains bounded by the limits above. Revisions can restore
prior file/option values through the Admin UI. There is no aggressive automatic
retention deletion or pinning policy yet.

Preview is started by an authenticated Admin POST, bound to that signed
session, theme type, a 30-minute expiry, and a fingerprint of the theme chain's
manifest/templates/CSS. It does not modify global active settings. Preview
responses are `private, no-store` and marked `noindex`; changed theme content
invalidates the preview. Public and Admin previews use a coherent selected
theme chain, and a broken Admin preview has a built-in escape path. The
overview displays configured and effective themes separately; invalid or
incompatible selections continue to use independent built-in fallbacks.

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

## Deliberately outside Phase 5

Theme marketplace or remote installation, upload/delete UI, arbitrary Admin
theme JavaScript, arbitrary template Python, a process-level sandbox, hard
render-time/output limits, asset uploads, theme preview sharing, global
revision retention/pinning, and mail-template editing are not implemented.
Theme trust is never imported or declared by a theme. These limitations do
not change the rule that themes are presentation resources and ArborPress
Core remains authoritative for security and business logic.
