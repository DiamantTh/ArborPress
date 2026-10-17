# Frontend build and runtime model

ArborPress keeps HTTP routing and server-side rendering in Quart and Jinja. Jinja
returns complete HTML; Svelte components are optional browser enhancements on
pages that explicitly opt into them. There is no client-side router, SvelteKit
server, Node SSR process, or JavaScript runtime service.

Node.js 24 and npm are build-time tools only. The runtime serves the compiled
same-origin assets through Quart's existing `/static/` route and requires neither
Node nor `node_modules`.

## Local build

Install the locked frontend dependencies and run the frontend checks/build from
the repository root:

```sh
npm ci --prefix frontend
npm run check --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
```

`npm run build` emits browser-only, fingerprinted bundles for the logical
`site`, `public`, `webauthn`, `admin`, and `editor-tiptap` entries, plus Vite's manifest, under
`arborpress/static/dist/`. The manifest is at
`arborpress/static/dist/.vite/manifest.json`. TipTap is a separately loaded,
fingerprinted entry, so its larger code is sent only on post-edit pages that
select that adapter. The smaller built-in and legacy-compatible editor adapters
remain package static files and the editor textarea remains the no-JavaScript
fallback.

Public routes remain Quart routes, and Jinja returns complete pages before any
browser bundle runs. Index, article, page, archive, search, profile, navigation,
and the ordinary comment form are usable without JavaScript. The public entry
enhances optional comment quoting on article pages and explains that boundary to
no-JavaScript visitors. The login page is also server-rendered; its WebAuthn
action is enabled only after the `webauthn` entry mounts, while SSO, recovery,
and any configured break-glass form remain ordinary HTML navigation or forms.
Configured third-party CAPTCHA widgets retain their existing provider-specific
browser requirements.

The Admin is also Quart/Jinja SSR, not a client-side application. Its navigation,
lists, settings, post forms, and security forms are rendered by the server; each
HTML mutation form contains its CSRF field before JavaScript runs. The fingerprinted
`admin` entry enhances the captcha question editor, password tools, session/action
confirmation, media URL copying, plugin step-up actions, and existing security
step-up flows. Without JavaScript, settings and content forms remain ordinary
submittable forms; the two browser-only tools explain their limitation and retain
their CLI/server-side alternatives where applicable.

The Admin receives structured captcha data through a non-executable
`application/json` element rendered with Jinja's `tojson`. The Svelte entry uses
an explicit set of known mount points; it does not select components dynamically
from arbitrary DOM-provided names. The `editor-tiptap` entry is loaded only when
the configured post editor is TipTap. Its original Markdown textarea remains the
no-JavaScript and initialization-failure fallback.

For a development rebuild on source changes (including Public and Admin
entries), run this in one terminal:

```sh
npm run dev --prefix frontend
```

Then start Quart with the desired explicit development prefix in another
terminal. The Vite watch build writes to the package static directory, which
Quart serves; no Vite development server or proxy is needed.

`make build` performs the locked install, checks, the browser build, and then
builds the Python wheel and sdist. The container build uses a Node 24 build stage
and copies only compiled assets into the Python package before packaging. The
final runtime image remains Python-only.

The old unbundled site helper and Admin security helper have been removed after
their behavior moved into Vite entries or server-rendered form markup. Theme
manifests may still contain a legacy `assets.js` field, but ArborPress does not
automatically execute theme or plugin scripts in Admin pages; the supported
theme contract remains a later architecture phase.

## Jinja asset lookup

The shared Jinja macros in `templates/macros/assets.html` resolve a logical
entry from the packaged Vite manifest. They emit same-origin stylesheet and
module-script tags; templates do not duplicate manifest traversal or hard-code
fingerprinted names:

```jinja
{% from "macros/assets.html" import vite_styles, vite_script with context %}
{{ vite_styles("admin") }}
{{ vite_script("admin") }}
```

The resolver checks manifest paths remain inside the packaged `dist/` directory
and rejects missing or malformed assets. A source checkout without a frontend
build reports the exact build command when a template requests an entry. Jinja
loads only the bundle needed by a page, and the manifest—not a hard-coded
fingerprint—selects its files. Public content and authentication policy stay
server-side; browser code receives only the small values needed for an
interaction.

For data passed from Jinja to a Svelte island, use `data-*` attributes for small
primitive values and Jinja's `tojson` filter in a non-executable
`application/json` script element for structured values. Browser code should
parse that element as JSON; templates must not concatenate executable
JavaScript or expose secrets in DOM data.
