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
npm run build --prefix frontend
npm run build:editor --prefix frontend
```

`npm run build` emits a browser-only, fingerprinted bundle for the logical
`webauthn` entry, plus Vite's manifest, under
`arborpress/static/dist/`. The manifest is at
`arborpress/static/dist/.vite/manifest.json`. The existing TipTap editor adapter
continues to build separately to `arborpress/static/js/editor-adapters/tiptap.js`
because the current administration template loads that adapter directly.

For a development rebuild on source changes, run this in one terminal:

```sh
npm run dev --prefix frontend
```

Then start Quart with the desired explicit development prefix in another
terminal. The Vite watch build writes to the package static directory, which
Quart serves; no Vite development server or proxy is needed.

`make build` performs the locked install, checks, both browser builds, and then
builds the Python wheel and sdist. The container build uses a Node 24 build stage
and copies only compiled assets into the Python package before packaging. The
final runtime image remains Python-only.

## Jinja asset lookup

The Python `vite_asset` Jinja global resolves a logical entry from the packaged
Vite manifest. It returns package-static paths, not external URLs. A template can
use it when a page is migrated to an enhancement bundle:

```jinja
{% set bundle = vite_asset("webauthn") %}
{% for stylesheet in bundle.stylesheets %}
  <link rel="stylesheet" href="{{ url_for('static', filename=stylesheet) }}">
{% endfor %}
<script type="module" src="{{ url_for('static', filename=bundle.javascript) }}"></script>
```

The resolver checks manifest paths remain inside the packaged `dist/` directory
and rejects missing or malformed assets. A source checkout without a frontend
build reports the exact build command when a template requests an entry. Public
and administration entries will be added as those pages are migrated; their
current routes and scripts are intentionally unchanged in this
build-foundation phase.

For data passed from Jinja to a Svelte island, use `data-*` attributes for small
primitive values and Jinja's `tojson` filter in a non-executable
`application/json` script element for structured values. Browser code should
parse that element as JSON; templates must not concatenate executable
JavaScript or expose secrets in DOM data.
