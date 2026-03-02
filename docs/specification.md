# Arbor Press – Detailed Technical Specification
**Date:** 2026-02-24

> This is the detailed, GitHub-friendly text version of the Arbor Press specification.
> It is intended to be pasted into a repository (e.g., as `SPEC.md`) and to serve as a shared reference for implementation and review.

---

## 0) Purpose / Positioning

Arbor Press is a **small, security-focused blogging platform / mini CMS** with a deliberately minimal core.

### Core intent
- Keep the core **small and auditable**.
- Prefer **secure-by-default** decisions over "flexibility by complexity".
- Support extensions via a **controlled plugin system** (no marketplace).
- Keep URLs **stable** and **SEO-friendly**.
- Be **reverse-proxy friendly** (nginx / Apache / Traefik).

### Non-goals
- No enterprise IAM/IdP dependency by default.
- No mandatory SPA requirement for the public site.
- No plugin-defined standalone security pages (core controls security UX).
- No "everything configurable" at the cost of security and maintainability.

### Deployment philosophy
Arbor Press is designed as a **classic server-side application first**:
- It must run reliably as a standard process on a host system.
- Containerization (e.g., Docker) is supported as an optional deployment method, but the project is **not container-first**:
  - No environment-variable-only configuration required.
  - No Docker-specific assumptions baked into core behavior.
  - Same operational workflows apply to bare-metal and containers.

---

## 1) Scope / Core Features

### Core functionality
- Publishing: **posts + pages** (including system pages like **Impressum**, **Privacy**, **Rules**).
- Admin interface for content management and security settings.
- Media handling with stable URLs.
- Search:
  - FTS as progressive enhancement where available
  - fallback search always available
- Import/Export designed to be independent from raw DB backup (portable content model).

### Optional functionality (supported by design)
- ActivityPub federation:
  - modes: full / outgoing-only / disabled
  - inbox-only possible as stricter mode (optional)
- External login via OAuth2/OIDC:
  - optional module
  - hidden unless configured
- Extended MFA methods via plugin interface.

---

## 2) Authentication Model (Primary Auth Layer)

### Primary authentication
- **WebAuthn/FIDO2** is the default and recommended method.
- **Username-first** flow:
  - user identifies account first
  - then completes WebAuthn authentication

### Multiple credentials per account
Each user may register multiple credentials:
- Credentials must be **labelable** (user-defined name).
- Store metadata (when available):
  - transport (usb/nfc/ble/internal)
  - credential type (platform/hardware if detectable)
  - created timestamp
  - last-used timestamp

### User Verification (UV / PIN / biometric)
- Configurable globally (optional by default).
- Enforceable per role and/or per action:
  - privileged actions require UV
- Compatibility:
  - legacy U2F-like "UP-only" credentials should remain usable where feasible.

### Step-up mechanism ("sudo mode")
Required for high-risk operations, for example:
- changing roles/permissions
- modifying authentication policies
- enabling/disabling federation
- plugin installation/enabling
- export generation
- key rotation
- security settings changes

Step-up can require:
- WebAuthn with UV (preferred)
- backup code (strictly controlled)

### Legacy passwords
- Implemented strictly as break-glass fallback.
- Disabled by default.
- Not visible in primary login flow.
- Can be fully disabled by policy.
- If enabled, must be clearly labeled: **"Legacy / Not Recommended"**.

---

## 3) MFA Backend Architecture (Modular MFA)

### Architecture
- MFA is implemented via a backend interface exposed by the core.
- The core provides:
  - enrollment hooks
  - verification hooks
  - policy evaluation hooks
  - UI integration slots (core renders security UI)

### System-level MFA modules included by default
- TOTP (SHA-256 minimum; 8–12 digits configurable)
- Optional HOTP (SHA-256 minimum; 8–12 digits configurable)
- Backup codes (one-time recovery)

### Extensibility
- Plugin interface for additional MFA methods.
- MFA methods must integrate into unified core UI components.
- No plugin-defined standalone security pages; the core remains UI authority.

---

## 4) Account & Role Model (Public vs Operational Identity)

### Account types
1. **Federated / Public Accounts**
   - May expose ActivityPub actor endpoints
   - Discoverable via WebFinger
   - Intended for public publishing and public identity

2. **Local-Only Operational Accounts (Admin/Moderation)**
   - Not discoverable externally
   - No WebFinger entry
   - No ActivityPub actor endpoint
   - Restricted to local auth flows
   - Intended for administration/moderation tasks only

### Role policies
Privileged roles may enforce:
- UV required
- step-up required
- legacy password disabled
- external SSO disabled (optional policy)

---

## 5) Federation (ActivityPub Integration)

### Federation modes
- Full federation (inbox + outbox enabled)
- Outgoing-only (broadcast without inbox)
- Disabled
- Optional stricter mode: Inbox-only (receive/display replies without publishing as actor)

### Required endpoints (when enabled)
- `/.well-known/webfinger`
- `/.well-known/nodeinfo`
- `/nodeinfo/{version}`
- `/ap/actor/{handle}`
- `/ap/inbox/{handle}`
- `/ap/outbox/{handle}`
- `/ap/object/{id}`

### Constraints
- Operational accounts must not generate actor endpoints.
- ActivityPub endpoints must not be language-prefixed.
- Federated content must be sanitized before rendering.
- UI must clearly distinguish:
  - internal comments
  - federated replies/mentions (remote actors)

### Practical comparisons (examples)
- **Mastodon**: actor endpoints are first-class per account; strong federation assumptions.
- **Blog-style federation**: often benefits from outgoing-only; inbox can be high-risk input.
- Arbor Press supports multiple federation modes, without forcing social-network behavior.

---

## 6) URL Schema (Stable & SEO-Friendly)

### Public routes
- `/p/{slug}` (post)
- `/page/{slug}` (page)
- `/tag/{tag}` (tag browsing)
- `/search?q=` (search)
- `/media/{yyyy}/{mm}/{file}` (media) — may be replaced by a dedicated media host without "media" in the path.

### Multi-user mode (optional)
- `/@{handle}`
- `/@{handle}/p/{slug}`

### Reserved namespaces
- `/admin`
- `/api`
- `/ap`
- `/.well-known`
- `/nodeinfo`
- `/auth`
- `/media`

### Canonicalization
- enforce lowercase slugs
- enforce HTTPS
- no trailing slash for content routes
- `301` redirect on slug changes
- optional short-ID fallback route: `/o/{id}` (stable random ID)

### Admin path hardening
- admin base path must be configurable/dynamic (not necessarily "/admin")
- admin entry points should not be linked publicly (noise reduction)
- additive only; never replaces real security controls

---

## 7) Internationalization (I18N)

### Supported models
A) Single-language site (default)
B) Language prefix:
- `/{lang}/p/{slug}`
- `/{lang}/page/{slug}`

### Rules
- ActivityPub and well-known endpoints are never language-prefixed.
- `hreflang` tags required for multi-language content.
- root path may redirect to default language

### Practical model preference
- languages can be represented as tags/categories for content organization
- system pages like Impressum/Privacy can exist once per language as separate pages

---

## 8) Admin & API Separation

### Admin interface
- base path: dynamic admin path
- typical routes:
  - `/admin/login`
  - `/admin/security`
  - `/admin/content/...`

Requirements:
- must emit `noindex`
- must emit `no-store` / strict cache control for admin/auth routes
- optional deployment on dedicated subdomain (e.g., `admin.example.tld`)

### API
- `/api/v1/...`
- strict versioning
- JSON-only
- separate admin APIs from public APIs
- CSRF protection for session-based endpoints where relevant
- public API endpoints must not expose operational account details

---

## 9) Theme & Frontend Model (Public + Admin)

### Theme philosophy
- public site is server-rendered first
- progressive enhancement allowed
- no SPA requirement for public site

### Theme model
- manual installation (no central store)
- each theme provides a manifest:
  - name, version, license, description
  - compatibility version range
  - assets (CSS, fonts, icons)
  - optional template overrides (public only)
  - optional progressive JS (must remain CSP-compatible)

### Admin customization (WP-like, but controlled)
- admin UI must remain structurally stable
- allow safe customization:
  - logo/branding
  - accent color
  - light/dark mode
  - navigation ordering / widgets
- no theme/plugin may override login/security pages or core security UX

### Frontend build note
If an SPA is used (Svelte/Vue) it should be build-time only:
- runtime does not require Node
- static build artifacts served by backend/reverse proxy

---

## 10) Security-First Design Principles

### HTTP headers
- strict CSP defaults
- `frame-ancestors` restricted
- `no-store` for admin/auth routes
- correct cache control for static media

### Reverse proxy friendly
- trust proxy configuration
- correct handling of `X-Forwarded-*`
- compatible with nginx / Apache / Traefik

### External content
- no remote HTML includes
- optional media proxy for external embeds
- sanitization for user-generated and federated content

### Operational hardening
- rate limits for auth endpoints
- audit logging for security events:
  - credential add/remove
  - step-up
  - policy changes
- safe session handling:
  - secure cookies
  - short TTL for admin sessions
  - step-up gating for sensitive actions

---

## 11) External Login (OAuth2 / OIDC Client) — Optional Only

External IdP/SSO is optional and must remain hidden unless configured.

### External login UX
- dedicated button (separate from username-first WebAuthn flow)
- routes:
  - `/auth/sso/{provider}`
  - `/auth/sso/{provider}/callback`

### Constraints
- claims mapped to internal roles
- no automatic privilege escalation via SSO
- operational accounts may be restricted from SSO
- local WebAuthn step-up may still be required for sensitive actions

---

## 12) Database Support (Modern Baseline + Capability Detection)

### Supported engines
- MariaDB >= 11.x (minimum)
- PostgreSQL >= 16.x (minimum; >= 17.x recommended)

### Policy
- focus on modern, actively maintained versions
- detect engine/version at startup and enable features progressively

### Feature detection
- maintain runtime capability flags (optionally persisted snapshot for admin visibility)
- avoid mandatory DB-vendor-exclusive features in core schema
- FTS implemented as pluggable provider:
  - PostgreSQL FTS provider
  - MariaDB FULLTEXT provider
  - fallback search provider always available

### Import/Export
- avoid "DB backup only" portability
- structured export/import suitable for migrating between instances

---

## 13) Mail System (Providers + OpenPGP)

### Mail backends
- SMTP (universal)
- optional provider APIs (only if configured)

### OpenPGP signing/encryption
- outbound mails should support OpenPGP signing (instance key)
- transactional mails can be encrypted per user if:
  - user enabled encryption
  - user provided a verified public key

### Key policy
- in-app key generation: modern ECC/Ed first (Ed25519/X25519 recommended)
- RSA supported import-only (RSA >= 4096 if imported)
- key management via admin UI and CLI
- private keys encrypted at rest; never logged

### Queueing
- outbound mails processed asynchronously (outbox queue)
- retries with backoff, idempotency, and minimal sensitive logging

---

## 14) CLI (WP-CLI / occ-style) — Admin Focus

The CLI is a first-class component used mainly for administration tasks.
Content management via CLI is optional/extendable.

### Admin CLI (examples)
- install / init
- migrate
- user management (add/disable/roles)
- auth policy status
- key management (generate/import/rotate/status)
- search reindex
- cache purge/warm
- federation inbox processing (if enabled)
- healthcheck

### CLI design rules
- commands reuse the same core services as the web app
- plugins may register additional CLI commands via declared capabilities

---

## 15) Plugin System (Controlled Extensions)

### Plugin model
- manual installation only
- manifest-driven registration
- core validates compatibility version
- declared capabilities:
  - mfa_provider
  - auth_provider
  - importer
  - exporter
  - federation_extension
  - comments_extension (optional concept)
  - mail_backend (optional concept)

### Constraints
- no marketplace / no remote store
- UI integration via core slots only
- no plugin may define standalone security pages

---

## 16) Logging Policy (Portable + Distro-Friendly)

### Defaults
- logs to stdout/stderr by default
- optional file logging if enabled

### Rationale
- stdout works for containers and systemd/journald on classic servers
- file logging can be enabled by deployments or distro packages
- upstream does not hardcode /var/log

### Log categories (recommended)
- app log (errors/warnings/info)
- access log (optional)
- audit/security log (credential, policy, admin actions)

---

## 17) Design Summary (One-liners)
- Minimal core, modular extensions, no enterprise bloat.
- WebAuthn/FIDO2-first auth with step-up for privileged actions.
- Legacy password only as hidden break-glass fallback.
- Clean separation: public/federated identities vs operational admin identities.
- Optional federation with strict constraints and sanitization.
- Stable URL schema and reverse-proxy friendly defaults.

---

## Appendix A) Suggested initial implementation stack (informational)
This section is informational; the core specification above is implementation-agnostic.

- Backend language: Python 3.10+
- Web framework: Quart (ASGI)
- CLI: Typer
- Frontend: Svelte (build-time), progressive enhancement at runtime
- DB: PostgreSQL >=16 or MariaDB >=11
- Reverse proxy: nginx/Apache/Traefik compatible
- Container: supported but not required
