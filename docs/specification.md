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
  - AAGUID, authenticator attachment, transports, backup eligibility/state
  - created timestamp
  - last-used timestamp
  - registration verification status. Legacy records with no UV evidence remain
    available but are marked `unknown` and should be re-enrolled.
- Standard limit: 10 WebAuthn credentials per user; instance configurable
  from 1 to 100. Lowering the limit never deletes existing credentials.

### User Verification (UV / PIN / biometric)
- Required for WebAuthn login, MFA, registration, and step-up.
- Resident keys are preferred, so username-first login remains compatible with
  non-discoverable FIDO2 credentials.
- Attestation defaults to `none`; ArborPress does not claim a manufacturer or
  model from an AAGUID without verified attestation.
- The login identifier resolves the account; only that account's credential IDs
  are returned in `allowCredentials` and accepted at completion.

### Step-up mechanism ("sudo mode")
Required for high-risk operations, for example:
- changing roles/permissions
- modifying authentication policies
- enabling/disabling federation
- plugin installation/enabling
- export generation
- key rotation
- security settings changes

Step-up uses WebAuthn with UV and is bound to the exact user, browser session,
action, and target. Grants are stored server-side, expire within five minutes,
and are atomically consumed once. An unregistered operation fails closed.

### Legacy passwords
- Implemented strictly as break-glass fallback.
- Disabled by default.
- Not visible in primary login flow.
- Can be fully disabled by policy.
- If enabled, must be clearly labeled: **"Legacy / Not Recommended"**.
- When usable WebAuthn or verified TOTP factors exist, password authentication
  requires one of them. Password-only recovery creates a restricted session
  that can only enroll a new WebAuthn credential.
- An administrator can explicitly revoke a user's WebAuthn credentials and
  active TOTP factors for authenticator recovery. This requires admin role,
  target-bound WebAuthn step-up, typed username confirmation, and a configured
  break-glass password for the target. It revokes the target's sessions and is
  audited; the next password login can only enroll a replacement credential.
- Password policy (min/max length, zxcvbn min score, HIBP check) is
  stored in the DB-backed `security` site_settings section and
  editable under `/admin/security`. The `[auth]` block in
  `config.toml` only seeds the bootstrap defaults.

### HIBP (Have I Been Pwned) password check
- Optional k-Anonymity lookup via the official Pwned Passwords API
  (only the first 5 SHA-1 hex chars are sent, no plaintext, no auth).
- Disabled by default; opt-in per deployment for privacy/GDPR review.
- Skipped for passwords generated by ArborPress itself.
- `hibp_fail_open` controls behaviour on API outage (default: accept,
  log warning).

### WebAuthn policy and RP-ID lock
- All WebAuthn relying-party parameters live in the DB-backed
  `webauthn` site_settings section (`/admin/webauthn`):
  - `user_verification`, `resident_key`, `attestation`,
    `authenticator_attachment` (W3C WebAuthn L3 §5.4.5–§5.4.7)
  - `algorithms` (COSE identifiers, RFC 9053; defaults `[-7, -257]`)
  - `timeout_ms`, `challenge_ttl_seconds`
  - `webauthn_credential_limit` (default 10; technical cap 100)
  - `conditional_ui_enabled`, `signal_api_enabled`,
    `require_2fa_after_passkey`, `require_mfa_after_sso`, `counter_strict`
- `rp.id` and `origin` are derived from `[web].base_url`
  (Punycode-encoded for IDN); `rp.name` from the general
  site title.
- **RP-ID lock** (W3C WebAuthn L3 §5.3): every credential is
  cryptographically bound to the `rp.id` it was registered under.
  A silent domain change would lock all users out, so ArborPress
  pins the last seen `rp.id` in the DB and refuses to issue
  registration/authentication options once a mismatch is detected
  in the presence of existing credentials.
- Recovery paths if a domain change is intentional:
  - Admin UI: `/admin/webauthn` shows the danger banner and
    requires the operator to retype the new `rp.id`.
  - CLI break-glass: `arborpress webauthn unlock-rp-id --confirm <new-rp-id>`
    for situations where no admin can authenticate.
- Confirmation is audited. Existing credential rows remain intact; users
  re-enroll against the new `rp.id` because the old keys are domain-bound.

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
- TOTP (SHA-256, 8 digits), with independent secrets and labels per device.
- TOTP enrollment stays pending until the user confirms a current code.
- Default TOTP limit is 5 per user (instance configurable, technical cap 50);
  HOTP and plugin MFA use independent limits.
- Pre-migration active TOTP secrets are retained with an `unknown` status. A
  valid current code proves possession and upgrades the status; until then they
  do not count as a recovery path for lockout checks.

### Credential removal and confirmation
- FIDO2 credentials and TOTP devices of the same user are equal alternatives;
  none is marked primary or backup. A credential's target and the fresh
  action/target/session-bound step-up determine the permitted operation.
- Removing a FIDO2 credential requires a one-shot WebAuthn step-up with
  successful user verification. With two usable FIDO2 credentials, the other
  one must confirm removal. The final usable FIDO2 credential is reserved for
  the existing authorized administrator recovery flow.
- TOTP removal accepts a fresh UV-verified WebAuthn step-up or a fresh TOTP
  step-up. With two usable TOTP devices, the other TOTP device must confirm;
  removing the final usable TOTP device requires WebAuthn. An account with a
  usable FIDO2 credential may remove its final TOTP device.
- Only persistent, active, confirmed TOTP devices count for removal policy.
  Pending enrollments and inactive or unconfirmed devices do not count.
  Credential counts and removal share a per-user database lock so concurrent
  removal requests cannot bypass the remaining-factor rules.
- Step-up grants record the authenticating method, assurance, and confirming
  credential/device identifier. Failed, blocked, successful, and consumed
  grants and credential removals use the shared ArborPress audit helper; audit
  details contain no authentication secrets.

### Auth state and sessions
- Short-lived WebAuthn ceremonies and pending TOTP enrollments are stored
  server-side, bound to purpose/user, and consumed once.
- All successful flows create the same `UserSession` record and store the auth
  method and assurance level (`webauthn_uv`, password plus WebAuthn/TOTP, SSO,
  or restricted recovery).
- SSO remains an OAuth/OIDC login path. When account or instance policy calls
  for extra MFA, the callback creates no session until WebAuthn or verified
  TOTP succeeds when the account or instance requires it; `sso_disabled` is
  still enforced. The `require_mfa_after_sso` instance setting controls the
  additional SSO check separately from WebAuthn user-verification policy.

### Database upgrade path
- `arborpress db migrate` (also run by the production container entrypoint)
  applies the repository's additive, idempotent schema upgrades for auth
  metadata, pending ceremonies, and step-up grants. Existing users, WebAuthn
  credentials, and OTP rows are retained. Legacy single-transport values are
  copied into the new transport list; historical UV and TOTP enrollment states
  are marked unknown. Legacy active TOTP remains usable after a correct code
  confirms possession. The migration runner is additive and versionless;
  deployments must run it before serving traffic.
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
  - `/admin/webauthn`
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
