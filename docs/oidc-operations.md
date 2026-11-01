# OIDC provider and identity operations

ArborPress uses its configured OIDC providers only for sign-in. Stable external
identity is the exact `(issuer, subject)` pair from a cryptographically verified
ID token. Email, username, display name, and provider role claims are not identity
proof and never link an existing local account.

## Provider lifecycle

An optional `[sso.providers.<id>]` section in the initial config is imported once
into the instance database when the provider catalog is first accessed. The
database is authoritative afterwards. Administrators use **Admin → OIDC
Providers** to create or edit a provider, enable/disable it, inspect discovery and
JWKS health, or rotate its client secret. The page is server-rendered and all
changes require the existing admin role, CSRF protection, and action-scoped local
step-up.

Provider IDs are stable. Providers with linked identities cannot be physically
deleted, and an issuer cannot be changed while identities are linked. Disable a
provider to stop new login and linking while retaining the identity records. Do
not change an issuer to recover from an IdP incident: repair discovery, JWKS, or
the client registration at the configured issuer instead.

Client secrets are encrypted at rest with Fernet using a purpose-separated key
derived from `web.secret_key`. The secret is accepted only through the dedicated
rotation form, is never shown again, and is omitted from audit events and
diagnostics. Preserve `web.secret_key` in protected backups. If it is lost or
changed without decrypting and re-encrypting provider secrets first, those saved
secrets cannot be recovered; rotate each affected provider secret after restoring
the key or through a separately configured recovery path. Never disable TLS,
signature, issuer, audience, nonce, or JWKS validation to recover a provider.

Use **Discovery and JWKS prüfen** to check the public HTTPS metadata and key set.
This is a diagnostic, not a trust override. ArborPress rejects private/loopback
addresses, unsafe redirects, oversized responses, and issuer mismatches. During
normal login, an unknown signing key ID triggers at most one bounded JWKS refresh.
For a provider outage, use a different currently usable local login method or
restore the IdP. An administrator can disable the provider without deleting
users' identities.

## Link and unlink identities

Users manage links under **Account Security**. Linking requires an active local
session, a provider-specific step-up, and a fresh OIDC code flow using state,
nonce, PKCE S256, and the configured issuer. The user must then confirm the link
on an ArborPress page. A provider identity already owned by any account is
rejected without disclosing which account owns it. No merge operation exists.

Unlinking is an owner-only CSRF-protected action requiring a fresh step-up. The
shared login-method resolver checks usable UV-capable WebAuthn credentials,
enabled break-glass/password recovery paths and their MFA requirements, and
enabled OIDC identities allowed by the local account policy. TOTP is a second
factor, not a standalone login method. The last usable login/recovery path cannot
be removed. Add and verify another method before unlinking an identity if it is
the only remaining path.

An inactive account or an account with `sso_disabled` cannot use OIDC login or
linking. Disabling a provider does not erase links, but they no longer count as
usable paths until that provider is enabled again.

## Diagnostics and privacy

The admin provider page shows discovery/JWKS health, last check and last success,
the linked-identity count, and daily UTC failure counts for the last 30 days.
Failure classes come from a fixed allowlist. Aggregates contain no IP address,
subject, email, username, session ID, token, authorization code, or header. Old
daily aggregates are pruned after 30 days; identity relations and audit history
are not part of this retention policy.

Audit records cover link/unlink, provider create/update, enable/disable, health
checks, and secret rotation. They record provider identifiers and outcomes, never
secret values or token/profile claims. Reverse proxies should redact the OIDC
callback query string because the authorization code and state use standard
query parameters.

## Initial configuration

The commented `[sso.providers.*]` example in `config/config.example.toml` is an
optional first-boot import. Keep initial client secrets in an included secrets
file with restrictive permissions. Once imported, update the provider through
the admin interface; later edits to TOML do not overwrite the database catalog.
Legacy `auto_link_by_email` and remote `role_mapping` options are ignored. New
accounts may only be created when `auto_create` is explicitly enabled; they are
assigned the local `viewer` role and are never selected by matching another
account's email or username.
