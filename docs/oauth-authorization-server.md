# ArborPress OAuth 2.0 / OpenID Connect Provider

ArborPress can act as an OAuth 2.0 authorization server and OpenID Connect
provider. It is disabled until an administrator enables it in Admin → OAuth
Server. The issuer is the configured canonical `web.base_url`; it is never
derived from Host or forwarded request headers. Production issuers must be
HTTPS. Once initialized, changing that URL fails closed because it changes the
issuer identity. There is no issuer migration UI.

## Clients and authorization

Administrators register clients at the admin page. Redirect URIs are exact
matches, with no wildcard support. HTTP is accepted only for loopback client
development. Public clients have no secret and must use Authorization Code
with PKCE S256. Confidential client secrets are generated randomly, stored as
SHA-256 digests, and displayed only on creation or rotation. PKCE is required
for both client types. Implicit and Resource Owner Password grants are not
implemented. Dynamic client registration and client credentials are not
implemented.

The authorization endpoint requires an active ArborPress browser session and
shows an explicit consent page when the client asks for new scopes. If the user
is not signed in, the flow resumes after the local password, SSO, or MFA login.
Authorization codes expire after three
minutes, are single-use, and are stored only as hashes. Authorization requests
must provide state, a PKCE S256 challenge, and nonce when requesting `openid`.

## Scopes and API

Registered scope names are `openid`, `profile`, `posts:read`, `posts:write`,
`comments:read`, `comments:write`, `media:read`, and `media:write`. Current
resource endpoints are deliberately small: `/api/v1/oauth/me` requires
`profile`; `/api/v1/oauth/posts` requires `posts:read` and returns only public,
published posts. `/oauth/userinfo` requires `openid` and returns only OIDC
claims permitted by the granted `profile` scope. Other named scopes do not
create an API or confer access by themselves. No administrator scope exists.

Resource APIs use opaque short-lived bearer access tokens. Token plaintext is
returned once and only its SHA-256 digest is stored. Refresh tokens are also
stored as digests, rotate on use, and reuse revokes the entire family. Users
can revoke grants at `/account/authorized-apps`; client disable and grant
revocation invalidate token families. Refresh tokens have a 30-day lifetime
and each family has a 90-day absolute lifetime. Access tokens last eight
minutes. Secret rotation invalidates outstanding codes and token families.

OAuth scope is only an additional limit: any future private/write operation
must also pass ArborPress local RBAC and object-level/ReBAC policy. Public post
listing is limited to published public objects. Browser session routes remain
cookie-authenticated and CSRF-protected; bearer APIs do not treat cookies as
credentials.

## OIDC identity and signing

The provider publishes `/.well-known/openid-configuration`, `/oauth/jwks`,
`/oauth/token`, and `/oauth/userinfo`. ID Tokens use RS256 and nonce. Subject
values are random immutable per-user identifiers stored in `oidc_subjects`;
username and email changes do not change `sub`. Signing keys are separate from
ActivityPub keys. Private RSA keys are Fernet-encrypted in the database with a
purpose-derived key from `web.secret_key`; therefore encrypted database
backups must include the matching protected configuration secret. The private
material is never displayed or exported. Administrators can rotate keys after
step-up; the previous public key remains in JWKS for 24 hours, while new tokens
use only the new current key.

## Operational boundaries

OAuth clients, grants, codes, token families, token digests, OIDC subjects,
and signing keys are instance-local database state. Restore the database and
the same `web.secret_key` together. Treat the secret key as a required backup
secret. Do not change the canonical issuer without a planned identity
migration. This implementation does not provide dynamic registration,
client-credentials, device, implicit, password, SAML, LDAP, CAS, or a broad
general-purpose API.
