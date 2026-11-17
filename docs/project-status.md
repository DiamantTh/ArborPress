# Product status and verification map

This page is the concise map of implemented ArborPress capabilities and the
evidence needed to assess a particular checkout. It does not grant production
approval: use the exact commit SHA, its Alembic head, executed test/CI results,
and deployment-specific recovery evidence. There are no product version
numbers or release tags.

## Implemented product areas

- Server-rendered publishing for posts and pages, author/object permissions,
  media validation, comments and moderation, revisions, tags, search, feeds,
  canonical URLs, language prefixes, translation groups and slug history.
- Username-first WebAuthn/FIDO2 login with persistent per-account random user
  handles, multiple credentials, MFA, target-bound step-up, controlled account
  recovery and optional restricted legacy-password break-glass.
- OIDC relying-party login with issuer/subject external identities, account
  linking lifecycle and MFA policy; ArborPress OAuth2/OIDC provider, client
  grants, PKCE and scoped resource API.
- Optional ActivityPub federation with actor identity, signed inbound/outbound
  processing, follows, posts and moderated comments. Federation remains
  disabled by default and does not include client-to-server API or Like/Vote
  mapping.
- Portable editorial transfer as a separate bounded ZIP/JSONL format, plus a
  distinct encrypted full-instance backup/verify/restore path.
- Controlled plugin and theme contracts, SSR administration, operational
  doctor, health/readiness, cache/search diagnostics and CLI operations.

## Deliberate boundaries and known limits

- WebAuthn login is username-first; discoverable/username-less login is not an
  implemented or required workflow. The user handle is an account selector,
  not authentication proof.
- Portable import verifies and preflights a bounded package (512 MiB total and
  250,000 structured records); full relational preflight retains bounded record
  data in memory. Split larger migrations and run dry-run first.
- Database and filesystem writes cannot share one atomic transaction. Import
  stages files and cleans up on ordinary failures; recovery after host crash
  follows the documented journal/maintenance procedures.
- OpenPGP mail signing/encryption and OpenPGP private-key lifecycle are not
  implemented. Legacy `arborpress key generate/import/rotate` commands fail
  explicitly and do not access key material. Federation and OIDC signing keys
  use separate implemented systems.
- PostgreSQL 16+ and MariaDB 11.4+ are supported production databases; SQLite
  is for development, tests and demos. External search/cache adapters are
  optional and do not replace authoritative database visibility checks.

## Verification entry points

- `docs/operational-readiness.md` defines evidence gates and decision policy.
- `docs/production-operations.md` defines deployment, recovery and
  safe-to-deploy operations.
- `docs/content-portability.md`, `docs/backups.md`, `docs/migrations.md`,
  `docs/search-cache.md`, `docs/activitypub.md`, `docs/oidc-operations.md`,
  `docs/oauth-authorization-server.md`, and `docs/themes.md` document their
  respective contracts and limits.
- `.github/workflows/ci.yml` defines reproducible CI jobs; a configured job is
  not evidence that it passed. Production readiness remains **not approved**
  until every mandatory gate is evidenced for the exact deployed commit.
