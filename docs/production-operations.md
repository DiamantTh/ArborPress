# Production operations

Deploy a recorded full Git commit, never an ambiguous `latest` reference.
ArborPress has no product versions or release tags. Wheel version metadata is
an internal packaging sentinel. Record `arborpress.BUILD_SHA`, Alembic head,
artifact SHA-256, and the matching CI run with every deployment.

## Supported deployment paths

Use PostgreSQL 16+ or MariaDB 11.4+. SQLite is for development, tests and demos;
`doctor --production` treats it as a blocker.

For containers, build either `container/Containerfile.ubuntu` (Ubuntu 24.04) or
`container/Containerfile.almalinux` (AlmaLinux 10) from the recorded commit.
Pass `--build-arg BUILD_SHA=FULL_COMMIT_SHA` when building either image.
Persist `/home/arborpress/instance`, owned by UID/GID 1001. Supply secrets at
runtime, never as image build arguments. Set `ARBORPRESS_DB__URL`,
`ARBORPRESS_WEB__BASE_URL` and `ARBORPRESS_WEB__SECRET_KEY`. The entrypoint
upgrades the database and starts the Python server. Expose it only behind the
configured trusted HTTPS proxy. Back up the volume and database together.

For venv/systemd, create a dedicated unprivileged service account and a private
prefix such as `/srv/arborpress`. Install the verified wheel in a Python 3.14+
virtual environment using pip; neither Poetry nor Node is needed at runtime.
Keep configuration in `PREFIX/instance/config/config.toml`, use
`include = ["secrets.toml"]` for private operator secrets (mode 0600), and run:

```sh
arborpress --prefix /srv/arborpress db upgrade
arborpress --prefix /srv/arborpress serve
```

A systemd unit should use that absolute venv executable, `User=arborpress`,
`UMask=0077`, `Restart=on-failure`, and an explicit prefix. Restrict writable
paths to instance state; allow the configured DB and outbound services. Stop
all web and separate worker processes before restore. Embedded workers are
available; use existing mail, notification and federation worker CLIs when
separating workers. Never run two unrelated prefixes against the same DB.

## Identity and recovery

Complete the protected installation flow and register a second independent
administrator credential/recovery path before accepting traffic. A copied
synced passkey is not necessarily an independent recovery path. Test both.
Use account security to remove credentials only after testing an alternative.
WebAuthn RP-ID and origin are security identities: changing the domain does
not migrate existing authenticators. `arborpress webauthn status` diagnoses
the lock. Operator RP-ID unlock is an explicit domain recovery action, not a
way to make old credentials valid at another origin. Break-glass is optional;
if enabled, test it offline and keep recovery material outside the server.

Keep the matching database, `web.secret_key`, provider-secret ciphertext,
OIDC signing-key ciphertext, and `auth.actor_key_enc_key` together. Back up
secret configuration only in encrypted full backups, with the backup recovery
key stored separately. Loss of the application key makes encrypted OIDC
provider secrets/signing keys unusable. Loss of the actor KEK makes actor
private keys unusable. Do not replace missing material with newly generated
keys and claim identity recovery. Restore the correct key material or keep
the affected feature disabled and investigate. Never disable token/signature
validation to work around an unavailable provider.

## Updates, backup and rollback

1. Record the running SHA, database head and artifact checksum.
2. Create an encrypted full backup including secrets; run full cryptographic
   verification with its recovery key. See [backups](backups.md) for exact CLI
   options, restore plan and staging dry-run commands.
3. Test restoration in an isolated matching-backend environment and compare
   users/authentication, identities/keys, content/comments, media, settings,
   themes and plugins. A manifest's existence is not proof of verification.
4. Stop writers, deploy the exact new wheel/image, and run `db upgrade`.
5. Run `doctor --production --json`, liveness and readiness. Test independent
   administrator login and the enabled mail/federation paths.
6. If validation fails, keep traffic stopped. A code rollback is safe only if
   the old code supports the installed schema. Review each downgrade first;
   it can discard new tables/data. Prefer the verified pre-update restore
   when schema/data compatibility is uncertain.

Database commits and filesystem swaps are not one atomic transaction.
Restore uses a maintenance marker and journal. After an interrupted restore,
keep all writers stopped and use `arborpress restore recover --offline`.
An uncertain server-DB commit requires operator reconciliation; never delete
markers merely to resume traffic. Repeat the isolated dry run before recovery.

## Health and diagnosis

`/_health` is process liveness. `/_ready` requires completed installation,
current reachable schema and no restore marker/journal. Optional cache/search
failures degrade diagnostics; `[cache] required = true` and the search Site
Setting `required` make those services readiness requirements. Public health
responses omit credentials, URLs and detailed exceptions.

`arborpress doctor`, `doctor --production`, and `doctor --production --json`
report read-only diagnostics. Exit 0 means no detected blocker, not an
independent security certification. Warnings include absent backup-verification
evidence. The doctor does not decrypt or cryptographically verify backups.
The admin system status page exposes the same safe facts to administrators.
Worker presence is not inferred from queue rows or claimed as proven health.

Use [search/cache operations](search-cache.md) when available and the existing
`search reindex`, `cache status`, `cache purge`, `cache warm` commands. Search
queries authoritative DB rows; unavailable external adapters use the documented
DB fallback. Cache is optional and never an authorization source of truth.
L1 consistency is bounded by its maximum five-second TTL.

## HTTPS proxy and logging

Use one canonical HTTPS origin for WebAuthn, OIDC and ActivityPub. Never derive
identity from arbitrary Host/Forwarded headers. Restrict proxy hostnames, trust
only the real proxy hop count, and reject unknown hosts before forwarding.
Keep upload limits consistent with application limits and preserve WebSocket
upgrade support. Do not log callback query strings: codes and state appear in
OIDC callback URLs. In Nginx define an access format using `$uri`, not `$request`
or `$request_uri`; in Apache omit `%q` and use `%U` instead of `%r`. Disable
query logging in Traefik access logs. Do not log Authorization/Cookie headers.
Apply HSTS only on a correctly configured HTTPS host. Check proxy examples
against the actual topology rather than copying trust settings unchanged.

## Safe-to-deploy checklist

- [ ] Record exact SHA and matching successful mandatory CI evidence.
- [ ] Use a supported production DB and canonical HTTPS origin.
- [ ] Set independent secure secrets and private instance permissions.
- [ ] Confirm the expected Alembic head.
- [ ] Test two independent administrator login/recovery methods.
- [ ] Create encrypted backup, pass full cryptographic verify and restore dry run.
- [ ] Secure application secret and OIDC/OAuth/federation recovery material separately.
- [ ] Enable mail/federation only with validated configurations.
- [ ] Run production doctor without blockers and review every warning.
- [ ] Confirm liveness/readiness and exact installed BUILD_SHA.
- [ ] Record rollback/restore procedure and artifact checksums/SBOM.
