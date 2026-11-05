# ArborPress security and release evidence

Assessment: **PRODUCTION READINESS NOT APPROVED** until all mandatory gates
for the exact deployed commit have passed. This replaces the historical
unsupported blanket production-readiness claim. ArborPress has no public
product version and creates no release tags.

## Evidence and scope

Security boundaries reside in the existing authentication/session/step-up,
permission/ReBAC, OIDC RP/provider, OAuth resource, federation fetch/signature,
comment moderation, mail/outbox, theme sandbox and plugin capability services.
Their regression tests are required by `.github/workflows/ci.yml`; passing
unit tests is not a standards certification or an independent penetration test.

Phase 12C adds read-only operational diagnostics, schema/restore-aware
readiness, required-service policy and server-database/container CI drills.
The source of operational truth is the commit SHA, Alembic head, lockfile,
CI evidence and deployment configuration. Public health responses omit DSNs,
secret values and exception details. Admin diagnostics require administrator
access. Doctor never repairs state or verifies backups implicitly.

## Mandatory security gates

- Full Python 3.14 and 3.15 regression suites, including Auth, OIDC/OAuth,
  CSRF/step-up, ReBAC, federation ownership/SSRF and HTML sanitization.
- Ruff without findings; strict operational-module mypy and explicit inherited
  global mypy baseline. Existing type debt is not evidence of exploitability,
  but remains maintenance risk and may not silently grow.
- Advisory audit of exact locked main/optional-runtime dependencies. Tooling
  is build-only. No blanket ignored CVEs or validation bypasses.
- Disposable PostgreSQL/MariaDB fresh/upgrade and cryptographic backup/restore
  evidence; SQLite is development/demo/test only.
- Ubuntu and AlmaLinux image build/start/migration/non-root/health/shutdown.
- Inspected wheel/sdist, commit metadata, CycloneDX SBOM and SHA-256 checksums.
- Deployment-specific production doctor without blockers and reviewed warnings,
  verified encrypted backup plus isolated restore, two independent admin login
  or recovery paths, correct HTTPS proxy trust and callback-log redaction.

## Recovery boundaries

Database and filesystem restore is not globally atomic. Maintenance markers and
journals deliberately fail closed; uncertain DB commits require investigation.
Preserve the matching `web.secret_key`, encrypted OIDC provider secrets and
signing keys, actor encryption key and database. Key loss must not silently
regenerate a different identity. See [production operations](docs/production-operations.md),
[backups](docs/backups.md) and [migrations](docs/migrations.md).

## Remaining assurance limits

Local availability of Python 3.15, PostgreSQL, MariaDB and container runtimes
must be recorded separately from CI coverage. Configuring a CI job does not
prove it passed. Production approval stays withheld while a mandatory gate is
unexecuted or failed. Optional external search adapters currently provide DB
fallback, not a complete remote-index synchronization implementation; see
[search/cache](docs/search-cache.md). No generic OAuth admin scope or remote
federation vote mapping exists. C2S ActivityPub, dynamic OAuth client registration
and linked-data signature execution remain outside the supported contract.

Audit tools find known dependency advisories, not all application defects.
Review deployment-specific exposure and maintain locked security updates.
Report suspected vulnerabilities privately to the repository maintainer; avoid
posting tokens, private keys, callback codes, DB dumps or user data in issues.

## Historical findings reconciled

Older recommendations to upgrade cryptography beyond 45, WebAuthn beyond 2.6,
Pydantic beyond 2.11 and Bleach beyond 6.3 are superseded by the current lock.
Encrypted backup, SBOM generation and advisory scanning now have executable
paths. Historical requests for sqlmap, 100-credential load tests, external
penetration testing, fuzzing, immutable remote audit storage, centralized log
forwarding and real-time alerting are not silently marked complete: independent
assurance and deployment-specific operational controls remain to be established.
They are not, by themselves, demonstrated exploitable application defects.
No blanket certification of all WebAuthn flags or every protocol standard is
made. Hardware authenticator support is already part of WebAuthn; actual
recovery independence must be checked on the deployment. Optional CSP/WAF
hardening and host-level encryption require topology-specific review.
