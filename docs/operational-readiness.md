# Operational readiness gates

ArborPress does not publish product version numbers or version tags. Every
operational assessment is attached to an immutable 40-character Git commit
SHA, its branch and published mirror state. A release decision records the
Alembic head, CI result, test counts, database matrix, security gates,
backup/restore evidence, build artifact identity, and deployment configuration.

## Required evidence

- Confirm the source SHA and that `origin/master` and the public mirror point
  to the same commit.
- Record the Alembic head and run fresh-install and supported upgrade paths.
- Run the complete test suite and required static checks; record skipped tests.
- Exercise supported database backends and backup/restore on the deployment
  topology.
- Review open security findings and verify the security-sensitive regression
  suites.
- Build a wheel whose embedded build SHA matches the source commit; smoke-test
  installation and CLI startup in an isolated environment. Use
  `poetry run python scripts/build_package.py`; plain `poetry build` remains a
  metadata/buildability check and carries the neutral `unknown` source marker.
- Record container/runtime checks and the exact deployment artifact checksum.

These gates describe evidence for an operational decision. They do not create
a product version sequence, guarantee compatibility for arbitrary external
extensions, or replace a deployment-specific recovery plan.

## Mandatory CI and deployment decision

The CI matrix retains Python 3.14/3.15 and Node 24, enforces global Ruff and a
committed mypy regression baseline, and adds disposable PostgreSQL/MariaDB
migration/recovery jobs and Ubuntu/AlmaLinux container smoke jobs. Artifact
publication depends on those jobs, a locked dependency audit, CycloneDX SBOM,
artifact inspection and checksums. A job definition is not passing evidence.

Use [production operations and safe-to-deploy checklist](production-operations.md).
Record each mandatory gate as passed, failed, or not executed, linking its
actual run. Withhold production approval when any mandatory gate lacks proof.
`doctor --production` is necessary operational evidence, not a replacement for
CI, cryptographic verification, restore drills or independent security review.
