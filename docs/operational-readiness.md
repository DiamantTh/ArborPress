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
  installation and CLI startup in an isolated environment.
- Record container/runtime checks and the exact deployment artifact checksum.

These gates describe evidence for an operational decision. They do not create
a product version sequence, guarantee compatibility for arbitrary external
extensions, or replace a deployment-specific recovery plan.
