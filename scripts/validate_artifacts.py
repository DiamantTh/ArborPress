"""Inspect package contents and produce commit-addressed release evidence."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from zipfile import ZipFile

from arborpress.core.migrations import _scripts

root = Path(__file__).resolve().parents[1]
git = shutil.which('git')
assert git is not None
commit = subprocess.check_output([git, 'rev-parse', 'HEAD'], cwd=root, text=True).strip() # noqa: S603
head = _scripts().get_current_head()
dist = root / 'dist'
wheel = next(dist.glob('*.whl'))
with ZipFile(wheel) as archive:
    names = archive.namelist()
    assert commit in archive.read('arborpress/_build_info.py').decode()
    assert 'arborpress/static/dist/.vite/manifest.json' in names
    assert any('/migrations/versions/' in name for name in names)
    assert any('/templates/' in name for name in names)
    for name in names:
        parts = Path(name).parts
        forbidden = {'.git', '.env', 'node_modules', 'secrets.toml', 'tests'}
        assert not any(p in forbidden for p in parts)
        assert not name.endswith(('.db', '.sqlite', '.key', '.pem'))
        assert b'-----BEGIN PRIVATE KEY-----' not in archive.read(name)
with tarfile.open(next(dist.glob('*.tar.gz'))) as source:
    for member in source.getmembers():
        parts = Path(member.name).parts
        assert not any(p in {'.git', '.env', 'node_modules', 'secrets.toml'} for p in parts)
        assert not member.name.endswith(('.db', '.sqlite', '.key', '.pem'))
sbom_path = dist / 'SBOM.cdx.json'
sbom = json.loads(sbom_path.read_text())
sbom.setdefault('metadata', {}).setdefault('properties', []).append(
    {'name': 'arborpress:build_sha', 'value': commit}
)
sbom_path.write_text(json.dumps(sbom, indent=2) + '\n')
metadata = {
    'commit_sha': commit,
    'alembic_head': head,
    'lock_sha256': hashlib.sha256((root / 'poetry.lock').read_bytes()).hexdigest(),
    'approval': 'requires all CI and deployment-specific readiness gates',
}
(dist / 'BUILD-METADATA.json').write_text(json.dumps(metadata, indent=2) + '\n')
(dist / 'RELEASE-NOTES.md').write_text(
    f'# ArborPress build {commit}\n\nAlembic head: `{head}`.\n\n'
    'Read-only production doctor, schema-aware readiness, strict lint and mypy regression '
    'gates, disposable server database recovery drills and container smoke gates.\n\n'
    'Before updating, create and fully verify an encrypted backup. Keep web.secret_key '
    'and the federation encryption key with the matching database. Follow '
    'docs/production-operations.md and docs/operational-readiness.md.\n\n'
    '## Breaking changes and migration\n\n'
    'No new schema revision is introduced by this operations work; upgrade to the recorded '
    'Alembic head before serving. PostgreSQL 16+ and MariaDB 11.4+ are production backends; '
    'SQLite remains development/demo/test only. Readiness now blocks uninstalled, stale-schema '
    'and restore-maintenance states. Optional services block only when configured required.\n\n'
    '## Security and identity\n\n'
    'Locked cryptography, Pillow, certifi and pyasn1 dependencies have been updated following '
    'advisory findings. Preserve web.secret_key, the matching database and actor-key encryption '
    'secret. OIDC/OAuth and ActivityPub identities must not be regenerated to mask key loss. '
    'Federation remains opt-in; no new C2S or remote vote behavior is introduced.\n\n'
    '## API, search and cache\n\n'
    'Existing /api/v1 public, bearer and admin contracts retain their authorization boundaries. '
    'Search uses authoritative public DB rows and documented native/LIKE fallback. External '
    'search adapters are not a complete remote-index implementation. Cache remains optional; '
    'L1 consistency is bounded by five seconds and purge remains instance-scoped.\n\n'
    '## Known limits and approval\n\n'
    'Inherited mypy debt is fingerprint-gated, not globally eliminated. Database and filesystem '
    'restore is not one atomic transaction. Full server-DB, Python 3.15 and container evidence '
    'must be attached to this exact commit before production approval. Consult the operational '
    'checklist and run production doctor on the actual deployment.\n\n'
    'This artifact is identified by its commit. Packaging metadata is not a product version. '
    'Artifact generation alone does not approve a deployment.\n'
)
files = sorted(p for p in dist.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
(dist / 'SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files
))
print(json.dumps(metadata, indent=2))
