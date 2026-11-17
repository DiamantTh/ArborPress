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
properties = sbom.setdefault('metadata', {}).setdefault('properties', [])
properties[:] = [item for item in properties if item.get('name') != 'arborpress:build_sha']
properties.append({'name': 'arborpress:build_sha', 'value': commit})
sbom_path.write_text(json.dumps(sbom, indent=2) + '\n')
metadata = {
    'commit_sha': commit,
    'alembic_head': head,
    'lock_sha256': hashlib.sha256((root / 'poetry.lock').read_bytes()).hexdigest(),
    'approval': 'requires all CI and deployment-specific readiness gates',
}
(dist / 'BUILD-METADATA.json').write_text(json.dumps(metadata, indent=2) + '\n')
(dist / 'RELEASE-NOTES.md').write_text(
    f'# ArborPress build record\n\nCommit: `{commit}`\n\nAlembic head: `{head}`.\n\n'
    'This file records the source identity and schema head for the inspected build. '
    'Consult the commit history and current documentation for the exact changes, '
    'migration instructions, security boundaries, and known limits.\n\n'
    'Before updating, create and fully verify an encrypted backup. Follow '
    'docs/production-operations.md, docs/backups.md, and docs/migrations.md. '
    'Do not assume a database downgrade is safe without reviewing its data effects.\n\n'
    'Production approval requires all mandatory checks to pass for this exact commit, '
    'including supported server databases, backup/restore, container runtime, '
    'dependency audit, artifact validation, and a deployment-specific production doctor. '
    'Artifact generation alone is not approval.\n\n'
    'The commit SHA is the build identity. Wheel metadata is an internal packaging '
    'requirement and is not an ArborPress product version.\n'
)
files = sorted(p for p in dist.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
(dist / 'SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files
))
print(json.dumps(metadata, indent=2))
