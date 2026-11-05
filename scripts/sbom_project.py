"""Emit PEP 621 root metadata without the legacy Poetry package configuration."""
import json
import tomllib
from pathlib import Path

project = tomllib.loads(Path('pyproject.toml').read_text())['project']
print('[project]')
for field in ('name', 'version', 'description', 'license'):
    print(f'{field} = {json.dumps(project[field])}')
