# Abhängigkeiten, Lizenzen und Quellen

Stand: 2026-03-02

Diese Übersicht listet die **direkten** Abhängigkeiten aus `pyproject.toml` und `frontend/package.json`.
Angaben zu Lizenzen basieren auf den veröffentlichten Paketmetadaten bzw. den verlinkten Quell-Repositories.

## Python (Runtime)

| Paket | Bereich | Lizenz (SPDX) | Paketquelle | Quell-/Lizenzlink |
|---|---|---|---|---|
| quart | Runtime | MIT | https://pypi.org/project/Quart/ | https://github.com/pallets/quart |
| hypercorn | Runtime | MIT | https://pypi.org/project/hypercorn/ | https://github.com/pgjones/hypercorn |
| typer | Runtime | MIT | https://pypi.org/project/typer/ | https://github.com/fastapi/typer |
| sqlalchemy | Runtime | MIT | https://pypi.org/project/SQLAlchemy/ | https://github.com/sqlalchemy/sqlalchemy |
| asyncpg | Runtime | Apache-2.0 | https://pypi.org/project/asyncpg/ | https://github.com/MagicStack/asyncpg |
| aiomysql | Runtime | MIT | https://pypi.org/project/aiomysql/ | https://github.com/aio-libs/aiomysql |
| webauthn | Runtime | BSD-3-Clause | https://pypi.org/project/webauthn/ | https://github.com/duo-labs/py_webauthn |
| argon2-cffi | Runtime | MIT | https://pypi.org/project/argon2-cffi/ | https://github.com/hynek/argon2-cffi |
| pyotp | Runtime | MIT | https://pypi.org/project/pyotp/ | https://github.com/pyauth/pyotp |
| cryptography | Runtime | Apache-2.0 OR BSD-3-Clause | https://pypi.org/project/cryptography/ | https://github.com/pyca/cryptography |
| bleach | Runtime | Apache-2.0 | https://pypi.org/project/bleach/ | https://github.com/mozilla/bleach |
| python-slugify | Runtime | MIT | https://pypi.org/project/python-slugify/ | https://github.com/un33k/python-slugify |
| markdown-it-py | Runtime | MIT | https://pypi.org/project/markdown-it-py/ | https://github.com/executablebooks/markdown-it-py |
| pillow | Runtime | HPND | https://pypi.org/project/Pillow/ | https://github.com/python-pillow/Pillow |
| aiofiles | Runtime | Apache-2.0 | https://pypi.org/project/aiofiles/ | https://github.com/Tinche/aiofiles |
| aiosmtplib | Runtime | MIT | https://pypi.org/project/aiosmtplib/ | https://github.com/cole/aiosmtplib |
| limits | Runtime | MIT | https://pypi.org/project/limits/ | https://github.com/alisaifee/limits |
| httpx | Runtime + Dev | BSD-3-Clause | https://pypi.org/project/httpx/ | https://github.com/encode/httpx |
| tomllib (Backport) | Runtime (Py<3.11) | MIT | https://pypi.org/project/tomllib/ | https://github.com/hukkin/tomli |
| pydantic | Runtime | MIT | https://pypi.org/project/pydantic/ | https://github.com/pydantic/pydantic |
| pydantic-settings | Runtime | MIT | https://pypi.org/project/pydantic-settings/ | https://github.com/pydantic/pydantic-settings |
| packaging | Runtime | Apache-2.0 OR BSD-2-Clause | https://pypi.org/project/packaging/ | https://github.com/pypa/packaging |
| alembic | Runtime | MIT | https://pypi.org/project/alembic/ | https://github.com/sqlalchemy/alembic |

## Python (Development)

| Paket | Bereich | Lizenz (SPDX) | Paketquelle | Quell-/Lizenzlink |
|---|---|---|---|---|
| pytest | Dev | MIT | https://pypi.org/project/pytest/ | https://github.com/pytest-dev/pytest |
| pytest-asyncio | Dev | Apache-2.0 | https://pypi.org/project/pytest-asyncio/ | https://github.com/pytest-dev/pytest-asyncio |
| aiosqlite | Dev | MIT | https://pypi.org/project/aiosqlite/ | https://github.com/omnilib/aiosqlite |
| ruff | Dev | MIT | https://pypi.org/project/ruff/ | https://github.com/astral-sh/ruff |
| mypy | Dev | MIT | https://pypi.org/project/mypy/ | https://github.com/python/mypy |

## Frontend (npm)

| Paket | Bereich | Lizenz (SPDX) | Paketquelle | Quell-/Lizenzlink |
|---|---|---|---|---|
| @simplewebauthn/browser | Runtime | MIT | https://www.npmjs.com/package/@simplewebauthn/browser | https://github.com/MasterKale/SimpleWebAuthn |
| @sveltejs/adapter-static | Dev | MIT | https://www.npmjs.com/package/@sveltejs/adapter-static | https://github.com/sveltejs/kit |
| @sveltejs/kit | Dev | MIT | https://www.npmjs.com/package/@sveltejs/kit | https://github.com/sveltejs/kit |
| @sveltejs/vite-plugin-svelte | Dev | MIT | https://www.npmjs.com/package/@sveltejs/vite-plugin-svelte | https://github.com/sveltejs/vite-plugin-svelte |
| eslint | Dev | MIT | https://www.npmjs.com/package/eslint | https://github.com/eslint/eslint |
| eslint-config-prettier | Dev | MIT | https://www.npmjs.com/package/eslint-config-prettier | https://github.com/prettier/eslint-config-prettier |
| eslint-plugin-svelte | Dev | MIT | https://www.npmjs.com/package/eslint-plugin-svelte | https://github.com/sveltejs/eslint-plugin-svelte |
| prettier | Dev | MIT | https://www.npmjs.com/package/prettier | https://github.com/prettier/prettier |
| prettier-plugin-svelte | Dev | MIT | https://www.npmjs.com/package/prettier-plugin-svelte | https://github.com/sveltejs/prettier-plugin-svelte |
| svelte | Dev | MIT | https://www.npmjs.com/package/svelte | https://github.com/sveltejs/svelte |
| svelte-check | Dev | MIT | https://www.npmjs.com/package/svelte-check | https://github.com/sveltejs/language-tools |
| tslib | Dev | 0BSD | https://www.npmjs.com/package/tslib | https://github.com/microsoft/tslib |
| typescript | Dev | Apache-2.0 | https://www.npmjs.com/package/typescript | https://github.com/microsoft/TypeScript |
| vite | Dev | MIT | https://www.npmjs.com/package/vite | https://github.com/vitejs/vite |

## Projektlizenz

- Hauptprojekt: GNU Affero General Public License v3.0 oder später (AGPL-3.0-or-later)
- Volltext: siehe `LICENSE` im Projekt-Root
