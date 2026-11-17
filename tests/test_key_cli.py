from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from typer.testing import CliRunner

from arborpress.cli.main import app


def _material(fingerprint: str) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "openpgp_user_id": f"ArborPress <{fingerprint.lower()}@example.invalid>",
        "algorithm": "EdDSA-255",
        "public_key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\npublic\n",
        "private_key": b"protected secret test bytes",
        "passphrase": b"random test passphrase",
        "expires_at": None,
    }


def test_key_cli_exposes_functional_openpgp_commands() -> None:
    result = CliRunner().invoke(app, ["key", "--help"])

    assert result.exit_code == 0
    for command in ("generate", "import", "rotate", "status"):
        assert command in result.output
    assert "not implemented" not in result.output.lower()


def test_key_cli_generate_import_rotate_and_status(
    test_engine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import arborpress.mail.openpgp as openpgp
    from arborpress.core import db as db_module
    from arborpress.models.mail import InstanceOpenPGPKey

    db_module._engine = test_engine
    db_module._session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    materials = iter(
        [
            _material("A" * 40),
            _material("B" * 40),
            _material("C" * 40),
        ]
    )
    monkeypatch.setattr(openpgp, "create_instance_key_material", lambda _user_id: next(materials))
    monkeypatch.setattr(
        openpgp,
        "import_instance_key_material",
        lambda _raw, _passphrase: _material("C" * 40),
    )
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "test-passphrase")

    runner = CliRunner()
    generated = runner.invoke(app, ["key", "generate", "test-instance"])
    assert generated.exit_code == 0, generated.output
    assert "generated and activated" in generated.output

    rotated = runner.invoke(app, ["key", "rotate", "test-instance"])
    assert rotated.exit_code == 0, rotated.output
    assert "rotated" in rotated.output

    key_file = tmp_path / "import.asc"
    key_file.write_text("synthetic protected test key", encoding="ascii")
    imported = runner.invoke(
        app, ["key", "import", str(key_file), "--passphrase-prompt"]
    )
    assert imported.exit_code == 0, imported.output
    assert "imported and activated" in imported.output

    status = runner.invoke(app, ["key", "status"])
    assert status.exit_code == 0, status.output
    assert "Instance OpenPGP mail-signing keys" in status.output
    assert "C" * 40 in status.output

    async def read_rows() -> list[InstanceOpenPGPKey]:
        async with db_module.get_session_factory()() as db:
            return list(
                (await db.execute(select(InstanceOpenPGPKey))).scalars().all()
            )

    import asyncio

    rows = asyncio.run(read_rows())
    assert len(rows) == 3
    assert sum(row.is_current for row in rows) == 1
    assert next(row for row in rows if row.is_current).fingerprint == "C" * 40
