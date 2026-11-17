from __future__ import annotations

import pytest
from typer.testing import CliRunner

from arborpress.cli.main import app


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["key", "generate", "example"], "no key was generated"),
        (["key", "import", "private.asc"], "no key was imported"),
        (["key", "rotate", "example"], "no key was rotated"),
    ],
)
def test_unimplemented_openpgp_key_operations_fail_closed(
    args: list[str], expected: str
) -> None:
    result = CliRunner().invoke(app, args)

    assert result.exit_code == 2
    assert expected in result.output
    assert "TODO" not in result.output


def test_key_status_is_documented_as_read_only() -> None:
    result = CliRunner().invoke(app, ["key", "--help"])

    assert result.exit_code == 0
    assert "OpenPGP key management is not implemented" in result.output
