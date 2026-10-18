from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from arborpress.backups.manifest import (
    CHECKSUMS_NAME,
    BackupComponent,
    BackupFile,
    BackupManifest,
    BackupVerificationError,
    checksum_line,
    parse_checksums,
    validate_relative_path,
)


def _manifest() -> BackupManifest:
    return BackupManifest(
        backup_id="20261018-120000",
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC).isoformat(),
        arborpress_version="0.1.0",
        python_version="3.14.8",
        database_system=None,
        alembic_revisions=(),
        consistency_mode="database-consistent; stable-file-reads",
        compression_backend="bz2",
        compression_profile="medium",
        compression_level=6,
        compression_threads=None,
        compression_block_size_bytes=None,
        components=(
            BackupComponent(
                "media",
                (
                    BackupFile(
                        "media/media-20261018-120000-0001.tar.bz2",
                        123,
                        "a" * 64,
                        "tar-pax+bz2",
                        456,
                        segment=1,
                        members=2,
                        member_paths=("cover.css", "images/logo.png"),
                    ),
                ),
            ),
        ),
        omitted_sensitive=("config/config.toml",),
        warnings=("No global filesystem snapshot is available.",),
    )


def test_manifest_toml_roundtrip_includes_component_file_metadata() -> None:
    manifest = _manifest()

    loaded = BackupManifest.from_toml(manifest.to_toml())

    assert loaded == manifest
    assert loaded.components[0].files[0].segment == 1
    assert "[[components.files]]" in manifest.to_toml()
    assert "secrets_included" not in manifest.to_toml()


def test_bz3_manifest_records_python_thread_and_block_configuration() -> None:
    manifest = replace(
        _manifest(),
        compression_backend="bz3",
        compression_profile="fast",
        compression_level=None,
        compression_threads=4,
        compression_block_size_bytes=500_000,
    )

    assert BackupManifest.from_toml(manifest.to_toml()) == manifest


@pytest.mark.parametrize("path", ["", "../outside", "/etc/passwd", "a\\b", "a/../b"])
def test_manifest_rejects_unsafe_relative_paths(path: str) -> None:
    with pytest.raises(BackupVerificationError):
        validate_relative_path(path)


@pytest.mark.parametrize("path", ["media/file\nother", "media/file\tname"])
def test_manifest_rejects_control_characters_in_paths(path: str) -> None:
    with pytest.raises(BackupVerificationError):
        validate_relative_path(path)


def test_checksum_file_roundtrip_and_rejects_duplicate_or_traversal() -> None:
    text = checksum_line("data/data-20261018-120000.tar.bz2", "b" * 64)

    assert parse_checksums(text) == {"data/data-20261018-120000.tar.bz2": "b" * 64}
    assert CHECKSUMS_NAME == "checksums.sha256"
    with pytest.raises(BackupVerificationError, match="Duplicate"):
        parse_checksums(text + text)
    with pytest.raises(BackupVerificationError, match="Unsafe"):
        parse_checksums("c" * 64 + "  ../escape\n")


def test_manifest_rejects_invalid_toml_and_unsupported_version() -> None:
    with pytest.raises(BackupVerificationError, match="Invalid backup manifest"):
        BackupManifest.from_toml("format_version = [")
    with pytest.raises(BackupVerificationError, match="Unsupported manifest version"):
        BackupManifest.from_toml("format_version = 3\n")
