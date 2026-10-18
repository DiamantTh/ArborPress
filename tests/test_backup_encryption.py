from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from arborpress.backups.compression import CompressionSettings
from arborpress.backups.encryption import (
    BackupKey,
    EncryptionError,
    context_from_manifest,
    create_encryption_context,
    decrypt_file_to_path,
    encrypt_file,
    generate_keyfile,
    load_keyfile,
    parse_envelope_header,
    verify_envelope_header,
)
from arborpress.backups.service import create_backup
from arborpress.backups.verify import verify_backup_set
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


def test_component_envelope_stream_roundtrip_and_authenticated_context(tmp_path: Path) -> None:
    source = tmp_path / "compressed.bin"
    source.write_bytes(os.urandom(131_072))
    encrypted = tmp_path / "component.apenc"
    decrypted = tmp_path / "decrypted.bin"
    key = BackupKey("passphrase", b"correct horse battery staple")
    context = create_encryption_context(key)

    digest, size, nonce = encrypt_file(
        source,
        encrypted,
        context=context,
        backup_id="20261018-120000",
        relative_path="media/chunk.tar.bz2.apenc",
        manifest_version=2,
    )
    verify_envelope_header(encrypted)
    assert len(nonce) == 12
    assert encrypted.stat().st_size == size
    assert len(digest) == 64
    decrypt_file_to_path(
        encrypted,
        decrypted,
        context=context,
        backup_id="20261018-120000",
        relative_path="media/chunk.tar.bz2.apenc",
        manifest_version=2,
    )
    assert decrypted.read_bytes() == source.read_bytes()

    mismatched = tmp_path / "mismatched.bin"
    with pytest.raises(EncryptionError, match="authentication"):
        decrypt_file_to_path(
            encrypted,
            mismatched,
            context=context,
            backup_id="20261018-120000",
            relative_path="data/chunk.tar.bz2.apenc",
            manifest_version=2,
        )
    assert not mismatched.exists()


def test_component_ciphertext_tampering_and_wrong_key_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"compressed payload" * 100)
    encrypted = tmp_path / "cipher.apenc"
    key = BackupKey("passphrase", b"correct horse battery staple")
    context = create_encryption_context(key)
    encrypt_file(
        source,
        encrypted,
        context=context,
        backup_id="20261018-120000",
        relative_path="data/payload.apenc",
        manifest_version=2,
    )

    damaged = bytearray(encrypted.read_bytes())
    damaged[-20] ^= 0x40
    encrypted.write_bytes(damaged)
    with pytest.raises(EncryptionError, match="authentication"):
        decrypt_file_to_path(
            encrypted,
            tmp_path / "damaged.out",
            context=context,
            backup_id="20261018-120000",
            relative_path="data/payload.apenc",
            manifest_version=2,
        )

    intact = tmp_path / "intact.apenc"
    encrypt_file(
        source,
        intact,
        context=context,
        backup_id="20261018-120000",
        relative_path="data/payload.apenc",
        manifest_version=2,
    )
    wrong = create_encryption_context(BackupKey("passphrase", b"wrong passphrase"))
    with pytest.raises(EncryptionError, match="authentication"):
        decrypt_file_to_path(
            intact,
            tmp_path / "wrong.out",
            context=wrong,
            backup_id="20261018-120000",
            relative_path="data/payload.apenc",
            manifest_version=2,
        )


def test_keyfile_generation_format_permissions_and_collision(tmp_path: Path) -> None:
    path = tmp_path / "backup.key"
    generate_keyfile(path)
    loaded = load_keyfile(path)
    assert loaded.source == "keyfile"
    assert len(loaded.material) == 32
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        generate_keyfile(path)
    previous = loaded.material
    generate_keyfile(path, overwrite=True)
    assert load_keyfile(path).material != previous
    source = tmp_path / "payload"
    source.write_bytes(b"keyfile encrypted stream")
    encrypted = tmp_path / "payload.apenc"
    context = create_encryption_context(loaded)
    encrypt_file(
        source,
        encrypted,
        context=context,
        backup_id="20261018-120000",
        relative_path="data/payload.apenc",
        manifest_version=2,
    )
    decrypted = tmp_path / "decrypted"
    decrypt_file_to_path(
        encrypted,
        decrypted,
        context=context,
        backup_id="20261018-120000",
        relative_path="data/payload.apenc",
        manifest_version=2,
    )
    assert decrypted.read_bytes() == source.read_bytes()
    wrong = context_from_manifest(
        BackupKey("keyfile", os.urandom(32)), context.parameters
    )
    with pytest.raises(EncryptionError, match="authentication"):
        decrypt_file_to_path(
            encrypted,
            tmp_path / "wrong-keyfile.out",
            context=wrong,
            backup_id="20261018-120000",
            relative_path="data/payload.apenc",
            manifest_version=2,
        )


def test_nonce_is_unique_for_multiple_component_files(tmp_path: Path) -> None:
    key = BackupKey("passphrase", b"correct horse battery staple")
    context = create_encryption_context(key)
    nonces: set[bytes] = set()
    for index in range(16):
        source = tmp_path / f"source-{index}"
        source.write_bytes(f"payload {index}".encode())
        _digest, _size, nonce = encrypt_file(
            source,
            tmp_path / f"component-{index}.apenc",
            context=context,
            backup_id="20261018-120000",
            relative_path=f"media/component-{index}.apenc",
            manifest_version=2,
        )
        nonces.add(nonce)
    assert len(nonces) == 16


@pytest.mark.asyncio
async def test_encrypted_backup_authenticates_manifest_and_secret_policy(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    config_contents = 'secret_key = "do-not-expose-this-value"\n'
    (paths.config / "config.toml").write_text(config_contents, encoding="utf-8")
    (paths.config / ".installed").write_text("yes\n", encoding="utf-8")
    (paths.media / "image.bin").write_bytes(b"media payload")
    key = BackupKey("passphrase", b"safe local recovery key")

    backup = await create_backup(
        paths=paths,
        components=("config", "media"),
        key=key,
        include_secrets=True,
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    assert backup.manifest.encryption == "aes-256-gcm"
    assert backup.manifest.secrets_included is True
    assert backup.manifest.omitted_sensitive == ()
    assert (backup.directory / "manifest.auth").is_file()
    assert "do-not-expose-this-value" not in (backup.directory / "manifest.toml").read_text()
    component = next(item for item in backup.manifest.components if item.name == "config")
    encrypted_file = backup.directory / component.files[0].path
    assert encrypted_file.suffix == ".apenc"
    assert b"do-not-expose-this-value" not in encrypted_file.read_bytes()

    structural = verify_backup_set(backup.directory)
    assert structural.verification_level == "structural-only"
    full = verify_backup_set(backup.directory, key=key)
    assert full.verification_level == "full-cryptographic"

    wrong_key = BackupKey("passphrase", b"not the right passphrase")
    with pytest.raises(ValueError, match="authentication failed"):
        verify_backup_set(backup.directory, key=wrong_key)

    manifest_path = backup.directory / "manifest.toml"
    original = manifest_path.read_bytes()
    manifest_path.write_bytes(
        original.replace(b"secrets_included = true", b"secrets_included = false")
    )
    with pytest.raises(ValueError, match="authentication failed"):
        verify_backup_set(backup.directory, key=key)


@pytest.mark.asyncio
async def test_unencrypted_backup_rejects_secret_inclusion_and_omits_config(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.config / "secrets.toml").write_text("secret = true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="requires --encrypt"):
        await create_backup(paths=paths, components=("config",), include_secrets=True)

    backup = await create_backup(
        paths=paths,
        components=("config",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    assert backup.manifest.secrets_included is False
    assert backup.manifest.omitted_sensitive == ("config/secrets.toml",)


@pytest.mark.asyncio
async def test_keyfile_inside_included_config_is_rejected(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    keyfile = paths.config / "backup.apkey"
    generate_keyfile(keyfile)
    with pytest.raises(ValueError, match="cannot be stored inside"):
        await create_backup(
            paths=paths,
            components=("config",),
            key=load_keyfile(keyfile),
            include_secrets=True,
            keyfile_path=keyfile,
        )


@pytest.mark.asyncio
async def test_encrypted_bz3_backup_when_optional_backend_is_installed(tmp_path: Path) -> None:
    pytest.importorskip("bz3")
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.media / "image.bin").write_bytes(b"optional bzip3 encrypted component")
    backup = await create_backup(
        paths=paths,
        components=("media",),
        compression=CompressionSettings(backend="bz3"),
        key=BackupKey("passphrase", b"optional bzip3 recovery phrase"),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    assert (
        verify_backup_set(
            backup.directory, key=BackupKey("passphrase", b"optional bzip3 recovery phrase")
        ).verification_level
        == "full-cryptographic"
    )


@pytest.mark.asyncio
async def test_each_encrypted_media_segment_has_its_own_authenticated_envelope(
    tmp_path: Path,
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.media / "first.bin").write_bytes(b"1234")
    (paths.media / "second.bin").write_bytes(b"5678")
    key = BackupKey("passphrase", b"segmented media encryption phrase")
    backup = await create_backup(
        paths=paths,
        components=("media",),
        key=key,
        media_segment_size=5,
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    media = next(component for component in backup.manifest.components if component.name == "media")
    assert [item.segment for item in media.files] == [1, 2]
    nonces = set()
    for item in media.files:
        with (backup.directory / item.path).open("rb") as stream:
            version, algorithm, nonce = parse_envelope_header(stream)
        assert (version, algorithm) == (1, 1)
        nonces.add(nonce)
    assert len(nonces) == 2
    assert verify_backup_set(backup.directory, key=key).verification_level == "full-cryptographic"
