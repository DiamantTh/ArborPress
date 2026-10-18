"""Versioned, component-level authenticated encryption for backup sets."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import os
import stat
import struct
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ENVELOPE_MAGIC = b"APENC\r\n\x1a"
ENVELOPE_VERSION = 1
ENVELOPE_ALGORITHM_AES_256_GCM = 1
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
ENVELOPE_HEADER = struct.Struct(">8sBB12s")
KEYFILE_MAGIC = b"APKEY01\n"
MANIFEST_AUTH_NAME = "manifest.auth"
DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MAX_SCRYPT_N = 2**17
CHUNK_SIZE = 1024 * 1024

KeySource = Literal["passphrase", "keyfile"]


class EncryptionError(ValueError):
    """An encrypted backup or key source is invalid or cannot authenticate."""


class UnsupportedEncryptionError(EncryptionError):
    """An encryption envelope or key format is newer than this runtime supports."""


@dataclass(frozen=True, slots=True)
class BackupKey:
    source: KeySource
    material: bytes

    def __post_init__(self) -> None:
        if self.source == "passphrase":
            if not self.material:
                raise ValueError("Backup passphrase must not be empty")
        elif self.source == "keyfile":
            if len(self.material) != KEY_BYTES:
                raise ValueError("Backup keyfiles must contain exactly 32 key bytes")
        else:
            raise ValueError("Unsupported backup key source")


@dataclass(frozen=True, slots=True)
class EncryptionParameters:
    envelope_version: int
    key_source: KeySource
    salt: str
    kdf: str
    scrypt_n: int | None = None
    scrypt_r: int | None = None
    scrypt_p: int | None = None
    manifest_auth: str = MANIFEST_AUTH_NAME

    def __post_init__(self) -> None:
        if self.envelope_version != ENVELOPE_VERSION:
            raise UnsupportedEncryptionError(
                f"Unsupported encryption envelope version: {self.envelope_version}"
            )
        try:
            salt_bytes = base64.b64decode(self.salt, validate=True)
        except ValueError as exc:
            raise EncryptionError("Invalid backup encryption salt") from exc
        if len(salt_bytes) < 16:
            raise EncryptionError("Backup encryption salt must contain at least 16 bytes")
        if self.manifest_auth != MANIFEST_AUTH_NAME:
            raise EncryptionError("Unsupported manifest authentication path")
        if self.key_source == "passphrase":
            if self.kdf != "scrypt" or None in (self.scrypt_n, self.scrypt_r, self.scrypt_p):
                raise EncryptionError("Passphrase backups require supported Scrypt parameters")
            if (
                self.scrypt_n is None
                or self.scrypt_n < 2**14
                or self.scrypt_n > MAX_SCRYPT_N
                or self.scrypt_n & (self.scrypt_n - 1)
                or self.scrypt_r is None
                or not 1 <= self.scrypt_r <= 8
                or self.scrypt_p is None
                or not 1 <= self.scrypt_p <= 2
            ):
                raise EncryptionError("Unsafe or unsupported Scrypt parameters")
        elif self.key_source == "keyfile":
            if self.kdf != "hkdf-sha256-keyfile-v1":
                raise EncryptionError("Unsupported keyfile derivation")
            if any(value is not None for value in (self.scrypt_n, self.scrypt_r, self.scrypt_p)):
                raise EncryptionError("Keyfile backups cannot contain Scrypt parameters")
        else:
            raise EncryptionError("Unsupported backup key source")

    @property
    def salt_bytes(self) -> bytes:
        return base64.b64decode(self.salt, validate=True)


@dataclass(frozen=True, slots=True)
class EncryptionContext:
    key: BackupKey
    parameters: EncryptionParameters
    _master: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_master", self._derive_master_key())

    def _derive_master_key(self) -> bytes:
        if self.key.source != self.parameters.key_source:
            raise EncryptionError("Backup key source does not match the backup manifest")
        if self.key.source == "passphrase":
            assert (
                self.parameters.scrypt_n and self.parameters.scrypt_r and self.parameters.scrypt_p
            )
            return Scrypt(
                salt=self.parameters.salt_bytes,
                length=KEY_BYTES,
                n=self.parameters.scrypt_n,
                r=self.parameters.scrypt_r,
                p=self.parameters.scrypt_p,
            ).derive(self.key.material)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=self.parameters.salt_bytes,
            info=b"ArborPress backup master key from keyfile v1",
        ).derive(self.key.material)

    def component_key(self, backup_id: str, relative_path: str) -> bytes:
        info = b"ArborPress component key v1\0" + backup_id.encode() + b"\0"
        info += relative_path.encode("utf-8") + struct.pack(">B", self.parameters.envelope_version)
        return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=info).derive(
            self._master
        )

    def manifest_key(self, backup_id: str) -> bytes:
        info = b"ArborPress manifest authentication key v1\0" + backup_id.encode()
        return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=info).derive(
            self._master
        )


def create_encryption_context(key: BackupKey) -> EncryptionContext:
    salt = os.urandom(16)
    if key.source == "passphrase":
        parameters = EncryptionParameters(
            envelope_version=ENVELOPE_VERSION,
            key_source="passphrase",
            salt=base64.b64encode(salt).decode("ascii"),
            kdf="scrypt",
            scrypt_n=DEFAULT_SCRYPT_N,
            scrypt_r=DEFAULT_SCRYPT_R,
            scrypt_p=DEFAULT_SCRYPT_P,
        )
    else:
        parameters = EncryptionParameters(
            envelope_version=ENVELOPE_VERSION,
            key_source="keyfile",
            salt=base64.b64encode(salt).decode("ascii"),
            kdf="hkdf-sha256-keyfile-v1",
        )
    return EncryptionContext(key=key, parameters=parameters)


def context_from_manifest(key: BackupKey, parameters: EncryptionParameters) -> EncryptionContext:
    return EncryptionContext(key=key, parameters=parameters)


def associated_data(
    backup_id: str, relative_path: str, envelope_version: int, manifest_version: int
) -> bytes:
    path = relative_path.encode("utf-8")
    return (
        b"ArborPress backup component v1\0"
        + struct.pack(">BBH", envelope_version, manifest_version, len(path))
        + backup_id.encode("ascii")
        + b"\0"
        + path
    )


def encrypt_file(
    source: Path,
    destination: Path,
    *,
    context: EncryptionContext,
    backup_id: str,
    relative_path: str,
    manifest_version: int,
) -> tuple[str, int, bytes]:
    """Stream one compressed component into a fresh encrypted envelope."""
    nonce = os.urandom(NONCE_BYTES)
    cipher = Cipher(
        algorithms.AES(context.component_key(backup_id, relative_path)), modes.GCM(nonce)
    )
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(
        associated_data(
            backup_id, relative_path, context.parameters.envelope_version, manifest_version
        )
    )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        destination,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_stream:
            header = ENVELOPE_HEADER.pack(
                ENVELOPE_MAGIC,
                context.parameters.envelope_version,
                ENVELOPE_ALGORITHM_AES_256_GCM,
                nonce,
            )
            output.write(header)
            digest.update(header)
            size += len(header)
            while chunk := input_stream.read(CHUNK_SIZE):
                encrypted = encryptor.update(chunk)
                output.write(encrypted)
                digest.update(encrypted)
                size += len(encrypted)
            tail = encryptor.finalize()
            output.write(tail)
            digest.update(tail)
            size += len(tail)
            tag = encryptor.tag
            output.write(tag)
            digest.update(tag)
            size += len(tag)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return digest.hexdigest(), size, nonce


def parse_envelope_header(stream: BinaryIO) -> tuple[int, int, bytes]:
    header = stream.read(ENVELOPE_HEADER.size)
    if len(header) != ENVELOPE_HEADER.size:
        raise EncryptionError("Encrypted backup component has a truncated header")
    magic, version, algorithm, nonce = ENVELOPE_HEADER.unpack(header)
    if magic != ENVELOPE_MAGIC:
        raise EncryptionError("Encrypted backup component has invalid magic")
    if version != ENVELOPE_VERSION:
        raise UnsupportedEncryptionError(f"Unsupported encryption envelope version: {version}")
    if algorithm != ENVELOPE_ALGORITHM_AES_256_GCM:
        raise UnsupportedEncryptionError(f"Unsupported encryption algorithm ID: {algorithm}")
    return version, algorithm, nonce


def verify_envelope_header(path: Path) -> None:
    with path.open("rb") as stream:
        parse_envelope_header(stream)
        stream.seek(0, os.SEEK_END)
        if stream.tell() < ENVELOPE_HEADER.size + TAG_BYTES:
            raise EncryptionError("Encrypted backup component is truncated")


def decrypt_file_to_path(
    source: Path,
    destination: Path,
    *,
    context: EncryptionContext,
    backup_id: str,
    relative_path: str,
    manifest_version: int,
) -> None:
    """Stream-decrypt to a caller-owned private temporary path; tag failure is fatal."""
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_stream:
            version, _algorithm, nonce = parse_envelope_header(input_stream)
            input_stream.seek(0, os.SEEK_END)
            total_size = input_stream.tell()
            ciphertext_size = total_size - ENVELOPE_HEADER.size - TAG_BYTES
            if ciphertext_size < 0:
                raise EncryptionError("Encrypted backup component is truncated")
            input_stream.seek(ENVELOPE_HEADER.size)
            input_stream.seek(total_size - TAG_BYTES)
            tag = input_stream.read(TAG_BYTES)
            input_stream.seek(ENVELOPE_HEADER.size)
            decryptor = Cipher(
                algorithms.AES(context.component_key(backup_id, relative_path)),
                modes.GCM(nonce),
            ).decryptor()
            decryptor.authenticate_additional_data(
                associated_data(backup_id, relative_path, version, manifest_version)
            )
            remaining = ciphertext_size
            while remaining:
                chunk = input_stream.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise EncryptionError("Encrypted backup component is truncated")
                remaining -= len(chunk)
                output.write(decryptor.update(chunk))
            try:
                decryptor.finalize_with_tag(tag)
            except InvalidTag:
                raise EncryptionError("Backup authentication failed") from None
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def manifest_authentication(context: EncryptionContext, backup_id: str, manifest: bytes) -> bytes:
    return hmac.digest(context.manifest_key(backup_id), manifest, "sha256")


def verify_manifest_authentication(
    context: EncryptionContext, backup_id: str, manifest: bytes, authentication: bytes
) -> None:
    expected = manifest_authentication(context, backup_id, manifest)
    if not hmac.compare_digest(expected, authentication):
        raise EncryptionError("Backup manifest authentication failed")


def encode_keyfile(material: bytes) -> bytes:
    if len(material) != KEY_BYTES:
        raise ValueError("Backup keyfiles must contain exactly 32 key bytes")
    return KEYFILE_MAGIC + base64.b64encode(material) + b"\n"


def generate_keyfile(path: Path, *, overwrite: bool = False) -> None:
    """Create a random 256-bit keyfile without silently replacing an existing file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing backup keyfile: {path}")
    material = os.urandom(KEY_BYTES)
    flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encode_keyfile(material))
            output.flush()
            os.fsync(output.fileno())
        if os.name == "posix":
            path.chmod(0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def load_keyfile(path: Path, *, require_secure_permissions: bool = True) -> BackupKey:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EncryptionError("Could not open backup keyfile safely") from exc
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise EncryptionError("Backup keyfile must be a regular non-symlink file")
        if (
            os.name == "posix"
            and require_secure_permissions
            and stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise EncryptionError("Backup keyfile permissions are too broad; use chmod 600")
        if metadata.st_size > 128:
            raise EncryptionError("ArborPress backup keyfile is too large")
        content = stream.read(129)
    if len(content) > 128:
        raise EncryptionError("ArborPress backup keyfile is too large")
    if not content.startswith(KEYFILE_MAGIC):
        raise EncryptionError("Unsupported or malformed ArborPress backup keyfile")
    try:
        material = base64.b64decode(content[len(KEYFILE_MAGIC) :].strip(), validate=True)
    except ValueError as exc:
        raise EncryptionError("Malformed ArborPress backup keyfile") from exc
    return BackupKey("keyfile", material)


@contextlib.contextmanager
def decrypted_component_file(
    source: Path,
    *,
    context: EncryptionContext,
    backup_id: str,
    relative_path: str,
    manifest_version: int,
) -> Iterator[Path]:
    """Yield a private, short-lived compressed plaintext temp file."""
    with tempfile.TemporaryDirectory(prefix="arborpress-decrypt-") as temporary:
        path = Path(temporary) / "component.stream"
        decrypt_file_to_path(
            source,
            path,
            context=context,
            backup_id=backup_id,
            relative_path=relative_path,
            manifest_version=manifest_version,
        )
        yield path
