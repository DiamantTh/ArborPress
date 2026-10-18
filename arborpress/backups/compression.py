"""Python-library compression configuration for backup components."""

from __future__ import annotations

import bz2
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

CompressionBackend = Literal["bz2", "bz3"]
CompressionProfile = Literal["fast", "medium", "strong", "custom"]
PROFILE_LEVELS: dict[str, int] = {"fast": 1, "medium": 6, "strong": 9}
BZ3_PROFILE_BLOCK_SIZES: dict[str, int] = {
    "fast": 500_000,
    "medium": 900_000,
    "strong": 1_500_000,
}
MAX_COMPRESSION_THREADS = 64


class CompressionUnavailableError(RuntimeError):
    """A requested optional Python compression library is unavailable."""


@dataclass(frozen=True, slots=True)
class CompressionSettings:
    backend: CompressionBackend = "bz2"
    profile: CompressionProfile = "medium"
    level: int | None = None
    threads: int | None = None

    def __post_init__(self) -> None:
        if self.backend not in {"bz2", "bz3"}:
            raise ValueError(f"Unsupported compression backend: {self.backend!r}")
        if self.profile not in {"fast", "medium", "strong", "custom"}:
            raise ValueError(f"Unsupported compression profile: {self.profile!r}")
        if self.profile == "custom":
            if self.level is None or not 1 <= self.level <= 9:
                raise ValueError("Custom BZip2 compression level must be between 1 and 9")
        elif self.level is not None and self.level != PROFILE_LEVELS[self.profile]:
            raise ValueError("An explicit compression level is only valid for the custom profile")
        if self.backend == "bz2" and self.threads not in {None, 1}:
            raise ValueError("The Python standard-library BZip2 backend is not parallel")
        if self.backend == "bz3" and self.threads is not None:
            if not 1 <= self.threads <= MAX_COMPRESSION_THREADS:
                raise ValueError(f"BZip3 threads must be between 1 and {MAX_COMPRESSION_THREADS}")

    @property
    def effective_level(self) -> int | None:
        if self.backend == "bz3":
            return None
        return self.level if self.profile == "custom" else PROFILE_LEVELS[self.profile]

    @property
    def effective_threads(self) -> int | None:
        if self.backend == "bz2":
            return None
        return self.threads or min(os.cpu_count() or 1, MAX_COMPRESSION_THREADS)

    @property
    def effective_block_size(self) -> int | None:
        if self.backend == "bz2":
            return None
        if self.profile == "custom":
            return 400_000 + (self.level or 1) * 100_000
        return BZ3_PROFILE_BLOCK_SIZES[self.profile]

    @property
    def extension(self) -> str:
        return self.backend


@contextmanager
def open_compressed_writer(path: Path, settings: CompressionSettings) -> Iterator[Any]:
    """Open a compressed binary output stream without invoking an executable."""
    if settings.backend == "bz2":
        with bz2.open(path, "wb", compresslevel=settings.effective_level or 6) as stream:
            yield stream
        return
    try:
        import bz3
    except ImportError as exc:
        raise CompressionUnavailableError(
            "BZip3 support is optional; install ArborPress with the 'backup-bz3' extra"
        ) from exc
    with bz3.open(
        path,
        "wb",
        block_size=settings.effective_block_size or 900_000,
        num_threads=settings.effective_threads or 1,
    ) as stream:
        yield stream


@contextmanager
def open_compressed_reader(path: Path, backend: CompressionBackend) -> Iterator[Any]:
    """Open a compressed binary input stream using only Python APIs."""
    if backend == "bz2":
        with bz2.open(path, "rb") as stream:
            yield stream
        return
    if backend != "bz3":
        raise ValueError(f"Unsupported compression backend: {backend!r}")
    try:
        import bz3
    except ImportError as exc:
        raise CompressionUnavailableError(
            "This backup uses BZip3; install ArborPress with the 'backup-bz3' extra to verify it"
        ) from exc
    with bz3.open(path, "rb") as stream:
        yield stream
