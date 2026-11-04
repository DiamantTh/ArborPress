"""Shared safe upload pipeline used by session and OAuth resource routes."""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.models.content import Media

MAX_MEDIA_BYTES = 20 * 1024 * 1024
MIME_EXTENSIONS = {
    "image/jpeg": (".jpg", "JPEG"),
    "image/png": (".png", "PNG"),
    "image/gif": (".gif", "GIF"),
    "image/webp": (".webp", "WEBP"),
    "image/avif": (".avif", "AVIF"),
}


class MediaUploadError(ValueError):
    """Upload failed a safe, user-correctable media validation rule."""


async def store_media_upload(
    db: AsyncSession,
    *,
    uploader_id: str,
    filename: str,
    content_type: str,
    data: bytes,
    alt_text: str | None = None,
) -> Media:
    """Validate a raster image and persist it using ArborPress media storage."""
    mime = content_type.split(";", 1)[0].strip().lower()
    expected = MIME_EXTENSIONS.get(mime)
    if expected is None:
        raise MediaUploadError("unsupported_media_type")
    if not data or len(data) > MAX_MEDIA_BYTES:
        raise MediaUploadError("media_size_limit")
    try:
        image = Image.open(BytesIO(data))
        if image.format != expected[1]:
            raise MediaUploadError("media_type_mismatch")
        width, height = image.size
        if width < 1 or height < 1 or width * height > 50_000_000:
            raise MediaUploadError("media_dimensions_limit")
        image.verify()
    except MediaUploadError:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError) as exc:
        raise MediaUploadError("invalid_image") from exc

    now = datetime.now(UTC)
    safe_filename = f"{uuid.uuid4().hex[:16]}{expected[0]}"
    relative = f"{now.year}/{now.month:02d}/{safe_filename}"
    root: Path = get_settings().web.media_dir
    directory = root / str(now.year) / f"{now.month:02d}"
    destination = directory / safe_filename
    await asyncio.to_thread(_atomic_write, directory, destination, data)
    media = Media(
        id=str(uuid.uuid4()),
        uploader_id=uploader_id,
        filename=safe_filename,
        mime_type=mime,
        size_bytes=len(data),
        storage_path=relative,
        alt_text=alt_text.strip()[:512] if alt_text and alt_text.strip() else None,
        width=width,
        height=height,
    )
    db.add(media)
    await db.flush()
    return media


def _atomic_write(directory: Path, destination: Path, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
