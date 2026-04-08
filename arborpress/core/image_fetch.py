"""Externes Bild herunterladen und lokal im Media-Speicher ablegen.

Entspricht dem Mastodon/Pixelfed-Ansatz: Externe Bilder werden beim
Post-Speichern **einmalig serverseitig heruntergeladen** und unter einer
lokalen ``/media/…``-URL gespeichert.  Der Besucher-Browser sieht
ausschliesslich URLs der eigenen Instanz – keine Drittanbieter-Anfragen,
kein Tracking, DSGVO-konform.

Das Original-URL wird in der Datenbank (``Media.original_url``) festgehalten,
damit Herkunft und Lizenz nachvollziehbar bleiben.

API
---
:func:`download_and_store`   Holt Bild, legt Media-Record an, gibt lokale URL.

Beim zweiten Aufruf mit derselben externen URL wird der vorhandene
Media-Record zurueckgegeben (De-Duplizierung per ``original_url``).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import mimetypes
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx

log = logging.getLogger("arborpress.image_fetch")

# ─── Konstanten ───────────────────────────────────────────────────────────────

_ALLOWED_MIME: frozenset[str] = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/svg+xml",
        "image/x-icon",
    }
)
_MAX_SIZE: int = 20 * 1024 * 1024  # 20 MiB
_TIMEOUT: float = 15.0


# ─── Public Function ─────────────────────────────────────────────────────────


async def download_and_store(
    url: str,
    db,
    uploader_id: str | None = None,
    alt_text: str | None = None,
) -> str | None:
    """Laedt ein externes Bild herunter und speichert es lokal.

    Wenn dieselbe ``url`` bereits in ``Media.original_url`` eingetragen ist,
    wird kein erneuter Download durchgefuehrt – es wird die vorhandene
    lokale URL zurueckgegeben.

    Args:
        url:          Externes Bild-URL.
        db:           Aktive SQLAlchemy Async-Session.
        uploader_id:  Optional: ID des speichernden Nutzers.
        alt_text:     Optionaler Alt-Text (aus Markdown ``![alt](url)``).

    Returns:
        Lokale URL (``/media/…``) oder ``None`` bei Fehler.
    """
    from sqlalchemy import select

    from arborpress.core.config import get_settings
    from arborpress.models.content import Media

    cfg = get_settings()

    # ── De-Duplizierung ────────────────────────────────────────────────
    result = await db.execute(select(Media).where(Media.original_url == url))
    existing: Media | None = result.scalar_one_or_none()
    if existing:
        return f"{cfg.web.base_url.rstrip('/')}/media/{existing.storage_path}"

    # ── Download ───────────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=_TIMEOUT,
            headers={"User-Agent": "ArborPress-MediaFetch/1.0"},
        ) as client:
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()
                mime = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                if mime not in _ALLOWED_MIME:
                    log.warning("Nicht erlaubter MIME-Typ %r fuer %s", mime, url)
                    return None

                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes(65536):
                    total += len(chunk)
                    if total > _MAX_SIZE:
                        log.warning("Bild ueberschreitet 20-MiB-Limit: %s", url)
                        return None
                    chunks.append(chunk)
                data = b"".join(chunks)
    except httpx.HTTPError as exc:
        log.warning("Download fehlgeschlagen fuer %s: %s", url, exc)
        return None

    # ── Dimensionen via Pillow ─────────────────────────────────────────
    width: int | None = None
    height: int | None = None
    if mime != "image/svg+xml":
        try:
            from io import BytesIO

            from PIL import Image
            img = Image.open(BytesIO(data))
            width, height = img.size
        except Exception:
            log.debug("Pillow konnte Bilddimensionen nicht lesen (url=%s)", url, exc_info=True)

    # ── Stabiler Dateiname: SHA-256 des URL + Erweiterung ─────────────
    digest = hashlib.sha256(url.encode()).hexdigest()
    # Erweiterung aus MIME oder aus URL ableiten
    ext = mimetypes.guess_extension(mime) or ""
    # mimetypes liefert manchmal .jpe statt .jpg
    if ext in (".jpe", ".jpeg"):
        ext = ".jpg"
    if not ext:
        from pathlib import PurePosixPath
        from urllib.parse import urlparse
        url_path = PurePosixPath(urlparse(url).path)
        ext = url_path.suffix[:6] if url_path.suffix else ".bin"

    now = datetime.now(UTC)
    yyyy, mm = now.year, now.month
    filename = f"{digest[:24]}{ext}"   # 24 hex characters suffice for uniqueness
    storage_path = f"{yyyy}/{mm:02d}/{filename}"
    dest_dir = cfg.web.media_dir / str(yyyy) / f"{mm:02d}"
    dest_path = dest_dir / filename

    # ── Auf Disk schreiben (sync in Thread) ───────────────────────────
    await asyncio.to_thread(_write_file, dest_dir, dest_path, data)
    log.info("Bild gespeichert: %s <- %s", storage_path, url)

    # ── Media-Record anlegen ──────────────────────────────────────────
    media = Media(
        id=str(uuid.uuid4()),
        uploader_id=uploader_id,
        filename=filename,
        mime_type=mime,
        size_bytes=len(data),
        storage_path=storage_path,
        alt_text=alt_text,
        width=width,
        height=height,
        original_url=url,
    )
    db.add(media)
    # Kein commit hier – wird vom aufrufenden Handler am Stueck committed

    return f"{cfg.web.base_url.rstrip('/')}/media/{storage_path}"


def _write_file(dest_dir: Path, dest_path: Path, data: bytes) -> None:
    """Schreibt Datei atomar (sync, fuer asyncio.to_thread)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest_path)
