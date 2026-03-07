"""Externer Bild-Proxy für DSGVO-konformes Laden externer Ressourcen.

Externe Bilder werden *nicht* direkt vom Browser des Besuchers geladen,
sondern über diese Instanz proxiert und optional gecacht.  Damit werden
keine Drittanbieter-IPs der Besucher bekannt gegeben.

Verwendung in Templates / Markdown
-----------------------------------
Statt ``<img src="https://example.com/foto.jpg">`` wird
``<img src="/proxy/img?url=https%3A%2F%2F...&sig=HMAC">`` ausgegeben.

Die Signatur verhindert, dass der Endpoint als Open-Proxy missbraucht wird.

API
---
:func:`proxy_url`       Erzeugt eine signierte Proxy-URL.
:func:`proxy_signed`    Prüft die Signatur und liefert/cached das Bild.

Konfiguration (``config.toml > [web]``)
-----------------------------------------
``proxy_secret``        HMAC-Secret (leer = Proxy deaktiviert, 404 auf Anfragen).
``proxy_cache_dir``     Verzeichnis für gecachte Bilder (Standard: ``media/.proxy-cache``).
``proxy_max_size``      Maximale Dateigröße in Byte (Standard: 8 MiB).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import mimetypes
import os
import urllib.parse
from datetime import timedelta
from pathlib import Path

import aiofiles
import httpx

log = logging.getLogger("arborpress.image_proxy")

# ─── Konstanten ───────────────────────────────────────────────────────────────

_ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset(
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

_CACHE_TTL: timedelta = timedelta(days=30)
_DEFAULT_MAX_SIZE: int = 8 * 1024 * 1024  # 8 MiB
_TIMEOUT: float = 10.0  # Sekunden


# ─── Hilfsfunktionen ──────────────────────────────────────────────────────────


def _sign(secret: str, url: str) -> str:
    """Erzeugt eine HMAC-SHA256-Signatur für *url*."""
    return hmac.new(
        secret.encode(),
        url.encode(),
        hashlib.sha256,
    ).hexdigest()


def _verify(secret: str, url: str, sig: str) -> bool:
    """Prüft die Signatur konstant-zeitlich (timing-safe)."""
    expected = _sign(secret, url)
    return hmac.compare_digest(expected, sig)


def _cache_path(cache_dir: Path, url: str) -> Path:
    """Berechnet den Pfad für den Datei-Cache eines URLs."""
    digest = hashlib.sha256(url.encode()).hexdigest()
    ext = ""
    parsed_path = urllib.parse.urlparse(url).path
    if "." in Path(parsed_path).suffix[:6]:  # max 5-Zeichen-Extension
        ext = Path(parsed_path).suffix.lower()[:6]
    return cache_dir / digest[:2] / (digest + ext)


# ─── Öffentliche Funktionen ───────────────────────────────────────────────────


def proxy_url(base_url: str, image_url: str, secret: str) -> str:
    """Erzeugt eine vollständige, signierte Proxy-URL.

    Args:
        base_url:   Basis-URL der ArborPress-Instanz (z.B. ``https://blog.example.com``).
        image_url:  Externes Bild-URL, das proxiert werden soll.
        secret:     ``proxy_secret`` aus der Konfiguration.

    Returns:
        Vollständige Proxy-URL mit Signatur-Parameter.
    """
    sig = _sign(secret, image_url)
    params = urllib.parse.urlencode({"url": image_url, "sig": sig})
    return f"{base_url.rstrip('/')}/proxy/img?{params}"


async def fetch_and_cache(
    url: str,
    cache_dir: Path,
    max_size: int = _DEFAULT_MAX_SIZE,
) -> tuple[bytes, str]:
    """Holt ein Bild von einem externen URL und cached es auf Disk.

    Args:
        url:        Externes Bild-URL.
        cache_dir:  Verzeichnis für den Datei-Cache.
        max_size:   Maximale erlaubte Dateigröße in Byte.

    Returns:
        Tuple ``(content_bytes, content_type)``.

    Raises:
        ValueError: Wenn der Content-Type kein Bild ist oder die Größe überschritten wird.
        httpx.HTTPError: Bei Netzwerkfehlern.
    """
    cache_file = _cache_path(cache_dir, url)

    # Cache-Hit?
    if cache_file.exists():
        meta_file = cache_file.with_suffix(cache_file.suffix + ".meta")
        ct = "image/jpeg"  # Fallback
        if meta_file.exists():
            try:
                async with aiofiles.open(meta_file) as f:
                    ct = (await f.read()).strip()
            except OSError:
                pass
        async with aiofiles.open(cache_file, "rb") as f:
            return await f.read(), ct

    # Cache-Miss → Fetch
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=_TIMEOUT,
        headers={"User-Agent": "ArborPress-ImageProxy/1.0"},
    ) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if ct not in _ALLOWED_CONTENT_TYPES:
                raise ValueError(f"Unerlaubter Content-Type: {ct!r}")

            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > max_size:
                    raise ValueError(f"Bild überschreitet Größenlimit ({max_size} Byte)")
                chunks.append(chunk)
            data = b"".join(chunks)

    # Auf Disk cachen
    await asyncio.to_thread(_write_cache, cache_file, data, ct)
    return data, ct


def _write_cache(cache_file: Path, data: bytes, content_type: str) -> None:
    """Schreibt Datei + Metadaten-Datei atomar (sync, für asyncio.to_thread)."""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache_file.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, cache_file)
    meta = cache_file.with_suffix(cache_file.suffix + ".meta")
    meta.write_text(content_type)


# ─── Route-Hilfsfunktion (für public.py) ─────────────────────────────────────


async def handle_proxy_request(
    url: str,
    sig: str,
    secret: str,
    cache_dir: Path,
    max_size: int = _DEFAULT_MAX_SIZE,
) -> tuple[bytes, str] | None:
    """Vollständige Signaturprüfung + Fetch/Cache-Logik für den Route-Handler.

    Returns:
        ``(data, content_type)`` oder ``None`` wenn Signatur ungültig / Fehler.
    """
    if not secret:
        log.warning("Proxy-Anfrage abgelehnt: proxy_secret nicht konfiguriert")
        return None
    if not _verify(secret, url, sig):
        log.warning("Proxy-Anfrage abgelehnt: ungültige Signatur für %s", url)
        return None
    try:
        return await fetch_and_cache(url, cache_dir, max_size)
    except ValueError as exc:
        log.warning("Proxy: ungültiger Content %s — %s", url, exc)
        return None
    except httpx.HTTPError as exc:
        log.warning("Proxy: HTTP-Fehler für %s — %s", url, exc)
        return None
