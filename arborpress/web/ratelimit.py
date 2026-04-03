"""Rate-Limiting via 'limits'-Bibliothek (§10 – Security-First Design Principles).

Verwendet dieselbe Storage-Konfiguration wie CacheSettings:
  - memory (Standard): In-Process-Dict, kein externer Dienst nötig.
  - redis: Geteilter Zustand über mehrere Worker-Prozesse/Instanzen hinweg.
  - Alle anderen Backends (memcached, file, none): Fallback auf MemoryStorage.

Fail-open: Bei Storage-Fehlern wird die Anfrage durchgelassen, damit ein
Ausfall des Cache-Backends nicht zu einem dauerhaften HTTP-429-Regen führt.
Dieses Verhalten ist für eine einfache Deployment-Umgebung angemessen; in
Hochsicherheitsumgebungen kann 'fail-closed' (False bei Fehler) gewählt werden.
"""

from __future__ import annotations

import logging

log = logging.getLogger("arborpress.web.ratelimit")

try:
    from limits import parse as _parse
    from limits import strategies as _strategies

    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _AVAILABLE = False
    log.warning("'limits' nicht installiert – Rate-Limiting deaktiviert")

# Modul-globaler Singleton: wird beim ersten Aufruf initialisiert
_limiter: object = None


def _get_limiter() -> object:
    global _limiter
    if _limiter is not None:
        return _limiter
    if not _AVAILABLE:
        return None

    from limits import storage as _storage

    from arborpress.core.config import get_settings

    cfg = get_settings()
    if cfg.cache.backend == "redis":
        store = _storage.RedisStorage(cfg.cache.redis_url)
    else:
        # memory, memcached, file, none → zustandsloser In-Process-Speicher
        store = _storage.MemoryStorage()

    _limiter = _strategies.FixedWindowRateLimiter(store)
    return _limiter


def check_rate_limit(key: str, limit_str: str) -> bool:
    """Prüft und dekrementiert das Rate-Limit für *key*.

    Args:
        key:       Eindeutiger Identifikator (z.B. ``"auth:127.0.0.1"``).
        limit_str: Format-String (z.B. ``"10/minute"``), kompatibel mit der
                   *limits*-Bibliothek und ``AuthSettings.auth_rate_limit``.

    Returns:
        ``True``  – Anfrage liegt innerhalb des Limits (erlaubt).
        ``False`` – Limit überschritten; Aufrufer soll HTTP 429 zurückgeben.
    """
    if not _AVAILABLE:
        return True  # fail-open wenn Bibliothek fehlt

    limiter = _get_limiter()
    if limiter is None:
        return True

    try:
        item = _parse(limit_str)
        return bool(limiter.hit(item, key))  # type: ignore[union-attr]
    except Exception as exc:
        log.error("Rate-Limit-Prüfung fehlgeschlagen (%s): %s", key, exc)
        return True  # fail-open bei Storage-Fehler
