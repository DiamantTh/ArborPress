"""Rate limiting via the 'limits' library (§10 – Security-First Design Principles).

Uses the same storage configuration as CacheSettings:
  - memory (default): in-process dict, no external service needed.
  - redis: shared state across multiple worker processes/instances.
  - All other backends (memcached, file, none): fall back to MemoryStorage.

Fail-open: on storage errors the request is allowed through, so that a
cache-backend outage does not cause a permanent HTTP-429 storm.
This behaviour is appropriate for a simple deployment environment; in
high-security environments 'fail-closed' (return False on error) can be chosen.
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
    log.warning("'limits' not installed – rate limiting disabled")

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
        # memory, memcached, file, none → stateless in-process storage
        store = _storage.MemoryStorage()

    _limiter = _strategies.FixedWindowRateLimiter(store)
    return _limiter


def check_rate_limit(key: str, limit_str: str) -> bool:
    """Checks and decrements the rate limit for *key*.

    Args:
        key:       Unique identifier (e.g. ``"auth:127.0.0.1"``).
        limit_str: Format string (e.g. ``"10/minute"``), compatible with the
                   *limits* library and ``AuthSettings.auth_rate_limit``.

    Returns:
        ``True``  – request is within the limit (allowed).
        ``False`` – limit exceeded; caller should return HTTP 429.
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
        log.error("Rate limit check failed (%s): %s", key, exc)
        return True  # fail-open on storage error
