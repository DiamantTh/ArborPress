"""Cache backend abstraction (§12 / §14 cache).

Supported backends:
  memory       – asyncio-compatible in-process dict (default, no dep)
  redis        – redis-py async (optional: pip install redis)
  memcached    – aiomcache (optional: pip install aiomcache)
  file         – JSON dump in directory (persistent, no external service)
  none         – disabled (every GET returns None)

Configuration via config.toml [cache]:
  backend      = "memory"           # memory|redis|memcached|file|none
  ttl          = 300                # default TTL in seconds
  prefix       = "ap:"              # key prefix
  # Redis
  redis_url    = "redis://localhost:6379/0"
  # Memcached
  memcached_host = "localhost"
  memcached_port = 11211
  # File
  file_dir     = "/tmp/arborpress_cache"

Public API (async):
  cache_get(key)               -> Any | None
  cache_set(key, value, ttl?)  -> None
  cache_delete(key)            -> None
  cache_flush()                -> None
  cache_backend_info()         -> str        (for CLI/admin)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("arborpress.cache")

# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


class CacheBackend:
    """Base interface – all backends implement these methods."""

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        raise NotImplementedError

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        raise NotImplementedError

    async def delete(self, key: str) -> None:
        raise NotImplementedError

    async def flush(self) -> None:
        raise NotImplementedError

    def info(self) -> str:
        return self.__class__.__name__


# ---------------------------------------------------------------------------
# none backend
# ---------------------------------------------------------------------------


class NoneBackend(CacheBackend):
    """Disabled cache – every GET returns None."""

    async def get(self, key: str) -> None:
        return None

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        pass

    async def delete(self, key: str) -> None:
        pass

    async def flush(self) -> None:
        pass

    def info(self) -> str:
        return "none (disabled)"


# ---------------------------------------------------------------------------
# memory backend
# ---------------------------------------------------------------------------


class MemoryBackend(CacheBackend):
    """In-process dict with TTL tracking. Thread/coroutine-safe via asyncio.Lock."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # {key: (value, expires_at_mono)}  expires_at_mono = 0 → nie ablaufen
        self._store: dict[str, tuple[Any, float]] = {}

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires = entry
            if expires and time.monotonic() > expires:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        async with self._lock:
            expires = (time.monotonic() + ttl) if ttl > 0 else 0.0
            self._store[key] = (value, expires)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def flush(self) -> None:
        async with self._lock:
            self._store.clear()

    def info(self) -> str:
        return f"memory ({len(self._store)} entries)"


# ---------------------------------------------------------------------------
# redis backend
# ---------------------------------------------------------------------------


class RedisBackend(CacheBackend):
    """Redis-Backend via redis-py >= 5 (async)."""

    def __init__(self, url: str, prefix: str = "ap:") -> None:
        self._url = url
        self._prefix = prefix
        self._client: Any = None  # redis.asyncio.Redis

    async def _ensure(self) -> Any:  # noqa: ANN401
        if self._client is None:
            try:
                import redis.asyncio as aioredis
            except ImportError as exc:
                raise RuntimeError(
                    "redis backend requires 'redis'. pip install 'redis[hiredis]'"
                ) from exc
            self._client = aioredis.from_url(self._url, decode_responses=False)
        return self._client

    def _k(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        r = await self._ensure()
        raw = await r.get(self._k(key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        r = await self._ensure()
        encoded = json.dumps(value, default=str)
        if ttl > 0:
            await r.setex(self._k(key), ttl, encoded)
        else:
            await r.set(self._k(key), encoded)

    async def delete(self, key: str) -> None:
        r = await self._ensure()
        await r.delete(self._k(key))

    async def flush(self) -> None:
        r = await self._ensure()
        # Delete only keys with this prefix
        keys = await r.keys(f"{self._prefix}*")
        if keys:
            await r.delete(*keys)

    def info(self) -> str:
        return f"redis ({self._url})"


# ---------------------------------------------------------------------------
# memcached backend
# ---------------------------------------------------------------------------


class MemcachedBackend(CacheBackend):
    """Memcached-Backend via aiomcache."""

    def __init__(self, host: str, port: int, prefix: str = "ap:") -> None:
        self._host = host
        self._port = port
        self._prefix = prefix
        self._client: Any = None

    async def _ensure(self) -> Any:  # noqa: ANN401
        if self._client is None:
            try:
                import aiomcache
            except ImportError as exc:
                raise RuntimeError(
                    "memcached backend requires 'aiomcache'. pip install aiomcache"
                ) from exc
            self._client = aiomcache.Client(self._host, self._port)
        return self._client

    def _k(self, key: str) -> bytes:
        # Memcached: no spaces/control chars, max 250 characters
        k = f"{self._prefix}{key}"[:250]
        return k.encode()

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        mc = await self._ensure()
        raw = await mc.get(self._k(key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        mc = await self._ensure()
        encoded = json.dumps(value, default=str).encode()
        await mc.set(self._k(key), encoded, exptime=ttl)

    async def delete(self, key: str) -> None:
        mc = await self._ensure()
        await mc.delete(self._k(key))

    async def flush(self) -> None:
        mc = await self._ensure()
        await mc.flush_all()

    def info(self) -> str:
        return f"memcached ({self._host}:{self._port})"


# ---------------------------------------------------------------------------
# file backend
# ---------------------------------------------------------------------------


class FileBackend(CacheBackend):
    """Simple file-based backend – one JSON file per key.

    Useful for single-server deployments without Redis when the cache
    should survive restarts (e.g. markdown render cache).
    """

    def __init__(self, directory: str, prefix: str = "ap_") -> None:
        self._dir = Path(directory)
        self._prefix = prefix
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # Replace unsafe characters
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)
        return self._dir / f"{self._prefix}{safe}.cache"

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        p = self._path(key)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("expires") and time.time() > data["expires"]:
                p.unlink(missing_ok=True)
                return None
            return data.get("value")
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        p = self._path(key)
        payload = {
            "value": value,
            "expires": (time.time() + ttl) if ttl > 0 else 0,
        }
        try:
            p.write_text(json.dumps(payload, default=str), encoding="utf-8")
        except OSError as exc:
            log.warning("FileCache.set failed: %s", exc)

    async def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    async def flush(self) -> None:
        for p in self._dir.glob(f"{self._prefix}*.cache"):
            p.unlink(missing_ok=True)

    def info(self) -> str:
        count = len(list(self._dir.glob(f"{self._prefix}*.cache")))
        return f"file ({self._dir}, {count} entries)"


# ---------------------------------------------------------------------------
# Singleton / Factory
# ---------------------------------------------------------------------------

_backend: CacheBackend | None = None
_default_ttl: int = 300


def _build_backend() -> CacheBackend:
    """Read config and build the configured backend."""
    try:
        from arborpress.core.config import get_settings
        cfg = get_settings()
        cache_cfg = cfg.cache
        backend_name = cache_cfg.backend
        prefix = cache_cfg.prefix
        global _default_ttl
        _default_ttl = cache_cfg.ttl

        if backend_name == "redis":
            return RedisBackend(url=cache_cfg.redis_url, prefix=prefix)
        if backend_name == "memcached":
            return MemcachedBackend(
                host=cache_cfg.memcached_host,
                port=cache_cfg.memcached_port,
                prefix=prefix,
            )
        if backend_name == "file":
            return FileBackend(directory=cache_cfg.file_dir, prefix=prefix.replace(":", "_"))
        if backend_name == "none":
            return NoneBackend()
        # Default: memory
        return MemoryBackend()
    except Exception as exc:
        log.warning("Cache configuration failed (%s) – using memory backend", exc)
        return MemoryBackend()


def get_backend() -> CacheBackend:
    """Return the initialized backend (lazy init)."""
    global _backend
    if _backend is None:
        _backend = _build_backend()
        log.info("Cache backend: %s", _backend.info())
    return _backend


def reset_backend(new_backend: CacheBackend | None = None) -> None:
    """Reset cache backend (e.g. after config change or in tests)."""
    global _backend
    _backend = new_backend


# ---------------------------------------------------------------------------
# Convenience functions (public API)
# ---------------------------------------------------------------------------


async def cache_get(key: str) -> Any | None:  # noqa: ANN401
    return await get_backend().get(key)


async def cache_set(key: str, value: Any, ttl: int | None = None) -> None:  # noqa: ANN401
    await get_backend().set(key, value, ttl if ttl is not None else _default_ttl)


async def cache_delete(key: str) -> None:
    await get_backend().delete(key)


async def cache_flush() -> None:
    await get_backend().flush()


def cache_backend_info() -> str:
    return get_backend().info()
