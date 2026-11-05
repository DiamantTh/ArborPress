"""Cache backend abstraction (§12 / §14 cache).

Supported backends:
  memory       – asyncio-compatible in-process dict (default, no dep)
  redis        – redis-py async (optional: pip install 'redis[hiredis]')
  valkey       – Valkey async (FOSS Redis-Fork BSD-3; pip install 'valkey[libvalkey]')
  memcached    – aiomcache (optional: pip install aiomcache)
  file         – JSON dump in directory (persistent, no external service)
  none         – disabled (every GET returns None)

Zwei-Ebenen-Cache (L1 + L2):
  l1_enabled = true  aktiviert einen in-process MemoryBackend (L1) vor dem
  konfigurierten externen Backend (L2). L1-TTL ist kürzer als L2-TTL, damit
  Invalidierungen aus L2 zeitnah wirken. Sinnvoll bei Multi-Worker-Deployments
  mit Valkey/Redis als L2.

Configuration via config.toml [cache]:
  backend      = "memory"           # memory|redis|valkey|memcached|file|none
  ttl          = 300                # default TTL in seconds
  prefix       = "ap:"              # key prefix
  # L1-Cache (in-process, vor externem Backend)
  l1_enabled   = false              # Zwei-Ebenen-Cache aktivieren
  l1_ttl       = 30                 # L1-TTL in Sekunden
  # Redis
  redis_url    = "redis://localhost:6379/0"
  # Valkey (FOSS Redis-Fork–kompatible URL)
  valkey_url   = "valkey://localhost:6379/0"
  # Memcached
  memcached_host = "localhost"
  memcached_port = 11211
  # File
  file_dir     = None  # defaults to PREFIX/instance/var/cache

Public API (async):
  cache_get(key)               -> Any | None
  cache_set(key, value, ttl?)  -> None
  cache_delete(key)            -> None
  cache_flush()                -> None
  cache_backend_info()         -> str        (for CLI/admin)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("arborpress.cache")

# Internal serialization namespace; this is not a product version.
CACHE_NAMESPACE = "arborpress:cache:v1"
MAX_L1_TTL_SECONDS = 5
MEMCACHED_MAX_TTL_SECONDS = 30 * 24 * 60 * 60

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


class NamespacedBackend(CacheBackend):
    """Isolate cache keys by format and ArborPress instance prefix."""

    def __init__(self, backend: CacheBackend, namespace: str) -> None:
        self._backend = backend
        self._namespace = namespace

    def _key(self, key: str) -> str:
        return f"{self._namespace}{key}"

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        return await self._backend.get(self._key(key))

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        await self._backend.set(self._key(key), value, ttl)

    async def delete(self, key: str) -> None:
        await self._backend.delete(self._key(key))

    async def flush(self) -> None:
        await _flush_namespace(self._backend, self._namespace)

    def info(self) -> str:
        return self._backend.info()

    @property
    def probe_backend(self) -> CacheBackend:
        return self._backend


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

    async def delete_prefix(self, prefix: str) -> None:
        """Delete only keys owned by one NamespacedBackend wrapper."""
        async with self._lock:
            for key in tuple(self._store):
                if key.startswith(prefix):
                    del self._store[key]

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
        batch: list[Any] = []
        async for key in r.scan_iter(match=f"{self._prefix}*", count=250):
            batch.append(key)
            if len(batch) >= 250:
                await r.delete(*batch)
                batch.clear()
        if batch:
            await r.delete(*batch)

    def info(self) -> str:
        return "redis"


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
        self._generation: str | None = None

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

    def _generation_key(self) -> bytes:
        return f"{self._prefix}generation"[:250].encode()

    async def _current_generation(self, mc: Any) -> str:
        raw = await mc.get(self._generation_key())
        if raw is None:
            candidate = secrets.token_hex(8).encode()
            try:
                await mc.add(self._generation_key(), candidate, exptime=0)
            except Exception as exc:
                # A concurrent worker may have initialized the shared key.
                log.debug("Memcached generation add raced (%s)", type(exc).__name__)
            raw = await mc.get(self._generation_key())
            if raw is None:
                raise RuntimeError("memcached cache namespace is unavailable")
        self._generation = raw.decode("ascii", errors="ignore") or "0"
        return self._generation

    async def _k(self, key: str, mc: Any) -> bytes:
        generation = await self._current_generation(mc)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{self._prefix}{generation}:{digest}"[:250].encode()

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        mc = await self._ensure()
        raw = await mc.get(await self._k(key, mc))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        mc = await self._ensure()
        encoded = json.dumps(value, default=str).encode()
        # Generation-based purge makes old generations unreachable. Bound
        # nominally permanent entries so stale generations are eventually
        # reclaimed by Memcached itself.
        effective_ttl = (
            min(ttl, MEMCACHED_MAX_TTL_SECONDS)
            if ttl > 0
            else MEMCACHED_MAX_TTL_SECONDS
        )
        await mc.set(await self._k(key, mc), encoded, exptime=effective_ttl)

    async def delete(self, key: str) -> None:
        mc = await self._ensure()
        await mc.delete(await self._k(key, mc))

    async def flush(self) -> None:
        mc = await self._ensure()
        generation = secrets.token_hex(8).encode()
        await mc.set(self._generation_key(), generation, exptime=0)
        self._generation = generation.decode("ascii")

    def info(self) -> str:
        return "memcached"


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

    def _path(self, key: str) -> Path:
        safe = hashlib.sha256(key.encode("utf-8")).hexdigest()
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
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary = p.with_name(f".{p.name}.{secrets.token_hex(6)}.tmp")
            temporary.write_text(json.dumps(payload, default=str), encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(p)
        except OSError as exc:
            log.warning("FileCache.set failed (%s)", type(exc).__name__)

    async def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    async def flush(self) -> None:
        for p in self._dir.glob(f"{self._prefix}*.cache"):
            p.unlink(missing_ok=True)

    def info(self) -> str:
        count = sum(1 for _ in self._dir.glob(f"{self._prefix}*.cache"))
        return f"file ({count} entries)"


# ---------------------------------------------------------------------------
# Valkey backend (FOSS Redis-Fork, BSD-3 licensed, API-kompatibel zu redis-py)
# ---------------------------------------------------------------------------


class ValkeyBackend(CacheBackend):
    """Valkey-Backend via valkey-py (API-kompatibel zu redis-py).

    Valkey ist der von der Linux Foundation betreute FOSS-Fork von Redis
    (Redis wechselte ab 7.4 zur BSL-Lizenz). Die Python-Library `valkey`
    ist ein Drop-in-Replacement für `redis.asyncio`.
    """

    def __init__(self, url: str, prefix: str = "ap:") -> None:
        self._url = url
        self._prefix = prefix
        self._client: Any = None  # valkey.asyncio.Valkey

    async def _ensure(self) -> Any:  # noqa: ANN401
        if self._client is None:
            try:
                import valkey.asyncio as aivalkey
            except ImportError as exc:
                raise RuntimeError(
                    "valkey backend requires 'valkey'. "
                    "pip install 'valkey[libvalkey]'"
                ) from exc
            self._client = aivalkey.from_url(self._url, decode_responses=False)
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
        batch: list[Any] = []
        async for key in r.scan_iter(match=f"{self._prefix}*", count=250):
            batch.append(key)
            if len(batch) >= 250:
                await r.delete(*batch)
                batch.clear()
        if batch:
            await r.delete(*batch)

    def info(self) -> str:
        return "valkey"


# ---------------------------------------------------------------------------
# Two-level backend (L1 in-process + L2 external)
# ---------------------------------------------------------------------------


class TwoLevelBackend(CacheBackend):
    """Zwei-Ebenen-Cache: L1 (in-process MemoryBackend) vor L2 (externer Backend).

    Lesepfad: L1-Hit → sofort zurück. L1-Miss → L2 abfragen, Ergebnis in L1 schreiben.
    Schreibpfad: in beide Ebenen schreiben.
    Löschpfad: aus beiden Ebenen löschen.

    L1 verwendet immer den kürzeren ``l1_ttl``, damit Invalidierungen aus L2
    zeitnah durchschlagen. Kann über ``CacheSettings.l1_enabled = false`` deaktiviert
    werden – dann wird der L2-Backend direkt zurückgegeben (kein Overhead).
    """

    def __init__(self, l1: CacheBackend, l2: CacheBackend, l1_ttl: int = 30) -> None:
        self._l1 = l1
        self._l2 = l2
        self._l1_ttl = min(max(1, l1_ttl), MAX_L1_TTL_SECONDS)

    async def get(self, key: str) -> Any | None:  # noqa: ANN401
        value = await self._l1.get(key)
        if value is not None:
            return value
        value = await self._l2.get(key)
        if value is not None:
            # L1 mit kürzerem TTL befüllen
            await self._l1.set(key, value, self._l1_ttl)
        return value

    async def set(self, key: str, value: Any, ttl: int) -> None:  # noqa: ANN401
        await self._l1.set(key, value, self._l1_ttl)
        await self._l2.set(key, value, ttl)

    async def delete(self, key: str) -> None:
        await self._l1.delete(key)
        await self._l2.delete(key)

    async def flush(self) -> None:
        await self._l1.flush()
        await self._l2.flush()

    def info(self) -> str:
        return f"two-level [L1: {self._l1.info()} | L2: {self._l2.info()}]"


async def _flush_namespace(backend: CacheBackend, namespace: str) -> None:
    """Purge one namespace without flushing shared in-process memory stores."""
    if isinstance(backend, MemoryBackend):
        await backend.delete_prefix(namespace)
    elif isinstance(backend, TwoLevelBackend):
        await _flush_namespace(backend._l1, namespace)
        await _flush_namespace(backend._l2, namespace)
    elif isinstance(backend, NoneBackend):
        return
    else:
        # Redis/Valkey/Memcached/File backends have their own configured
        # ArborPress prefix and implement purge without touching other apps.
        await backend.flush()


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

        instance_prefix = _instance_prefix(prefix)
        if backend_name == "redis":
            backend: CacheBackend = RedisBackend(
                url=cache_cfg.redis_url, prefix=f"{instance_prefix}backend:"
            )
        elif backend_name == "valkey":
            backend = ValkeyBackend(
                url=cache_cfg.valkey_url, prefix=f"{instance_prefix}backend:"
            )
        elif backend_name == "memcached":
            backend = MemcachedBackend(
                host=cache_cfg.memcached_host,
                port=cache_cfg.memcached_port,
                prefix=f"{instance_prefix}backend:",
            )
        elif backend_name == "file":
            from arborpress.runtime.paths import ensure_instance_layout, get_runtime_paths

            paths = get_runtime_paths()
            ensure_instance_layout(paths)
            file_dir = cache_cfg.file_dir or paths.cache
            backend = FileBackend(
                directory=str(file_dir),
                prefix=f"{instance_prefix}backend:".replace(":", "_"),
            )
        elif backend_name == "none":
            backend = NoneBackend()
        else:
            # Default: memory – L1 makes no sense on top of memory
            backend = MemoryBackend()

        # Zwei-Ebenen-Cache: L1 (in-process) vor L2 (externer Backend)
        if cache_cfg.l1_enabled:
            backend = TwoLevelBackend(
                l1=MemoryBackend(),
                l2=backend,
                l1_ttl=min(max(1, cache_cfg.l1_ttl), MAX_L1_TTL_SECONDS),
            )

        return NamespacedBackend(backend, instance_prefix)
    except Exception as exc:
        log.warning(
            "Cache configuration failed (%s) – using memory backend", type(exc).__name__
        )
        return NamespacedBackend(MemoryBackend(), _instance_prefix("ap:"))


def _instance_prefix(configured_prefix: str) -> str:
    """Return a stable per-instance prefix independent of process CWD."""
    from arborpress.runtime.paths import get_runtime_paths

    prefix_path = str(get_runtime_paths().prefix.resolve())
    instance_id = hashlib.sha256(prefix_path.encode("utf-8")).hexdigest()[:12]
    # Configured prefixes are operator-controlled and can be arbitrarily long.
    # Hash them to keep Memcached keys below its protocol limit and avoid key
    # collisions caused by truncating long prefixes.
    configured_id = hashlib.sha256(configured_prefix.encode("utf-8")).hexdigest()[:16]
    return f"{CACHE_NAMESPACE}:{instance_id}:{configured_id}:"


def get_backend() -> CacheBackend:
    """Return the initialized backend (lazy init)."""
    global _backend
    if _backend is None:
        _backend = _build_backend()
        log.info("Cache backend: %s", _backend.info())
    return _backend


def reset_backend_for_tests() -> None:
    """Reset the backend singleton between tests using different prefixes."""
    global _backend, _default_ttl
    _backend = None
    _default_ttl = 300


def reset_backend(new_backend: CacheBackend | None = None) -> None:
    """Reset cache backend (e.g. after config change or in tests)."""
    global _backend
    _backend = new_backend


# ---------------------------------------------------------------------------
# Convenience functions (public API)
# ---------------------------------------------------------------------------


async def cache_get(key: str) -> Any | None:  # noqa: ANN401
    try:
        return await get_backend().get(key)
    except Exception as exc:
        log.warning("Cache read failed (%s)", type(exc).__name__)
        return None


async def cache_set(key: str, value: Any, ttl: int | None = None) -> None:  # noqa: ANN401
    try:
        await get_backend().set(key, value, ttl if ttl is not None else _default_ttl)
    except Exception as exc:
        log.warning("Cache write failed (%s)", type(exc).__name__)


async def cache_delete(key: str) -> None:
    try:
        await get_backend().delete(key)
    except Exception as exc:
        log.warning("Cache invalidation failed (%s)", type(exc).__name__)


async def cache_flush() -> None:
    await get_backend().flush()


def cache_backend_info() -> str:
    return get_backend().info()


def cache_namespace() -> str:
    """Return the internal cache-format namespace for operator diagnostics."""
    return CACHE_NAMESPACE


async def cache_health(*, read_only: bool = False) -> tuple[bool, str]:
    """Probe the backend with an isolated, short-lived ArborPress key."""
    backend = get_backend()
    if isinstance(backend, NamespacedBackend):
        backend = backend.probe_backend
    if isinstance(backend, TwoLevelBackend):
        backend = backend._l2
    key = f"_health:{secrets.token_hex(8)}"
    try:
        if read_only:
            await backend.get(key)
            return True, "read_reachable"
        await backend.set(key, "ok", 5)
        value = await backend.get(key)
        await backend.delete(key)
        if value != "ok":
            return False, "read_after_write_failed"
        return True, "ok"
    except Exception as exc:
        log.warning("Cache health probe failed (%s)", type(exc).__name__)
        return False, type(exc).__name__
