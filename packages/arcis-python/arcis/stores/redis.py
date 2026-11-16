"""
Arcis Redis Rate Limit Store
==============================

Distributed rate limiting using Redis as the backing store. Every counted
request is one atomic round trip: a Lua script runs ``INCR``, ``PEXPIRE``
on the first hit and ``PTTL``, so concurrent requests from any number of
server instances never admit more than the limit.

Errors are raised, not swallowed. The limiter decides what happens on an
outage (the sync ``RateLimiter`` falls back to memory, ``AsyncRateLimiter``
allows the request) and logs the error at most once per window.

Usage (sync: Flask, Django):
    from redis import Redis
    from arcis.stores.redis import RedisRateLimitStore
    from arcis import RateLimiter

    redis_client = Redis(host='localhost', port=6379)
    store = RedisRateLimitStore(redis_client)
    limiter = RateLimiter(max_requests=100, window_ms=60000, store=store)

Usage (async: FastAPI):
    import redis.asyncio as redis
    from arcis.stores.redis import AsyncRedisRateLimitStore
    from arcis.fastapi import ArcisMiddleware, AsyncRateLimiter

    redis_client = redis.Redis(host='localhost', port=6379)
    store = AsyncRedisRateLimitStore(redis_client)
    app.add_middleware(ArcisMiddleware, async_rate_limiter=AsyncRateLimiter(store=store))

Requires:
    pip install arcis[redis]
    # or: pip install redis
"""

import time
from dataclasses import dataclass
from typing import Any, Optional, Tuple

from ..core.types import RateLimitEntry


@dataclass
class RedisStoreOptions:
    """Configuration options for the Redis rate limit store."""

    key_prefix: str = "arcis:ratelimit:"
    """Prefix applied to all Redis keys."""

    window_ms: int = 60000
    """Unused. The limiter passes its window on every increment."""

    ttl_buffer_seconds: int = 1
    """Unused. Keys expire exactly when their window ends."""

    use_lua_script: bool = True
    """Unused. The atomic Lua script is always used."""


# KEYS[1] = counter key, ARGV[1] = window in milliseconds.
# Returns {total_hits, ttl_ms}.
_INCREMENT_SCRIPT = """
local hits = redis.pcall('INCR', KEYS[1])
if type(hits) == 'table' and hits['err'] then
  -- An entry in the older hash format: replace it with a counter.
  redis.call('DEL', KEYS[1])
  hits = redis.call('INCR', KEYS[1])
end
if hits == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {hits, ttl}
"""

# Decrement floored at zero.
_DECREMENT_SCRIPT = """
local hits = tonumber(redis.call('GET', KEYS[1]))
if hits and hits > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
"""


def _to_result(raw: Any) -> Tuple[int, float]:
    hits, ttl_ms = raw
    return int(hits), time.time() + int(ttl_ms) / 1000


def _to_entry(value: Any, ttl_ms: Any) -> Optional[RateLimitEntry]:
    # PTTL is -2 for a missing key and -1 for a key without expiry.
    if value is None or ttl_ms is None or int(ttl_ms) <= 0:
        return None
    return RateLimitEntry(count=int(value), reset_time=time.time() + int(ttl_ms) / 1000)


class RedisRateLimitStore:
    """
    Redis-backed rate limit store for sync frameworks (Flask, Django).

    - One atomic round trip per counted request (Lua: INCR, PEXPIRE, PTTL)
    - Keys expire with their window (no cleanup thread needed)
    - Raises Redis errors so the limiter's fallback and reporting run
    - Thread-safe for multi-threaded WSGI servers

    Example:
        from redis import Redis
        from arcis.stores.redis import RedisRateLimitStore
        from arcis import RateLimiter

        store = RedisRateLimitStore(Redis(host='localhost', port=6379))
        limiter = RateLimiter(max_requests=100, window_ms=60000, store=store)
    """

    def __init__(
        self,
        redis_client,
        options: Optional[RedisStoreOptions] = None,
        key_prefix: Optional[str] = None,
        window_ms: Optional[int] = None,
    ):
        """Create the store.

        Args:
            redis_client: A ``redis.Redis`` client.
            options: Store options; only ``key_prefix`` is used.
            key_prefix: Overrides ``options.key_prefix``.
            window_ms: Unused; the limiter passes its window on each call.
        """
        self._redis = redis_client
        opts = options or RedisStoreOptions()
        self._key_prefix = key_prefix or opts.key_prefix
        self._increment_script = self._redis.register_script(_INCREMENT_SCRIPT)
        self._decrement_script = self._redis.register_script(_DECREMENT_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"

    def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        """Count one hit atomically; return ``(total_hits, reset_time)`` in seconds."""
        return _to_result(self._increment_script(keys=[self._key(key)], args=[int(window_ms)]))

    def decrement(self, key: str) -> None:
        """Remove one hit, floored at zero."""
        self._decrement_script(keys=[self._key(key)])

    def reset_key(self, key: str) -> None:
        """Delete the counter for ``key``."""
        self._redis.delete(self._key(key))

    def get(self, key: str) -> Optional[RateLimitEntry]:
        """Return the current entry with ``reset_time`` in seconds, or None."""
        pipe = self._redis.pipeline()
        pipe.get(self._key(key))
        pipe.pttl(self._key(key))
        value, ttl_ms = pipe.execute()
        return _to_entry(value, ttl_ms)

    def cleanup(self) -> None:
        """No-op: Redis TTL handles expiry."""

    def close(self) -> None:
        """No-op: the Redis client belongs to the caller and stays open."""

    def ping(self) -> bool:
        """Return True when Redis answers a PING."""
        try:
            return bool(self._redis.ping())
        except Exception:
            return False


class AsyncRedisRateLimitStore:
    """
    Async Redis-backed rate limit store for async frameworks (FastAPI, aiohttp).

    Uses ``redis.asyncio``. Same atomic script and error behavior as
    :class:`RedisRateLimitStore`.

    Example:
        import redis.asyncio as redis
        from arcis.stores.redis import AsyncRedisRateLimitStore
        from arcis.fastapi import ArcisMiddleware, AsyncRateLimiter

        store = AsyncRedisRateLimitStore(redis.Redis(host='localhost', port=6379))
        app.add_middleware(ArcisMiddleware, async_rate_limiter=AsyncRateLimiter(store=store))
    """

    def __init__(
        self,
        redis_client,
        options: Optional[RedisStoreOptions] = None,
        key_prefix: Optional[str] = None,
        window_ms: Optional[int] = None,
    ):
        """Create the store.

        Args:
            redis_client: A ``redis.asyncio.Redis`` client.
            options: Store options; only ``key_prefix`` is used.
            key_prefix: Overrides ``options.key_prefix``.
            window_ms: Unused; the limiter passes its window on each call.
        """
        self._redis = redis_client
        opts = options or RedisStoreOptions()
        self._key_prefix = key_prefix or opts.key_prefix
        self._increment_script = self._redis.register_script(_INCREMENT_SCRIPT)
        self._decrement_script = self._redis.register_script(_DECREMENT_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"

    async def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        """Count one hit atomically; return ``(total_hits, reset_time)`` in seconds."""
        raw = await self._increment_script(keys=[self._key(key)], args=[int(window_ms)])
        return _to_result(raw)

    async def decrement(self, key: str) -> None:
        """Remove one hit, floored at zero."""
        await self._decrement_script(keys=[self._key(key)])

    async def reset_key(self, key: str) -> None:
        """Delete the counter for ``key``."""
        await self._redis.delete(self._key(key))

    async def get(self, key: str) -> Optional[RateLimitEntry]:
        """Return the current entry with ``reset_time`` in seconds, or None."""
        pipe = self._redis.pipeline()
        pipe.get(self._key(key))
        pipe.pttl(self._key(key))
        value, ttl_ms = await pipe.execute()
        return _to_entry(value, ttl_ms)

    async def cleanup(self) -> None:
        """No-op: Redis TTL handles expiry."""

    async def close(self) -> None:
        """No-op: the Redis client belongs to the caller and stays open."""

    async def ping(self) -> bool:
        """Return True when Redis answers a PING."""
        try:
            return bool(await self._redis.ping())
        except Exception:
            return False
