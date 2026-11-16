"""Async rate limiter for FastAPI / Starlette and other async frameworks.

Extracted from ``fastapi.py`` (which re-exports these names, so
``from arcis.fastapi import AsyncRateLimiter`` keeps working). Holds the async
rate-limit store protocol, the in-memory store, the exceeded-exception, and the
``AsyncRateLimiter`` itself. Framework-agnostic beyond the Starlette ``Request``
type used by the default key function.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Dict, Optional, Protocol, Tuple, Union

from starlette.requests import Request

from .core.types import RateLimitEntry
from .core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE
from .middleware.rate_limit import (
    StoreErrorReporter,
    validate_max_requests,
    validate_window_ms,
)
from .stores.base import ensure_async_store
from .stores.memory import DEFAULT_MAX_SIZE, InMemoryStore
from .utils.ip import (
    DEFAULT_IPV6_SUBNET,
    TrustedProxies,
    rate_limit_key,
    validate_ipv6_subnet,
    validate_trusted_proxies,
)

logger = logging.getLogger(__name__)


# ============================================================================
# ASYNC RATE LIMITER STORE PROTOCOL
# ============================================================================

class AsyncRateLimitStore(Protocol):
    """Protocol for async rate limit stores (e.g. Redis with redis.asyncio).

    ``increment`` is the one atomic call per counted request; it creates the
    counter and its expiry together. Stores raise their errors.
    """

    async def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        """Count one hit; return ``(total_hits, reset_time)`` in Unix seconds."""
        ...

    async def decrement(self, key: str) -> None:
        """Remove one hit, floored at zero."""
        ...

    async def reset_key(self, key: str) -> None:
        """Forget a key."""
        ...


# ============================================================================
# ASYNC IN-MEMORY STORE
# ============================================================================

class AsyncInMemoryStore:
    """
    Async facade over :class:`~arcis.stores.memory.InMemoryStore`.

    Every operation is a short critical section under a threading lock with
    no awaits inside, so it is atomic across coroutines and threads. Same
    size cap and eviction (expired first, then least recently used).
    Suitable for single-instance deployments with async frameworks.
    """

    def __init__(self, max_size: int = DEFAULT_MAX_SIZE):
        self._memory = InMemoryStore(max_size)
        self._closed = False

    async def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        """Count one hit; return ``(total_hits, reset_time)``."""
        return self._memory.increment(key, window_ms)

    async def decrement(self, key: str) -> None:
        """Remove one hit, floored at zero."""
        self._memory.decrement(key)

    async def reset_key(self, key: str) -> None:
        """Forget a key."""
        self._memory.reset_key(key)

    async def get(self, key: str) -> Optional[RateLimitEntry]:
        """Return the entry for a key, or None if missing or expired."""
        return self._memory.get(key)

    async def cleanup(self) -> None:
        """Remove expired entries."""
        self._memory.cleanup()

    async def clear(self) -> None:
        """Clear all entries."""
        self._memory.clear()

    async def close(self) -> None:
        """Mark store as closed and drop its entries."""
        self._closed = True
        self._memory.close()


# ============================================================================
# ASYNC RATE LIMITER
# ============================================================================

class AsyncRateLimitExceeded(Exception):
    """Exception raised when async rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 0):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


class AsyncRateLimiter:
    """
    Async fixed-window rate limiter for FastAPI and other async frameworks.

    Each counted request makes one atomic ``await store.increment(key,
    window_ms)`` call, so several instances sharing a Redis store never admit
    more than ``max_requests`` per window. When the store fails the request
    is allowed (fail open) and the error is logged at most once per window.

    The default key is the client IP from the trust-aware resolver passed
    through ``ip_key_generator``. Forwarded headers count only when the
    socket peer (``scope["client"]``) is in ``trusted_proxies``.

    Example:
        limiter = AsyncRateLimiter(max_requests=100, window_ms=60000)

        # In middleware or dependency
        result = await limiter.check(request)

        # With a shared Redis store
        from arcis.stores.redis import AsyncRedisRateLimitStore
        import redis.asyncio as redis

        store = AsyncRedisRateLimitStore(redis.Redis())
        limiter = AsyncRateLimiter(store=store)
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_ms: int = DEFAULT_WINDOW_MS,
        message: str = DEFAULT_RATE_LIMIT_MESSAGE,
        key_func: Optional[Callable] = None,
        skip_func: Optional[Callable] = None,
        store: Optional[AsyncRateLimitStore] = None,
        trusted_proxies: TrustedProxies = None,
        ipv6_subnet: Union[int, bool] = DEFAULT_IPV6_SUBNET,
    ):
        """Create a limiter. Arguments match :class:`arcis.RateLimiter`.

        Raises:
            ValueError: On an invalid limit, window, proxy entry or subnet.
        """
        self.max_requests = validate_max_requests(max_requests)
        self.window_ms = validate_window_ms(window_ms)
        self.window_seconds = self.window_ms / 1000
        self.message = message
        validate_trusted_proxies(trusted_proxies)
        self.trusted_proxies = trusted_proxies
        self.ipv6_subnet = validate_ipv6_subnet(ipv6_subnet)
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._closed = False
        self._error_reporter = StoreErrorReporter(self.window_seconds, "allowing the request")

        # Use provided store or create async in-memory store
        self._store_provided = store is not None
        self.store = ensure_async_store(store) if store is not None else AsyncInMemoryStore()

        # Cleanup task for in-memory store
        self._cleanup_task: Optional[asyncio.Task] = None
        # Lock prevents concurrent first requests from each spawning a cleanup task
        self._cleanup_lock: Optional[asyncio.Lock] = None

    def _default_key_func(self, request: Request) -> str:
        """Default key: trust-aware client IP through ``ip_key_generator``."""
        return rate_limit_key(request, self.trusted_proxies, self.ipv6_subnet)

    def _allowed_without_counting(self) -> Dict[str, Any]:
        return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

    async def _start_cleanup(self) -> None:
        """Start background cleanup task for in-memory store.

        Uses a lock so concurrent first requests don't each spawn a task.
        Lock is lazily created on first call (must be inside running loop).
        """
        if self._store_provided:
            return  # External stores handle their own cleanup

        if self._cleanup_lock is None:
            self._cleanup_lock = asyncio.Lock()

        async with self._cleanup_lock:
            # Re-check under lock: another coroutine may have started it
            if self._cleanup_task is not None:
                return

            # At least one second between sweeps so tiny windows do not spin.
            interval = max(1.0, self.window_seconds)

            async def cleanup_loop():
                while not self._closed:
                    try:
                        await asyncio.sleep(interval)
                        if not self._closed:
                            await self.store.cleanup()
                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        logger.error("Async rate limiter cleanup error: %s", e)

            self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def check(self, request: Request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.
        
        Returns dict with limit info and raises AsyncRateLimitExceeded if exceeded.
        
        Args:
            request: The FastAPI/Starlette request
            
        Returns:
            Dict with keys: allowed, limit, remaining, reset
            
        Raises:
            AsyncRateLimitExceeded: If rate limit is exceeded
        """
        if self._closed:
            return self._allowed_without_counting()

        # Start cleanup task if not already running
        if self._cleanup_task is None and not self._store_provided:
            await self._start_cleanup()

        # Check skip function
        if self.skip_func:
            should_skip = self.skip_func(request)
            if asyncio.iscoroutine(should_skip):
                should_skip = await should_skip
            if should_skip:
                return self._allowed_without_counting()

        key = self.key_func(request)
        # Mirror the skip_func async-handling pattern: if the user passed
        # an async key_func, await it. Without this, the returned coroutine
        # would silently be used as the rate-limit key, breaking per-IP
        # isolation entirely.
        if asyncio.iscoroutine(key):
            key = await key

        try:
            count, reset_time = await self.store.increment(key, self.window_ms)
        except Exception as exc:
            # Store outage: fail open, report once per window.
            self._error_reporter.report(exc)
            return self._allowed_without_counting()

        reset = max(0, int(reset_time - time.time()))
        remaining = max(0, self.max_requests - count)

        if count > self.max_requests:
            raise AsyncRateLimitExceeded(self.message, reset)

        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }

    async def close(self) -> None:
        """Stop cleanup task and release resources."""
        if self._closed:
            return
        self._closed = True
        
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        close = getattr(self.store, "close", None)
        if close is not None:
            await close()
