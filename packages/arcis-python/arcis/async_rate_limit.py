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
from typing import Any, Callable, Dict, Optional, Protocol

from starlette.requests import Request

from .core.types import RateLimitEntry
from .core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE
from .utils.ip import detect_client_ip

logger = logging.getLogger(__name__)


# ============================================================================
# ASYNC RATE LIMITER STORE PROTOCOL
# ============================================================================

class AsyncRateLimitStore(Protocol):
    """Protocol for async rate limit stores (e.g., Redis with aioredis)."""
    
    async def get(self, key: str) -> Optional[RateLimitEntry]:
        """Get rate limit entry for a key."""
        ...
    
    async def set(self, key: str, count: int, reset_time: float) -> None:
        """Set rate limit entry for a key."""
        ...
    
    async def increment(self, key: str) -> int:
        """Increment count for a key and return new count."""
        ...
    
    async def cleanup(self) -> None:
        """Remove expired entries."""
        ...
    
    async def close(self) -> None:
        """Close the store and release resources."""
        ...


# ============================================================================
# ASYNC IN-MEMORY STORE
# ============================================================================

class AsyncInMemoryStore:
    """
    Async-safe in-memory store for rate limiting.
    
    Uses asyncio.Lock for thread safety in async context.
    Suitable for single-instance deployments with async frameworks.
    """
    
    def __init__(self):
        self._store: Dict[str, RateLimitEntry] = {}
        self._lock = asyncio.Lock()
        self._closed = False
        self._cleanup_task: Optional[asyncio.Task] = None
    
    async def get(self, key: str) -> Optional[RateLimitEntry]:
        """Get rate limit entry for a key."""
        async with self._lock:
            entry = self._store.get(key)
            if entry and entry.reset_time < time.time():
                del self._store[key]
                return None
            return entry
    
    async def set(self, key: str, count: int, reset_time: float) -> None:
        """Set rate limit entry for a key."""
        async with self._lock:
            self._store[key] = RateLimitEntry(count=count, reset_time=reset_time)
    
    async def increment(self, key: str) -> int:
        """Increment count for a key. Returns 1 if key not found (race condition
        edge case — caller's set() was cleaned up between get() and increment()). The next
        request will re-create the entry via set()."""
        async with self._lock:
            entry = self._store.get(key)
            if entry:
                entry.count += 1
                return entry.count
            return 1
    
    async def cleanup(self) -> None:
        """Remove expired entries."""
        async with self._lock:
            now = time.time()
            expired = [k for k, v in self._store.items() if v.reset_time < now]
            for k in expired:
                del self._store[k]
    
    async def clear(self) -> None:
        """Clear all entries."""
        async with self._lock:
            self._store.clear()
    
    async def close(self) -> None:
        """Mark store as closed and cancel cleanup task."""
        self._closed = True
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        await self.clear()


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
    Async rate limiter for FastAPI and other async frameworks.
    
    Uses asyncio-native locking and supports pluggable async stores
    (e.g., aioredis for distributed rate limiting).
    
    Example:
        limiter = AsyncRateLimiter(max_requests=100, window_ms=60000)
        
        # In middleware or dependency
        result = await limiter.check(request)
        
        # With custom async store (e.g., Redis)
        from arcis.stores.redis import AsyncRedisRateLimitStore
        import redis.asyncio as redis
        
        redis_client = redis.Redis()
        store = AsyncRedisRateLimitStore(redis_client)
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
    ):
        if max_requests < 1:
            raise ValueError(f"max_requests must be >= 1, got {max_requests}")
        if window_ms < 1:
            raise ValueError(f"window_ms must be >= 1, got {window_ms}")

        self.max_requests = max_requests
        self.window_seconds = window_ms / 1000
        self.window_ms = window_ms
        self.message = message
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._closed = False
        
        # Use provided store or create async in-memory store
        self._store_provided = store is not None
        self.store = store or AsyncInMemoryStore()
        
        # Cleanup task for in-memory store
        self._cleanup_task: Optional[asyncio.Task] = None
        # Lock prevents concurrent first requests from each spawning a cleanup task
        self._cleanup_lock: Optional[asyncio.Lock] = None

    def _default_key_func(self, request: Request) -> str:
        """Default key function. Uses the real client IP.

        SECURITY: delegates to ``detect_client_ip`` which parses
        ``X-Forwarded-For`` from the right (proxy-appended end) and prefers
        platform-specific spoofproof headers (Cloudflare, Vercel, Fly.io,
        etc.). Reading XFF from the left is spoofable: an attacker can
        prepend an arbitrary value and be rate-limited under that key.
        """
        # FastAPI/Starlette: socket peer address is always trustworthy
        if hasattr(request, 'client') and request.client:
            host = request.client.host
            if host:
                return host

        return detect_client_ip(request) or "unknown"
    
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
            # Re-check under lock — another coroutine may have started it
            if self._cleanup_task is not None:
                return

            async def cleanup_loop():
                while not self._closed:
                    try:
                        await asyncio.sleep(self.window_seconds)
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
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}
        
        # Start cleanup task if not already running
        if self._cleanup_task is None and not self._store_provided:
            await self._start_cleanup()
        
        # Check skip function
        if self.skip_func:
            should_skip = self.skip_func(request)
            if asyncio.iscoroutine(should_skip):
                should_skip = await should_skip
            if should_skip:
                return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}
        
        key = self.key_func(request)
        # Mirror the skip_func async-handling pattern: if the user passed
        # an async key_func, await it. Without this, the returned coroutine
        # would silently be used as the rate-limit key, breaking per-IP
        # isolation entirely.
        if asyncio.iscoroutine(key):
            key = await key
        now = time.time()

        entry = await self.store.get(key)
        
        if not entry or entry.reset_time < now:
            # New window. Compute reset as the same `reset_time - now`
            # delta that the subsequent-request branch uses so clients
            # see a consistent representation across the whole window.
            reset_time = now + self.window_seconds
            await self.store.set(key, 1, reset_time)
            return {
                "allowed": True,
                "limit": self.max_requests,
                "remaining": self.max_requests - 1,
                "reset": int(reset_time - now),
            }

        count = await self.store.increment(key)
        remaining = max(0, self.max_requests - count)
        reset = int(entry.reset_time - now)
        
        if count > self.max_requests:
            raise AsyncRateLimitExceeded(self.message, max(0, reset))
        
        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": max(0, reset),
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
        
        await self.store.close()
