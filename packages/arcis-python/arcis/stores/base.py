"""
Arcis rate-limit store contract and the adapter for older stores.

Every counted request makes exactly one atomic call:
``increment(key, window_ms) -> (total_hits, reset_time)`` where
``reset_time`` is a Unix timestamp in seconds. The counter and its expiry
are created together; a get-then-set sequence is not allowed.
``decrement(key)`` (floored at 0), ``reset_key(key)`` and an optional
``get(key)`` complete the interface. Async stores expose the same methods
as coroutines. A store must raise its errors: the limiter decides whether
to fail open or fall back to memory, and reports the error.

Stores written for the older ``get`` / ``set`` / ``increment(key)``
interface keep working through :func:`ensure_store` and
:func:`ensure_async_store`, which wrap them and warn once that the
sequence is not atomic across processes.
"""

import asyncio
import inspect
import logging
import threading
import time
from typing import Any, Optional, Protocol, Tuple

from ..core.types import RateLimitEntry

logger = logging.getLogger(__name__)

_warned_store_types: set = set()
_warned_lock = threading.Lock()


class RateLimitStore(Protocol):
    """Protocol for synchronous rate-limit stores."""

    def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        """Count one hit; return ``(total_hits, reset_time)``."""
        ...

    def decrement(self, key: str) -> None:
        """Remove one hit, floored at zero."""
        ...

    def reset_key(self, key: str) -> None:
        """Forget a key."""
        ...


def _supports_window(store: Any) -> bool:
    """True when ``store.increment`` accepts ``(key, window_ms)``."""
    method = getattr(store, 'increment', None)
    if not callable(method):
        return False
    try:
        inspect.signature(method).bind('key', 1)
    except TypeError:
        return False
    except ValueError:
        # No introspectable signature (C extension); assume the current contract.
        return True
    return True


def _warn_legacy(store: Any) -> None:
    name = type(store).__name__
    with _warned_lock:
        if name in _warned_store_types:
            return
        _warned_store_types.add(name)
    logger.warning(
        'arcis: rate-limit store %s uses the older get/set/increment(key) interface. '
        'It keeps working, but the read-then-write sequence is not atomic across '
        'processes, so concurrent requests can exceed the limit. Implement '
        'increment(key, window_ms) -> (total_hits, reset_time).',
        name,
    )


def _call_optional(store: Any, names: Tuple[str, ...], *args: Any) -> Any:
    for name in names:
        method = getattr(store, name, None)
        if callable(method):
            return method(*args)
    return None


class LegacyStoreAdapter:
    """Presents an older synchronous store through the atomic contract.

    Uses the store's own ``increment_or_set(key, window_seconds)`` when it has
    one, otherwise get then set/increment under a process-local lock.
    """

    def __init__(self, store: Any) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._increment_or_set = getattr(store, 'increment_or_set', None)
        if not callable(self._increment_or_set):
            self._increment_or_set = None
            missing = [n for n in ('get', 'set', 'increment') if not callable(getattr(store, n, None))]
            if missing:
                raise TypeError(
                    f"rate-limit store {type(store).__name__} must implement "
                    f"increment(key, window_ms); it is also missing {', '.join(missing)}"
                )

    def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        if self._increment_or_set is not None:
            count, reset_time = self._increment_or_set(key, window_ms / 1000)
            return int(count), float(reset_time)
        with self._lock:
            now = time.time()
            entry = self._store.get(key)
            if not entry or entry.reset_time <= now:
                reset_time = now + window_ms / 1000
                self._store.set(key, 1, reset_time)
                return 1, reset_time
            return int(self._store.increment(key)), float(entry.reset_time)

    def decrement(self, key: str) -> None:
        _call_optional(self._store, ('decrement',), key)

    def reset_key(self, key: str) -> None:
        _call_optional(self._store, ('reset_key', 'reset', 'delete'), key)

    def get(self, key: str) -> Optional[RateLimitEntry]:
        return _call_optional(self._store, ('get',), key)

    def cleanup(self) -> None:
        _call_optional(self._store, ('cleanup',))

    def close(self) -> None:
        _call_optional(self._store, ('close',))


class AsyncLegacyStoreAdapter:
    """Presents an older async store (get / set / increment(key)) atomically per process."""

    def __init__(self, store: Any) -> None:
        missing = [n for n in ('get', 'set', 'increment') if not callable(getattr(store, n, None))]
        if missing:
            raise TypeError(
                f"rate-limit store {type(store).__name__} must implement "
                f"increment(key, window_ms); it is also missing {', '.join(missing)}"
            )
        self._store = store
        self._lock: Optional[asyncio.Lock] = None

    async def _maybe_await(self, value: Any) -> Any:
        return await value if inspect.isawaitable(value) else value

    async def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.time()
            entry = await self._maybe_await(self._store.get(key))
            if not entry or entry.reset_time <= now:
                reset_time = now + window_ms / 1000
                await self._maybe_await(self._store.set(key, 1, reset_time))
                return 1, reset_time
            count = await self._maybe_await(self._store.increment(key))
            return int(count), float(entry.reset_time)

    async def decrement(self, key: str) -> None:
        await self._maybe_await(_call_optional(self._store, ('decrement',), key))

    async def reset_key(self, key: str) -> None:
        await self._maybe_await(_call_optional(self._store, ('reset_key', 'reset', 'delete'), key))

    async def get(self, key: str) -> Optional[RateLimitEntry]:
        return await self._maybe_await(_call_optional(self._store, ('get',), key))

    async def cleanup(self) -> None:
        await self._maybe_await(_call_optional(self._store, ('cleanup',)))

    async def close(self) -> None:
        await self._maybe_await(_call_optional(self._store, ('close',)))


def ensure_store(store: Any) -> Any:
    """Return ``store`` if it implements the atomic contract, else wrap it."""
    if _supports_window(store):
        return store
    adapter = LegacyStoreAdapter(store)
    _warn_legacy(store)
    return adapter


def ensure_async_store(store: Any) -> Any:
    """Async counterpart of :func:`ensure_store`."""
    if _supports_window(store):
        return store
    adapter = AsyncLegacyStoreAdapter(store)
    _warn_legacy(store)
    return adapter
