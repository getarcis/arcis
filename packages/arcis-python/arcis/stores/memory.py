"""
Arcis In-Memory Rate Limit Store

Thread-safe in-memory store implementing the atomic rate-limit contract
(spec/API_SPEC.md, "Store contract and counting").
"""

import time
import threading
from collections import OrderedDict
from typing import Optional, Tuple

from ..core.types import RateLimitEntry


DEFAULT_MAX_SIZE = 10_000

# A full expiry sweep is O(size). At the cap it runs at most this often so a
# flood of new keys cannot turn every insert into a full scan; between
# sweeps the least recently used key makes room.
_SWEEP_INTERVAL_SECONDS = 1.0


class InMemoryStore:
    """Thread-safe in-memory store for rate limiting.

    Fixed window per key starting at its first hit. At ``max_size`` keys the
    store evicts expired keys first, then the least recently used, so it
    never stops limiting new keys.
    """

    def __init__(self, max_size: int = DEFAULT_MAX_SIZE):
        if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size < 1:
            raise ValueError(f"max_size must be an integer >= 1, got {max_size!r}")
        self._store: "OrderedDict[str, RateLimitEntry]" = OrderedDict()
        self._lock = threading.Lock()
        self._closed = False
        self._max_size = max_size
        self._last_sweep = 0.0

    def increment(self, key: str, window_ms: int) -> Tuple[int, float]:
        """Count one hit for ``key``.

        Creates the counter and its expiry together when the key is new or
        its window has ended.

        Args:
            key: Rate-limit key.
            window_ms: Window length in milliseconds.

        Returns:
            ``(total_hits, reset_time)``, reset_time a Unix timestamp in seconds.
        """
        with self._lock:
            now = time.time()
            entry = self._store.get(key)
            if entry is not None and entry.reset_time > now:
                entry.count += 1
                self._store.move_to_end(key)
                return entry.count, entry.reset_time
            if entry is None and len(self._store) >= self._max_size:
                self._make_room(now)
            reset_time = now + window_ms / 1000
            self._store[key] = RateLimitEntry(count=1, reset_time=reset_time)
            self._store.move_to_end(key)
            return 1, reset_time

    def decrement(self, key: str) -> None:
        """Remove one hit from ``key``, never going below zero."""
        with self._lock:
            entry = self._store.get(key)
            if entry is not None and entry.count > 0:
                entry.count -= 1

    def reset_key(self, key: str) -> None:
        """Forget ``key``."""
        with self._lock:
            self._store.pop(key, None)

    def get(self, key: str) -> Optional[RateLimitEntry]:
        """Return a copy of the entry for ``key``, or None if missing or expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.reset_time <= time.time():
                del self._store[key]
                return None
            return RateLimitEntry(count=entry.count, reset_time=entry.reset_time)

    def _make_room(self, now: float) -> None:
        """Evict expired keys, then least recently used ones (lock held)."""
        if now - self._last_sweep >= _SWEEP_INTERVAL_SECONDS:
            self._last_sweep = now
            self._evict_expired(now)
        while len(self._store) >= self._max_size:
            self._store.popitem(last=False)

    def _evict_expired(self, now: float) -> None:
        """Remove expired entries (lock held)."""
        expired = [k for k, v in self._store.items() if v.reset_time <= now]
        for k in expired:
            del self._store[k]

    def cleanup(self) -> None:
        """Remove expired entries."""
        with self._lock:
            self._evict_expired(time.time())

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._store.clear()

    def close(self) -> None:
        """Mark store as closed."""
        self._closed = True
        self.clear()
