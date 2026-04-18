"""
Arcis In-Memory Rate Limit Store

Thread-safe in-memory store for rate limiting.
"""

import time
import threading
from typing import Dict, Optional

from ..core.types import RateLimitEntry


DEFAULT_MAX_SIZE = 10_000


class InMemoryStore:
    """Thread-safe in-memory store for rate limiting."""
    def __init__(self, max_size: int = DEFAULT_MAX_SIZE):
        if max_size < 1:
            raise ValueError(f"max_size must be >= 1, got {max_size}")
        self._store: Dict[str, RateLimitEntry] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._max_size = max_size

    def get(self, key: str) -> Optional[RateLimitEntry]:
        """Return the rate limit entry for key, or None if missing/expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry and entry.reset_time < time.time():
                del self._store[key]
                return None
            return entry

    def set(self, key: str, count: int, reset_time: float):
        """Store a rate limit entry with the given count and reset timestamp."""
        with self._lock:
            if key not in self._store and len(self._store) >= self._max_size:
                self._evict_expired()
                # If still at capacity after eviction, fail open — don't crash the app
                if len(self._store) >= self._max_size:
                    return
            self._store[key] = RateLimitEntry(count=count, reset_time=reset_time)

    def increment(self, key: str) -> int:
        """Increment the request count for a key. Returns 1 if key not found (race condition
        edge case — caller's set() was cleaned up between get() and increment()). The next
        request will re-create the entry via set()."""
        with self._lock:
            entry = self._store.get(key)
            if entry:
                entry.count += 1
                return entry.count
            return 1

    def increment_or_set(self, key: str, window_seconds: float) -> tuple:
        """Atomically increment an existing entry or create a new one.

        Eliminates the get()+set()/increment() race condition where two concurrent
        threads both see count=N, both increment, and both are allowed through.

        Returns (count, reset_time) under a single lock acquisition.
        """
        with self._lock:
            now = time.time()
            entry = self._store.get(key)
            if entry is None or entry.reset_time < now:
                reset_time = now + window_seconds
                if key not in self._store and len(self._store) >= self._max_size:
                    self._evict_expired()
                    if len(self._store) >= self._max_size:
                        return 1, reset_time  # fail open
                self._store[key] = RateLimitEntry(count=1, reset_time=reset_time)
                return 1, reset_time
            entry.count += 1
            return entry.count, entry.reset_time

    def _evict_expired(self):
        """Remove expired entries (must be called with lock held)."""
        now = time.time()
        expired = [k for k, v in self._store.items() if v.reset_time < now]
        for k in expired:
            del self._store[k]

    def cleanup(self):
        """Remove expired entries."""
        with self._lock:
            self._evict_expired()

    def clear(self):
        """Clear all entries."""
        with self._lock:
            self._store.clear()

    def close(self):
        """Mark store as closed."""
        self._closed = True
        self.clear()
