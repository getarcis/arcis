"""
Arcis Middleware - Rate Limiter

RateLimitExceeded exception and RateLimiter class.
"""

import time
import threading
import atexit
import weakref
from typing import Any, Callable, Dict, Optional

from ..stores.memory import InMemoryStore
from ..core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 0):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


def _finalize_cleanup(cleanup_event: threading.Event,
                      cleanup_thread: Optional[threading.Thread],
                      store: Any) -> None:
    """Module-level finalizer for RateLimiter. Used via weakref.finalize so
    GC of a RateLimiter triggers cleanup of its daemon thread + store
    without keeping the limiter alive. Test reruns and hot-reload now
    don't leak threads."""
    try:
        cleanup_event.set()
    except Exception:
        pass
    try:
        if cleanup_thread is not None and cleanup_thread.is_alive():
            cleanup_thread.join(timeout=1.0)
    except Exception:
        pass
    try:
        if store is not None and hasattr(store, "close"):
            store.close()
    except Exception:
        pass


class RateLimiter:
    """
    Rate limiter with configurable limits and window sizes.

    Example:
        limiter = RateLimiter(max_requests=100, window_ms=60000)
        try:
            result = limiter.check(request)
        except RateLimitExceeded as e:
            return error_response(e.message, e.retry_after)
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_ms: int = DEFAULT_WINDOW_MS,
        message: str = DEFAULT_RATE_LIMIT_MESSAGE,
        key_func: Optional[Callable] = None,
        skip_func: Optional[Callable] = None,
        store: Optional[InMemoryStore] = None,
    ):
        if max_requests < 1:
            raise ValueError(f"max_requests must be >= 1, got {max_requests}")
        if window_ms < 1:
            raise ValueError(f"window_ms must be >= 1, got {window_ms}")

        self.max_requests = max_requests
        self.window_seconds = window_ms / 1000
        self.message = message
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._store_provided = store is not None
        self.store = store or InMemoryStore()
        self._closed = False
        self._fallback_lock = threading.Lock()

        # Start cleanup thread only for in-memory store
        # External stores (e.g. Redis) handle their own expiry
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_event = threading.Event()
        if not self._store_provided:
            self._start_cleanup_thread()

        # Register cleanup on exit (covers normal shutdown).
        atexit.register(self.close)
        # Also fire close() when the RateLimiter is garbage-collected so
        # test reruns and hot-reload workflows don't leak daemon threads.
        # `weakref.finalize` args don't pin `self`; only the store/event
        # are referenced, which is exactly what cleanup needs.
        self._finalizer = weakref.finalize(
            self, _finalize_cleanup, self._cleanup_event, self._cleanup_thread, self.store
        )

    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        def cleanup_loop():
            while not self._cleanup_event.wait(timeout=self.window_seconds):
                if self._closed:
                    break
                self.store.cleanup()

        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def close(self):
        """Stop cleanup thread and release resources."""
        if self._closed:
            return
        self._closed = True
        self._cleanup_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)
        self.store.close()

    def _default_key_func(self, request) -> str:
        """Default key function - uses client IP address.

        Delegates to detect_client_ip() which reads X-Forwarded-For from the
        right (proxy-appended end) to prevent trivial IP spoofing bypasses.
        """
        from ..utils.ip import detect_client_ip
        return detect_client_ip(request)

    def check(self, request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.
        Returns dict with limit info and raises RateLimitExceeded if exceeded.
        """
        if self._closed:
            # Fail open if closed
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

        if self.skip_func and self.skip_func(request):
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

        key = self.key_func(request)

        # Use atomic increment_or_set when available (InMemoryStore) to avoid the
        # get()+increment() race where two concurrent threads both see count=N and
        # both get allowed. External stores (Redis) handle atomicity via INCR.
        if hasattr(self.store, 'increment_or_set'):
            count, reset_time = self.store.increment_or_set(key, self.window_seconds)
            now = time.time()
            reset = max(0, int(reset_time - now))
        else:
            # Serialize get+increment to prevent TOCTOU race where two threads
            # both see count=N and both pass through.
            with self._fallback_lock:
                now = time.time()
                entry = self.store.get(key)
                if not entry:
                    self.store.set(key, 1, now + self.window_seconds)
                    return {
                        "allowed": True,
                        "limit": self.max_requests,
                        "remaining": self.max_requests - 1,
                        "reset": int(self.window_seconds),
                    }
                count = self.store.increment(key)
                reset = max(0, int(entry.reset_time - now))

        remaining = max(0, self.max_requests - count)

        if count > self.max_requests:
            raise RateLimitExceeded(self.message, reset)

        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }
