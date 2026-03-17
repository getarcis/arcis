"""
Arcis Middleware - Sliding Window Rate Limiter

More accurate than fixed window — uses a weighted sum of the previous
and current window to approximate a true sliding window.

Algorithm:
    weight = (window_sec - elapsed) / window_sec
    count = (prev_window * weight) + current_window
    allow = count < limit

Examples:
    limiter = SlidingWindowLimiter(max_requests=100, window='15m')
    result = limiter.check(request)
"""

import time
import threading
import atexit
import math
from typing import Any, Callable, Dict, Optional, Union

from ..utils.duration import parse_duration
from ..core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE


class SlidingWindowLimiter:
    """
    Sliding window rate limiter.

    Uses weighted sum of previous and current window counts
    to approximate a true sliding window without per-request storage.

    Example:
        limiter = SlidingWindowLimiter(max_requests=100, window='15m')
        try:
            result = limiter.check(request)
        except RateLimitExceeded as e:
            return error_response(e.message, e.retry_after)
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window: Union[str, int] = DEFAULT_WINDOW_MS,
        message: str = DEFAULT_RATE_LIMIT_MESSAGE,
        key_func: Optional[Callable] = None,
        skip_func: Optional[Callable] = None,
    ):
        if max_requests < 1:
            raise ValueError(f"max_requests must be >= 1, got {max_requests}")

        self.max_requests = max_requests
        self.window_ms = parse_duration(window)
        if self.window_ms < 1:
            raise ValueError(f"window must be > 0, got {window}")
        self.window_sec = self.window_ms / 1000
        self.message = message
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._closed = False
        self._lock = threading.Lock()

        # Two windows per key
        self._current: Dict[str, Dict[str, Any]] = {}
        self._previous: Dict[str, Dict[str, Any]] = {}

        # Cleanup thread
        self._cleanup_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        atexit.register(self.close)

    def _default_key_func(self, request) -> str:
        """Default key function - uses client IP address."""
        from ..utils.ip import detect_client_ip
        return detect_client_ip(request)

    def _cleanup_loop(self):
        """Background cleanup of expired windows."""
        # Clamp interval: min 10s, max 300s regardless of window size
        cleanup_interval = max(10, min(300, self.window_sec))
        while not self._cleanup_event.wait(timeout=cleanup_interval):
            if self._closed:
                break
            now = time.time()
            cutoff = now - self.window_sec * 2
            with self._lock:
                expired = [k for k, v in self._previous.items() if v['start'] < cutoff]
                for k in expired:
                    del self._previous[k]
                expired = [k for k, v in self._current.items() if v['start'] < cutoff]
                for k in expired:
                    del self._current[k]

    def close(self):
        """Stop cleanup thread and release resources."""
        if self._closed:
            return
        self._closed = True
        self._cleanup_event.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)
        atexit.unregister(self.close)

    def check(self, request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.

        Returns:
            Dict with limit info: allowed, limit, remaining, reset, retry_after.

        Raises:
            SlidingWindowRateLimitExceeded: If rate limit is exceeded.
        """
        if self._closed:
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

        if self.skip_func and self.skip_func(request):
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

        key = self.key_func(request)
        now = time.time()
        window_start = math.floor(now / self.window_sec) * self.window_sec

        with self._lock:
            # Rotate windows if needed
            if key not in self._current or self._current[key]['start'] < window_start:
                if key in self._current:
                    self._previous[key] = self._current[key]
                self._current[key] = {'count': 0, 'start': window_start}

            # Calculate weighted count BEFORE incrementing
            elapsed = now - window_start
            weight = max(0, (self.window_sec - elapsed) / self.window_sec)
            prev_count = self._previous.get(key, {}).get('count', 0)
            estimated = (prev_count * weight) + self._current[key]['count'] + 1

            reset = max(1, math.ceil(window_start + self.window_sec - now))

            if estimated > self.max_requests:
                # Don't increment — rejected requests should not consume quota
                from ..middleware.rate_limit import RateLimitExceeded
                raise RateLimitExceeded(self.message, reset)

            # Only increment on allowed requests
            self._current[key]['count'] += 1

        remaining = max(0, int(self.max_requests - estimated))

        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }
