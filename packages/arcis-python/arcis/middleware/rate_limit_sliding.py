"""
Arcis Middleware - Sliding Window Rate Limiter

More accurate than fixed window: uses a weighted sum of the previous
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
from ..utils.ip import (
    DEFAULT_IPV6_SUBNET,
    TrustedProxies,
    rate_limit_key,
    validate_ipv6_subnet,
    validate_trusted_proxies,
)
from ..core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE
from .rate_limit import RateLimitExceeded, validate_max_requests, validate_window_ms


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
        trusted_proxies: TrustedProxies = None,
        ipv6_subnet: Union[int, bool] = DEFAULT_IPV6_SUBNET,
    ):
        """Create a limiter.

        Args:
            max_requests: Requests allowed per window; 0 blocks every request.
            window: Window as whole milliseconds or a duration string ('15m').
            message: Message carried by ``RateLimitExceeded``.
            key_func: ``request -> key``. Default: resolved client IP key.
            skip_func: ``request -> bool``; True skips counting.
            trusted_proxies: Proxy IPs / CIDR ranges whose X-Forwarded-For is
                honored. None uses the default private set; [] trusts none.
            ipv6_subnet: IPv6 prefix grouped into one key (1-128) or False.

        Raises:
            ValueError: On an invalid limit, window, proxy entry or subnet.
        """
        self.max_requests = validate_max_requests(max_requests)
        window_ms = parse_duration(window) if isinstance(window, str) else window
        self.window_ms = validate_window_ms(window_ms, "window")
        self.window_sec = self.window_ms / 1000
        self.message = message
        validate_trusted_proxies(trusted_proxies)
        self.trusted_proxies = trusted_proxies
        self.ipv6_subnet = validate_ipv6_subnet(ipv6_subnet)
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._closed = False
        self._lock = threading.Lock()

        # Two windows per key, each {'count': int, 'index': int} where index
        # is floor(now_ms / window_ms).
        self._current: Dict[str, Dict[str, int]] = {}
        self._previous: Dict[str, Dict[str, int]] = {}

        # Cleanup thread
        self._cleanup_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        atexit.register(self.close)

    def _default_key_func(self, request) -> str:
        """Default key: trust-aware client IP through ``ip_key_generator``."""
        return rate_limit_key(request, self.trusted_proxies, self.ipv6_subnet)

    def _window_index(self, now: float) -> int:
        return int((now * 1000) // self.window_ms)

    def _cleanup_loop(self):
        """Background cleanup of windows that can no longer count."""
        # Clamp interval: min 10s, max 300s regardless of window size
        cleanup_interval = max(10, min(300, self.window_sec))
        while not self._cleanup_event.wait(timeout=cleanup_interval):
            if self._closed:
                break
            # Only the window right before the current one still counts.
            oldest_useful = self._window_index(time.time()) - 1
            with self._lock:
                for windows in (self._previous, self._current):
                    expired = [k for k, v in windows.items() if v['index'] < oldest_useful]
                    for k in expired:
                        del windows[k]

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
        index = self._window_index(now)
        window_start = index * self.window_sec

        with self._lock:
            current = self._current.get(key)
            if current is None or current['index'] != index:
                # Rotate. The old current window becomes the previous one
                # only when it is the window immediately before this one; a
                # key idle for a full window starts from zero.
                if current is not None and current['index'] == index - 1:
                    self._previous[key] = current
                else:
                    self._previous.pop(key, None)
                current = {'count': 0, 'index': index}
                self._current[key] = current

            previous = self._previous.get(key)
            prev_count = previous['count'] if previous and previous['index'] == index - 1 else 0

            # Calculate weighted count BEFORE incrementing
            elapsed = now - window_start
            weight = max(0, (self.window_sec - elapsed) / self.window_sec)
            estimated = (prev_count * weight) + current['count'] + 1

            reset = max(1, math.ceil(window_start + self.window_sec - now))

            if estimated > self.max_requests:
                # Don't increment: rejected requests should not consume quota
                raise RateLimitExceeded(self.message, reset)

            # Only increment on allowed requests
            current['count'] += 1

        remaining = max(0, int(self.max_requests - estimated))

        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }
