"""
Arcis Middleware - Token Bucket Rate Limiter

Allows burst traffic while enforcing an average rate.
Tokens refill at a steady rate. Each request costs 1 token.

Algorithm:
    tokens = min(capacity, tokens + elapsed * refill_rate)
    if tokens >= cost: allow, subtract cost
    else: deny

Examples:
    limiter = TokenBucketLimiter(capacity=50, refill_rate=10)
    result = limiter.check(request)
"""

import time
import threading
import atexit
import math
from typing import Any, Callable, Dict, Optional


class TokenBucketLimiter:
    """
    Token bucket rate limiter.

    Allows burst traffic up to `capacity` while enforcing
    a sustained rate of `refill_rate` requests per second.

    Example:
        limiter = TokenBucketLimiter(capacity=50, refill_rate=10)
        try:
            result = limiter.check(request)
        except TokenBucketRateLimitExceeded:
            return error_response(429)
    """

    def __init__(
        self,
        capacity: int = 100,
        refill_rate: float = 10.0,
        cost: int = 1,
        message: str = "Too many requests, please try again later.",
        key_func: Optional[Callable] = None,
        skip_func: Optional[Callable] = None,
    ):
        if capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        if refill_rate <= 0:
            raise ValueError(f"refill_rate must be > 0, got {refill_rate}")
        if cost < 1:
            raise ValueError(f"cost must be >= 1, got {cost}")
        if cost > capacity:
            raise ValueError(f"cost ({cost}) must be <= capacity ({capacity}), otherwise all requests are permanently denied")

        self.capacity = capacity
        self.refill_rate = refill_rate
        self.cost = cost
        self.message = message
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._closed = False
        self._lock = threading.Lock()
        self._buckets: Dict[str, Dict[str, float]] = {}

        # Cleanup stale buckets
        self._cleanup_event = threading.Event()
        self._stale_threshold = (capacity / refill_rate) * 2
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        atexit.register(self.close)

    def _default_key_func(self, request) -> str:
        """Default key function - uses client IP address."""
        from ..utils.ip import detect_client_ip
        return detect_client_ip(request)

    def _cleanup_loop(self):
        """Remove stale buckets periodically."""
        while not self._cleanup_event.wait(timeout=60.0):
            if self._closed:
                break
            now = time.time()
            with self._lock:
                expired = [
                    k for k, v in self._buckets.items()
                    if now - v['last_refill'] > self._stale_threshold
                ]
                for k in expired:
                    del self._buckets[k]

    def close(self):
        """Stop cleanup thread and release resources."""
        if self._closed:
            return
        self._closed = True
        self._cleanup_event.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)
        atexit.unregister(self.close)

    def _refill(self, bucket: Dict[str, float], now: float) -> None:
        """Add tokens based on elapsed time."""
        elapsed = now - bucket['last_refill']
        tokens_to_add = elapsed * self.refill_rate
        bucket['tokens'] = min(self.capacity, bucket['tokens'] + tokens_to_add)
        bucket['last_refill'] = now

    def check(self, request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.

        Returns:
            Dict with limit info: allowed, capacity, remaining, retry_after.

        Raises:
            RateLimitExceeded: If rate limit is exceeded.
        """
        if self._closed:
            return {"allowed": True, "capacity": self.capacity, "remaining": self.capacity, "retry_after": 0}

        if self.skip_func and self.skip_func(request):
            return {"allowed": True, "capacity": self.capacity, "remaining": self.capacity, "retry_after": 0}

        key = self.key_func(request)
        now = time.time()

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = {'tokens': float(self.capacity), 'last_refill': now}

            bucket = self._buckets[key]
            self._refill(bucket, now)

            if bucket['tokens'] < self.cost:
                retry_after = math.ceil((self.cost - bucket['tokens']) / self.refill_rate)
                from ..middleware.rate_limit import RateLimitExceeded
                raise RateLimitExceeded(self.message, retry_after)

            bucket['tokens'] -= self.cost
            remaining = int(max(0, bucket['tokens']))

        return {
            "allowed": True,
            "capacity": self.capacity,
            "remaining": remaining,
            "retry_after": 0,
        }
