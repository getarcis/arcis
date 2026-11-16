"""
Arcis Middleware - Rate Limiter

RateLimitExceeded exception, RateLimiter class, and the configuration
validators shared by every limiter.
"""

import atexit
import logging
import numbers
import threading
import time
import weakref
from typing import Any, Callable, Dict, Optional, Union

from ..stores.base import ensure_store
from ..stores.memory import InMemoryStore
from ..core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE
from ..utils.ip import (
    DEFAULT_IPV6_SUBNET,
    TrustedProxies,
    rate_limit_key,
    validate_ipv6_subnet,
    validate_trusted_proxies,
)

logger = logging.getLogger(__name__)

MAX_WINDOW_MS = 2**31 - 1


def validate_window_ms(value: Any, name: str = "window_ms") -> int:
    """Return the window as whole milliseconds from 1 to 2^31-1, else raise ValueError."""
    is_number = isinstance(value, (numbers.Integral, float)) and not isinstance(value, bool)
    if not is_number or (isinstance(value, float) and not value.is_integer()):
        raise ValueError(f"{name} must be a whole number of milliseconds, got {value!r}")
    ms = int(value)
    if not 1 <= ms <= MAX_WINDOW_MS:
        raise ValueError(f"{name} must be between 1 and {MAX_WINDOW_MS} milliseconds, got {value!r}")
    return ms


def validate_max_requests(value: Any, name: str = "max_requests") -> int:
    """Return ``value`` when it is a non-negative int (0 blocks every request)."""
    if isinstance(value, bool) or not isinstance(value, numbers.Integral) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    return int(value)


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 0):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


class StoreErrorReporter:
    """Logs store errors at most once per window for one limiter."""

    def __init__(self, window_seconds: float, outcome: str) -> None:
        self._window_seconds = window_seconds
        self._outcome = outcome
        self._last: Optional[float] = None
        self._lock = threading.Lock()

    def report(self, exc: BaseException) -> None:
        now = time.monotonic()
        with self._lock:
            if self._last is not None and now - self._last < self._window_seconds:
                return
            self._last = now
        logger.error(
            "arcis rate limiter: store error (%s: %s); %s. Further store errors are "
            "reported at most once per window.",
            type(exc).__name__, exc, self._outcome,
        )


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
    Fixed-window rate limiter with configurable limits and window sizes.

    Each counted request makes one atomic ``store.increment(key, window_ms)``
    call. When a provided store (e.g. Redis) fails, the request is counted
    by an in-memory fallback and the error is logged at most once per window.

    The default key is the client IP from the trust-aware resolver
    (``arcis.utils.ip.resolve_client_ip``) passed through
    ``ip_key_generator`` (IPv6 grouped by ``ipv6_subnet``). Forwarded headers
    count only when the socket peer is in ``trusted_proxies``.

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
        store: Optional[Any] = None,
        trusted_proxies: TrustedProxies = None,
        ipv6_subnet: Union[int, bool] = DEFAULT_IPV6_SUBNET,
    ):
        """Create a limiter.

        Args:
            max_requests: Requests allowed per window; 0 blocks every request.
            window_ms: Window length in whole milliseconds (1 to 2^31-1).
            message: Message carried by ``RateLimitExceeded``.
            key_func: ``request -> key``. Default: resolved client IP key.
            skip_func: ``request -> bool``; True skips counting.
            store: Store implementing ``increment(key, window_ms)``. Older
                get/set stores are wrapped. Default: ``InMemoryStore``.
            trusted_proxies: Proxy IPs / CIDR ranges whose X-Forwarded-For is
                honored. None uses the default private set; [] trusts none.
            ipv6_subnet: IPv6 prefix grouped into one key (1-128) or False.

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
        self._store_provided = store is not None
        self.store = ensure_store(store) if store is not None else InMemoryStore()
        # In-memory fallback used only when an external store (e.g. Redis) is
        # provided and then fails. Preserves availability while keeping
        # protection (not a pure fail-open). Mirrors the Node rate limiter.
        self._fallback_store = InMemoryStore() if self._store_provided else None
        self._error_reporter = StoreErrorReporter(
            self.window_seconds, "counting in the in-memory fallback"
        )
        self._closed = False

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
        # At least one second between sweeps so tiny windows do not spin.
        interval = max(1.0, self.window_seconds)

        def cleanup_loop():
            while not self._cleanup_event.wait(timeout=interval):
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
        if hasattr(self.store, "close"):
            self.store.close()
        if self._fallback_store is not None:
            self._fallback_store.close()

    def _default_key_func(self, request) -> str:
        """Default key: trust-aware client IP through ``ip_key_generator``."""
        return rate_limit_key(request, self.trusted_proxies, self.ipv6_subnet)

    def _allowed_without_counting(self) -> Dict[str, Any]:
        return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

    def check(self, request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.
        Returns dict with limit info and raises RateLimitExceeded if exceeded.
        """
        if self._closed:
            # Fail open if closed
            return self._allowed_without_counting()

        if self.skip_func and self.skip_func(request):
            return self._allowed_without_counting()

        key = self.key_func(request)

        try:
            count, reset_time = self.store.increment(key, self.window_ms)
        except Exception as exc:
            # Primary store failed (e.g. Redis is down). Count in memory so
            # protection continues, and report the outage once per window.
            self._error_reporter.report(exc)
            if self._fallback_store is None:
                return self._allowed_without_counting()
            count, reset_time = self._fallback_store.increment(key, self.window_ms)

        reset = max(0, int(reset_time - time.time()))
        remaining = max(0, self.max_requests - count)

        if count > self.max_requests:
            raise RateLimitExceeded(self.message, reset)

        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }
