"""
Arcis FastAPI Integration

Includes both sync and async rate limiters for FastAPI applications.
"""

import time
import json
import asyncio
import logging
from typing import Callable, Optional, Dict, Any, List, Protocol
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from .sanitizers.sanitize import Sanitizer, scan_threats
from .middleware.rate_limit import RateLimiter, RateLimitExceeded
from .middleware.headers import SecurityHeaders
from .middleware.error_handler import ErrorHandler
from .middleware.telemetry import (
    ARCIS_MARKER_ATTR,
    ArcisTelemetryMarker,
    build_event,
    extract_starlette_ip,
)
from .core.types import RateLimitEntry
from .core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE
from .telemetry.client import AsyncTelemetryClient
from .telemetry.types import TelemetryOptions
from .middleware.telemetry import telemetry_options_from_env as _telemetry_options_from_env
from .utils.ip import detect_client_ip

logger = logging.getLogger(__name__)


# Sentinel for "param not supplied" so ArcisMiddleware can distinguish
# rate_limiter=None (explicit disable) from rate_limiter not passed
# (fall through to the rate_limit bool default). Benchmark E2, 2026-06-07.
_RL_UNSET = object()


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


# ============================================================================
# ARCIS MIDDLEWARE (UPDATED WITH ASYNC SUPPORT)
# ============================================================================

class ArcisMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware for Arcis security.
    
    Now supports both sync and async rate limiters.
    
    Usage:
        from fastapi import FastAPI
        from arcis.fastapi import ArcisMiddleware
        
        app = FastAPI()
        app.add_middleware(ArcisMiddleware)
        
        # With async rate limiter (default for new installations):
        app.add_middleware(
            ArcisMiddleware,
            use_async_rate_limiter=True,
            rate_limit_max=100,
        )
        
        # With custom async store (e.g., Redis):
        from arcis.stores.redis import AsyncRedisRateLimitStore
        import redis.asyncio as redis
        
        redis_client = redis.Redis()
        async_store = AsyncRedisRateLimitStore(redis_client)
        
        app.add_middleware(
            ArcisMiddleware,
            async_rate_limiter=AsyncRateLimiter(store=async_store),
        )

    Important: Request Body Access
        The middleware calls ``await request.json()`` to sanitize JSON bodies.
        Starlette only allows the body stream to be read once, so calling
        ``request.json()`` or ``request.body()`` again inside a route handler
        will return empty data.

        Use ``request.state.sanitized_body`` (or the alias ``request.state.json``)
        to access the parsed and sanitized body instead::

            @app.post("/submit")
            async def submit(request: Request):
                body = request.state.sanitized_body  # already sanitized
                ...
    """
    
    def __init__(
        self,
        app,
        # Sanitizer options
        sanitize: bool = True,
        sanitize_xss: bool = True,
        sanitize_sql: bool = True,
        sanitize_nosql: bool = True,
        sanitize_path: bool = True,
        # Block mode: when True, scan request body + query for attack
        # patterns and return 403 (with telemetry attribution) instead of
        # silently sanitizing. Opt-in for backwards compatibility.
        block: bool = False,
        # Dry-run mode: when True, run the full block-mode detection
        # pipeline but do NOT return 403. The threat is logged + the
        # on_sanitize callback fires + the marker is set (so telemetry
        # records would-have-blocked decisions). Use for safe rollout:
        # turn on `block=True + dry_run=True`, watch the marker stream
        # for false positives, then flip dry_run=False once confident.
        # Ignored when block=False.
        dry_run: bool = False,
        # Per-request callback fired when sanitization modifies input or
        # the block path matches a threat. Receives a dict with keys:
        #   - vector: str
        #   - rule: str
        #   - matched: str (truncated sample of the matched value)
        #   - path: str (request URL path)
        #   - dry_run: bool (True if dry_run is on)
        # Useful for log aggregation, alerting on silent-rewrite cases,
        # and dashboards. Must not raise; exceptions are swallowed.
        on_sanitize: Optional[Callable[[Dict[str, Any]], None]] = None,
        # Rate limiter options
        rate_limit: bool = True,
        rate_limit_max: int = DEFAULT_MAX_REQUESTS,
        rate_limit_window_ms: int = DEFAULT_WINDOW_MS,
        use_async_rate_limiter: bool = True,  # NEW: default to async
        # Security headers options
        headers: bool = True,
        csp: Optional[str] = None,
        # Error handler options
        error_handling: bool = True,
        is_dev: bool = False,
        # Pre-built components (for Arcis class).
        # rate_limiter / async_rate_limiter use the `_RL_UNSET` sentinel
        # so callers can distinguish "not supplied" (use default if
        # rate_limit=True) from "supplied as None" (explicit disable —
        # benchmark E2 fix, 2026-06-07).
        sanitizer: Optional[Sanitizer] = None,
        rate_limiter=_RL_UNSET,
        async_rate_limiter=_RL_UNSET,
        security_headers: Optional[SecurityHeaders] = None,
        error_handler: Optional[ErrorHandler] = None,
        # Telemetry: dict, TelemetryOptions, or pre-built AsyncTelemetryClient.
        # When None, telemetry is fully disabled (zero overhead).
        telemetry: Optional[Any] = None,
    ):
        super().__init__(app)

        self.block = block
        self.dry_run = dry_run
        self.on_sanitize = on_sanitize

        self.sanitizer = sanitizer or (Sanitizer(
            xss=sanitize_xss,
            sql=sanitize_sql,
            nosql=sanitize_nosql,
            path=sanitize_path,
        ) if sanitize else None)
        
        # Determine which rate limiter to use.
        # Three states per param (`rate_limiter` / `async_rate_limiter`):
        #   _RL_UNSET — caller didn't pass — fall through to bool default
        #   None      — caller explicitly disabled (benchmark E2, 2026-06-07)
        #   object    — caller supplied a custom limiter — use it
        self.async_rate_limiter = None
        self.rate_limiter = None

        explicit_disable = (rate_limiter is None) or (async_rate_limiter is None)
        if explicit_disable:
            # Explicit None for either slot disables rate limiting entirely.
            # Matches the principle of least surprise: passing `None` to a
            # parameter that accepts an Optional should mean "no value."
            pass
        elif async_rate_limiter is not _RL_UNSET:
            self.async_rate_limiter = async_rate_limiter
        elif rate_limiter is not _RL_UNSET:
            self.rate_limiter = rate_limiter
        elif rate_limit:
            if use_async_rate_limiter:
                self.async_rate_limiter = AsyncRateLimiter(
                    max_requests=rate_limit_max,
                    window_ms=rate_limit_window_ms,
                )
            else:
                self.rate_limiter = RateLimiter(
                    max_requests=rate_limit_max,
                    window_ms=rate_limit_window_ms,
                )
        
        self.security_headers = security_headers or (SecurityHeaders(
            content_security_policy=csp,
        ) if headers else None)
        
        self.error_handler = error_handler or (ErrorHandler(
            is_dev=is_dev,
        ) if error_handling else None)

        # ── Telemetry wiring ───────────────────────────────────────────────
        # Accept four shapes for `telemetry`:
        #   1. AsyncTelemetryClient — used as-is (caller-managed lifecycle)
        #   2. TelemetryOptions     — wrap in a new client we own
        #   3. dict                 — convert to TelemetryOptions, then wrap
        #   4. None                 — fall back to ARCIS_* env vars; if those
        #                             aren't set either, telemetry is fully
        #                             disabled with zero overhead.
        self._telemetry_client: Optional[AsyncTelemetryClient] = None
        self._owns_telemetry_client: bool = False
        if telemetry is None:
            telemetry = _telemetry_options_from_env()
        if telemetry is not None:
            if isinstance(telemetry, AsyncTelemetryClient):
                self._telemetry_client = telemetry
            elif isinstance(telemetry, TelemetryOptions):
                self._telemetry_client = AsyncTelemetryClient(telemetry)
                self._owns_telemetry_client = True
            elif isinstance(telemetry, dict):
                self._telemetry_client = AsyncTelemetryClient(TelemetryOptions(**telemetry))
                self._owns_telemetry_client = True
            else:
                raise TypeError(
                    "ArcisMiddleware.telemetry must be AsyncTelemetryClient, "
                    "TelemetryOptions, dict, or None"
                )

    async def close(self) -> None:
        """Drain telemetry queue and stop the background flush task.

        Only closes the client if this middleware created it (caller-supplied
        clients are left alone — caller manages their lifecycle).
        """
        if self._telemetry_client is not None and self._owns_telemetry_client:
            try:
                await self._telemetry_client.close()
            except Exception:
                # fail-open on shutdown
                pass

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Telemetry: start latency clock + give inner middleware a place to
        # write attribution. The marker is only created when telemetry is
        # active so the request.state surface stays clean otherwise.
        telemetry_start: Optional[float] = None
        if self._telemetry_client is not None:
            telemetry_start = time.perf_counter()
            # Use setattr+ARCIS_MARKER_ATTR rather than direct dunder syntax —
            # ``request.state.__arcis`` would be mangled to
            # ``request.state._ArcisMiddleware__arcis`` inside this class.
            setattr(request.state, ARCIS_MARKER_ATTR, ArcisTelemetryMarker())

        # Rate limiting (async or sync)
        rate_limit_info = None

        if self.async_rate_limiter:
            try:
                rate_limit_info = await self.async_rate_limiter.check(request)
            except AsyncRateLimitExceeded as e:
                response = JSONResponse(
                    content={"error": e.message, "retry_after": e.retry_after},
                    status_code=429,
                )
                response.headers["Retry-After"] = str(e.retry_after)
                self._maybe_record(request, response, telemetry_start)
                return response
        elif self.rate_limiter:
            try:
                rate_limit_info = self.rate_limiter.check(request)
            except RateLimitExceeded as e:
                response = JSONResponse(
                    content={"error": e.message, "retry_after": e.retry_after},
                    status_code=429,
                )
                response.headers["Retry-After"] = str(e.retry_after)
                self._maybe_record(request, response, telemetry_start)
                return response
        
        # Read JSON body once (used by both block scan and sanitizer below).
        body: Any = None
        body_read = False
        if (self.block or self.sanitizer):
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    body = await request.json()
                    body_read = True
                except json.JSONDecodeError as e:
                    return JSONResponse(
                        content={"error": "Invalid JSON in request body", "detail": str(e)},
                        status_code=400,
                    )
                except Exception:
                    body = None

        # Block mode: scan body + query params for attack patterns. On match,
        # write the telemetry marker (so the dashboard records vector/rule)
        # and return 403 before the handler runs.
        if self.block:
            threat = None
            if body_read and body is not None:
                threat = scan_threats(body)
            if threat is None:
                try:
                    qp = dict(request.query_params)
                except Exception:
                    qp = {}
                if qp:
                    threat = scan_threats(qp)
            if threat is None:
                threat = scan_threats(request.url.path or "")

            if threat is not None:
                vector, rule, matched = threat
                if self._telemetry_client is not None:
                    marker: Optional[ArcisTelemetryMarker] = getattr(
                        request.state, ARCIS_MARKER_ATTR, None
                    )
                    if marker is None:
                        marker = ArcisTelemetryMarker()
                        setattr(request.state, ARCIS_MARKER_ATTR, marker)
                    marker.vector = vector
                    marker.rule = rule
                    marker.severity = "high"
                    marker.matched_pattern = matched
                    marker.reason = f"{vector} pattern detected in request"
                    # In dry_run mode the would-have-blocked decision is
                    # still recorded; downstream tooling can graph these
                    # before flipping the switch.
                    marker.decision = "would_deny" if self.dry_run else "deny"

                # Fire the on_sanitize callback so operators can wire
                # logging / alerting without subscribing to the
                # telemetry stream. Swallow exceptions — callbacks must
                # not be able to crash the middleware.
                if self.on_sanitize is not None:
                    try:
                        self.on_sanitize({
                            "vector": vector,
                            "rule": rule,
                            "matched": matched,
                            "path": request.url.path or "",
                            "dry_run": self.dry_run,
                        })
                    except Exception:
                        logger.exception("on_sanitize callback raised")

                # Dry-run: log + continue past the deny path. The marker
                # above carries decision=would_deny; the next handler
                # serves the request normally.
                if self.dry_run:
                    logger.info(
                        "arcis dry-run: would block vector=%s rule=%s path=%s",
                        vector, rule, request.url.path or "",
                    )
                else:
                    response = JSONResponse(
                        content={
                            "error": "Request blocked for security reasons",
                            "code": "SECURITY_THREAT",
                            "vector": vector,
                        },
                        status_code=403,
                    )
                    self._maybe_record(request, response, telemetry_start)
                    return response

        # Store sanitized body in request state if JSON
        if self.sanitizer and body_read and body is not None:
            try:
                request.state.sanitized_body = self.sanitizer(body)
                request.state.json = request.state.sanitized_body
            except Exception:
                pass
        
        # Process request with error handling
        try:
            response = await call_next(request)
        except Exception as e:
            if self.error_handler:
                status_code = getattr(e, 'status_code', 500) or 500
                error_response = self.error_handler.handle(e, status_code)
                response = JSONResponse(content=error_response, status_code=status_code)
            else:
                raise
        
        # Add security headers
        if self.security_headers:
            for header, value in self.security_headers.get_headers().items():
                response.headers[header] = value
        
        # Add rate limit headers
        if rate_limit_info:
            response.headers["X-RateLimit-Limit"] = str(rate_limit_info["limit"])
            response.headers["X-RateLimit-Remaining"] = str(rate_limit_info["remaining"])
            response.headers["X-RateLimit-Reset"] = str(rate_limit_info["reset"])
        
        # Remove fingerprinting headers
        if "server" in response.headers:
            del response.headers["server"]

        # Telemetry: emit AFTER all response mutation has settled so latency
        # and final status reflect what the client actually sees.
        self._maybe_record(request, response, telemetry_start)

        return response

    def _maybe_record(
        self,
        request: Request,
        response: Response,
        start: Optional[float],
    ) -> None:
        """Build and record a TelemetryEvent if telemetry is configured.

        Never raises — telemetry must not affect the response. ``start`` is
        ``None`` when telemetry is disabled, in which case this is a no-op.
        """
        if self._telemetry_client is None or start is None:
            return
        try:
            from datetime import datetime, timezone

            latency_ms = (time.perf_counter() - start) * 1000.0
            marker: Optional[ArcisTelemetryMarker] = getattr(
                request.state, ARCIS_MARKER_ATTR, None
            )
            user_agent = request.headers.get("user-agent", "") if hasattr(request, "headers") else ""
            event = build_event(
                ip=extract_starlette_ip(request),
                method=request.method,
                path=request.url.path if hasattr(request, "url") else "/",
                status=response.status_code,
                user_agent=user_agent,
                latency_ms=latency_ms,
                marker=marker,
                ts=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )
            self._telemetry_client.record(event)
        except Exception:
            # fail-open: telemetry must never break a response
            return


# ============================================================================
# DEPENDENCIES
# ============================================================================

def get_sanitized_body(request: Request) -> Optional[Dict[str, Any]]:
    """
    Dependency to get sanitized request body in FastAPI.
    
    Usage:
        from fastapi import Depends
        from arcis.fastapi import get_sanitized_body
        
        @app.post("/users")
        async def create_user(body: dict = Depends(get_sanitized_body)):
            # body is already sanitized
            pass
    """
    return getattr(request.state, "sanitized_body", None)


def get_json(request: Request) -> Optional[Dict[str, Any]]:
    """
    Alias for get_sanitized_body - more intuitive name.
    
    Usage:
        from fastapi import Depends
        from arcis.fastapi import get_json
        
        @app.post("/users")
        async def create_user(data: dict = Depends(get_json)):
            # data is already sanitized
            pass
    """
    return get_sanitized_body(request)


async def get_rate_limit_info(request: Request) -> Optional[Dict[str, Any]]:
    """
    Dependency to get rate limit info for the current request.
    
    Usage:
        from fastapi import Depends
        from arcis.fastapi import get_rate_limit_info
        
        @app.get("/status")
        async def status(rate_info: dict = Depends(get_rate_limit_info)):
            return {"requests_remaining": rate_info.get("remaining")}
    """
    return getattr(request.state, "rate_limit_info", None)


# ============================================================================
# STANDALONE ASYNC RATE LIMIT DEPENDENCY
# ============================================================================

def create_rate_limit_dependency(
    max_requests: int = DEFAULT_MAX_REQUESTS,
    window_ms: int = DEFAULT_WINDOW_MS,
    key_func: Optional[Callable] = None,
    skip_func: Optional[Callable] = None,
    store: Optional[AsyncRateLimitStore] = None,
):
    """
    Create a FastAPI dependency for rate limiting.
    
    Useful when you want per-route rate limiting instead of global middleware.
    
    Usage:
        from fastapi import Depends
        from arcis.fastapi import create_rate_limit_dependency
        
        # Global rate limiter
        rate_limit = create_rate_limit_dependency(max_requests=100)
        
        # Strict rate limiter for sensitive endpoints
        strict_rate_limit = create_rate_limit_dependency(max_requests=10, window_ms=60000)
        
        @app.post("/login", dependencies=[Depends(strict_rate_limit)])
        async def login():
            pass
        
        @app.get("/data", dependencies=[Depends(rate_limit)])
        async def get_data():
            pass
    """
    limiter = AsyncRateLimiter(
        max_requests=max_requests,
        window_ms=window_ms,
        key_func=key_func,
        skip_func=skip_func,
        store=store,
    )

    async def rate_limit_dependency(request: Request):
        try:
            info = await limiter.check(request)
            request.state.rate_limit_info = info
            return info
        except AsyncRateLimitExceeded as e:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={"error": e.message, "retry_after": e.retry_after},
                headers={"Retry-After": str(e.retry_after)},
            )

    return rate_limit_dependency


# improvements.md §1.4 — per-framework protect_login factory for FastAPI.
def create_login_protection_dependency(
    *,
    username_field: str = "username",
    password_field: str = "password",
    require_credentials: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    correlation_window: Any = None,
    route: str = "/login",
):
    """
    Create a FastAPI dependency that runs check_login() and raises
    HTTPException on rejection.

    Wraps arcis.check_login (which is framework-agnostic) into the
    FastAPI Depends() shape, including IP extraction from request.client
    so callers don't have to pull it manually.

    Usage:
        from fastapi import FastAPI, Depends
        from arcis.fastapi import create_login_protection_dependency
        from arcis.middleware.correlation import CorrelationWindow

        cw = CorrelationWindow()
        login_protect = create_login_protection_dependency(
            correlation_window=cw,
            route="/login",
        )

        @app.post("/login", dependencies=[Depends(login_protect)])
        async def login(req: Request):
            ...

    On rejection the dependency raises HTTPException(429) with
    detail = {"reason": "<bot|missing_credentials|correlation>",
              "details": {...}}.
    """
    from .middleware.protect_login import check_login as _check_login

    async def login_protection_dependency(request: Request):
        client_ip = request.client.host if request.client else None
        result = _check_login(
            request,
            username_field=username_field,
            password_field=password_field,
            require_credentials=require_credentials,
            check_bot=check_bot,
            allowed_bot_categories=allowed_bot_categories,
            correlation_window=correlation_window,
            client_ip=client_ip,
            route=route,
        )
        if not result.allowed:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={"reason": result.reason, "details": result.details},
            )
        return result

    return login_protection_dependency
