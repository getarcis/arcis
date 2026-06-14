"""FastAPI dependency factories + route-level protect helpers.

Extracted from ``fastapi.py`` (which re-exports these names, so
``from arcis.fastapi import protect_login`` keeps working). Holds the
per-route rate-limit / login-protection dependency factories and the
``protect_login`` / ``protect_signup`` / ``protect_api`` helpers. FastAPI is
imported lazily inside each helper (it stays an optional dependency).
"""

import json
from typing import Any, Callable, Dict, List, Optional

from starlette.requests import Request

from .async_rate_limit import AsyncRateLimiter, AsyncRateLimitStore, AsyncRateLimitExceeded
from .middleware.rate_limit import RateLimiter
from .core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS


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


# ============================================================================
# PROTECT FACTORIES (improvements.md §1.4)
# ============================================================================
# Per-framework wrappers around the composite login / signup / api checks
# plus a shared CorrelationWindow. Each factory returns a FastAPI/Starlette
# async dependency that auto-extracts the client IP (X-Forwarded-For first
# hop, then request.client.host) and the route path, forwards them into the
# base check with the right vector tag, and raises HTTPException on denial.
#
# Rate limiting stays the RateLimiter middleware's job (Pattern 3). Mount
# create_rate_limit_dependency / ArcisMiddleware at the route for the
# Node-parity limits (login 5/min, signup 3/min, api 100/min); these
# factories own the correlation + bot + credential / threat wiring.


class _BodyRequest:
    """Wrapper exposing a parsed body dict + headers to the base checks.

    A Starlette ``Request`` only exposes the body via the async
    ``request.json()`` coroutine, which the synchronous base checks
    cannot read. The factory reads it once (async) and hands the base
    check this duck-typed shim instead.
    """

    def __init__(self, body: Any, headers: Any) -> None:
        self.body = body
        self.headers = headers


async def _read_json_body(request: Request) -> Any:
    """Best-effort async read of a JSON body. Returns None on any error."""
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        return None
    try:
        return await request.json()
    except Exception:
        return None


def _starlette_client_ip(request: Request) -> Optional[str]:
    """Resolve client IP: X-Forwarded-For first hop, then socket peer."""
    from .middleware.protect_factories import client_ip_from_xff_then

    fallback = request.client.host if request.client else None
    return client_ip_from_xff_then(
        request.headers.get("x-forwarded-for"), fallback
    )


def protect_login(
    *,
    username_field: str = "username",
    password_field: str = "password",
    require_credentials: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    correlation_window: Any = None,
    route: Optional[str] = None,
):
    """FastAPI/Starlette login-protection dependency factory.

    Returns an async dependency that runs :func:`check_login` with the
    auto-extracted client IP, the route path, and the ``"login"`` vector,
    forwarding an optional shared :class:`CorrelationWindow`. On denial it
    raises ``HTTPException`` (429 for correlation, 403 for bot, 400 for
    missing credentials) with body ``{"error": reason}``.

    Args:
        username_field: Body field carrying the username. Default
            ``"username"``.
        password_field: Body field carrying the password. Default
            ``"password"``.
        require_credentials: Forwarded to :func:`check_login`.
        check_bot: Forwarded to :func:`check_login`.
        allowed_bot_categories: Forwarded to :func:`check_login`.
        correlation_window: Optional shared window. Pass the same
            instance to several factories to share per-IP state.
        route: Route label recorded in the window. Defaults to the
            request path.

    Returns:
        An async FastAPI dependency callable.
    """
    from fastapi import HTTPException

    from .middleware.protect_factories import block_status_code, check_login

    async def login_dependency(request: Request):
        client_ip = _starlette_client_ip(request)
        body = await _read_json_body(request)
        shim = _BodyRequest(body, request.headers)
        result = check_login(
            shim,
            username_field=username_field,
            password_field=password_field,
            require_credentials=require_credentials,
            check_bot=check_bot,
            allowed_bot_categories=allowed_bot_categories,
            correlation_window=correlation_window,
            client_ip=client_ip,
            route=route if route is not None else request.url.path,
        )
        if not result.allowed:
            raise HTTPException(
                status_code=block_status_code(result.reason),
                detail={"error": result.reason},
            )
        return result

    return login_dependency


def protect_signup(
    *,
    email_field: str = "email",
    check_email: bool = True,
    block_disposable: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    allowed_email_domains: Optional[List[str]] = None,
    blocked_email_domains: Optional[List[str]] = None,
    correlation_window: Any = None,
    route: Optional[str] = None,
):
    """FastAPI/Starlette signup-protection dependency factory.

    Returns an async dependency that runs the signup check (bot + email
    validation) then consults an optional shared
    :class:`CorrelationWindow` (vector ``"signup"``). On denial it raises
    ``HTTPException`` (429 for correlation, 403 for bot, 400 for email
    errors) with body ``{"error": reason}``.

    Args:
        email_field: Body field carrying the email. Default ``"email"``.
        check_email: Forwarded to the signup check.
        block_disposable: Forwarded to the signup check.
        check_bot: Forwarded to the signup check.
        allowed_bot_categories: Forwarded to the signup check.
        allowed_email_domains: Forwarded to the signup check.
        blocked_email_domains: Forwarded to the signup check.
        correlation_window: Optional shared window.
        route: Route label recorded in the window. Defaults to the
            request path.

    Returns:
        An async FastAPI dependency callable.
    """
    from fastapi import HTTPException

    from .middleware.protect_factories import (
        block_status_code,
        signup_check_with_correlation,
    )

    async def signup_dependency(request: Request):
        client_ip = _starlette_client_ip(request)
        body = await _read_json_body(request)
        shim = _BodyRequest(body, request.headers)
        result = signup_check_with_correlation(
            shim,
            correlation_window=correlation_window,
            client_ip=client_ip,
            route=route if route is not None else request.url.path,
            email_field=email_field,
            check_email=check_email,
            block_disposable=block_disposable,
            check_bot=check_bot,
            allowed_bot_categories=allowed_bot_categories,
            allowed_email_domains=allowed_email_domains,
            blocked_email_domains=blocked_email_domains,
        )
        if not result.allowed:
            raise HTTPException(
                status_code=block_status_code(result.reason),
                detail={"error": result.reason},
            )
        return result

    return signup_dependency


def protect_api(
    *,
    expected_origins: Optional[List[str]] = None,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    scan_body: bool = True,
    correlation_window: Any = None,
    route: Optional[str] = None,
):
    """FastAPI/Starlette API-protection dependency factory.

    Returns an async dependency that runs :func:`check_api` (origin + bot
    + body threat scan) with the auto-extracted client IP, the route
    path, and the ``"api"`` vector, forwarding an optional shared
    :class:`CorrelationWindow`. On denial it raises ``HTTPException`` (429
    for correlation, 403 for bot / bad-origin / threat) with body
    ``{"error": reason}``.

    Args:
        expected_origins: Forwarded to :func:`check_api`.
        check_bot: Forwarded to :func:`check_api`.
        allowed_bot_categories: Forwarded to :func:`check_api`.
        scan_body: Forwarded to :func:`check_api`.
        correlation_window: Optional shared window.
        route: Route label recorded in the window. Defaults to the
            request path.

    Returns:
        An async FastAPI dependency callable.
    """
    from fastapi import HTTPException

    from .middleware.protect_factories import block_status_code, check_api

    async def api_dependency(request: Request):
        client_ip = _starlette_client_ip(request)
        body = await _read_json_body(request)
        shim = _BodyRequest(body, request.headers)
        result = check_api(
            shim,
            expected_origins=expected_origins,
            check_bot=check_bot,
            allowed_bot_categories=allowed_bot_categories,
            scan_body=scan_body,
            correlation_window=correlation_window,
            client_ip=client_ip,
            route=route if route is not None else request.url.path,
        )
        if not result.allowed:
            raise HTTPException(
                status_code=block_status_code(result.reason),
                detail={"error": result.reason},
            )
        return result

    return api_dependency
