"""
Arcis Django Integration
========================

Django middleware for Arcis security.

Usage:
    # settings.py
    MIDDLEWARE = [
        'arcis.django.ArcisMiddleware',
        # ... other middleware
    ]

    # Optional configuration in settings.py
    ARCIS_CONFIG = {
        'sanitize': True,
        'sanitize_xss': True,
        'sanitize_sql': True,
        'sanitize_nosql': True,
        'sanitize_path': True,
        'rate_limit': True,
        'rate_limit_max': 100,
        'rate_limit_window_ms': 60000,
        'headers': True,
        'csp': None,
        'is_dev': False,  # Set to True for development
    }
"""

import functools
import json
import logging
from typing import Callable, List, Optional, Dict, Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin

from .sanitizers.sanitize import Sanitizer, scan_threats
from .middleware.rate_limit import RateLimiter, RateLimitExceeded
from .middleware.headers import SecurityHeaders
from .middleware.error_handler import ErrorHandler
from .stores.memory import InMemoryStore
from .logging.safe_logger import SafeLogger

logger = logging.getLogger(__name__)


def get_client_ip(request: HttpRequest) -> str:
    """Extract client IP from Django request, handling proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip:
        return x_real_ip
    return request.META.get('REMOTE_ADDR', 'unknown')


class ArcisMiddleware(MiddlewareMixin):
    """
    Django middleware that runs the Arcis sanitizer pipeline against
    request data (XSS, SQL, NoSQL, path, command, SSTI, XXE, LDAP,
    XPath, email-header, prototype pollution) plus rate limiting,
    security headers, and error handling.

    Opt-in via config['block'] = True (default False): on a detected
    attack pattern the middleware returns 403 with reason + rule
    before the request reaches your view. Pair with config['dry_run']
    = True to log + record but not refuse (safe rollout).

    Not wired here: bot detection, CSRF, HPP, SSRF URL validation,
    correlation window, prompt-injection (V32), deserialization (V33),
    GraphQL guard (V34). Those are opt-in helpers, compose as needed.

    Usage:
        # settings.py
        MIDDLEWARE = [
            'arcis.django.ArcisMiddleware',
            ...
        ]

        # Optional: Configure Arcis
        ARCIS_CONFIG = {
            'rate_limit_max': 50,
            'sanitize_sql': False,  # Disable SQL sanitization
            'is_dev': True,  # Show error details
        }
    """

    # Shared rate limiter store across all instances
    _rate_limit_store = InMemoryStore()
    _rate_limiter: Optional[RateLimiter] = None

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

        # Load configuration from Django settings
        config = getattr(settings, 'ARCIS_CONFIG', {})

        # E1 — block / dry-run / on_sanitize knobs match FastAPI + Litestar.
        self.block: bool = config.get('block', False)
        self.dry_run: bool = config.get('dry_run', False)
        self.on_sanitize: Optional[Callable[[Dict[str, Any]], None]] = (
            config.get('on_sanitize')
        )

        # Initialize sanitizer
        sanitize_enabled = config.get('sanitize', True)
        if sanitize_enabled:
            self.sanitizer = Sanitizer(
                xss=config.get('sanitize_xss', True),
                sql=config.get('sanitize_sql', True),
                nosql=config.get('sanitize_nosql', True),
                path=config.get('sanitize_path', True),
            )
        else:
            self.sanitizer = None
        
        # Initialize rate limiter (shared across instances)
        rate_limit_enabled = config.get('rate_limit', True)
        if rate_limit_enabled and ArcisMiddleware._rate_limiter is None:
            ArcisMiddleware._rate_limiter = RateLimiter(
                max_requests=config.get('rate_limit_max', 100),
                window_ms=config.get('rate_limit_window_ms', 60000),
                key_func=lambda req: get_client_ip(req),
                store=self._rate_limit_store,
            )
        self.rate_limiter = ArcisMiddleware._rate_limiter if rate_limit_enabled else None
        
        # Initialize security headers
        headers_enabled = config.get('headers', True)
        if headers_enabled:
            self.security_headers = SecurityHeaders(
                content_security_policy=config.get('csp'),
            )
        else:
            self.security_headers = None
        
        # Initialize error handler
        error_handler_enabled = config.get('error_handler', True)
        is_dev = config.get('is_dev', settings.DEBUG)
        if error_handler_enabled:
            self.error_handler = ErrorHandler(is_dev=is_dev)
        else:
            self.error_handler = None
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Rate limiting check
        rate_limit_info = None
        if self.rate_limiter:
            try:
                rate_limit_info = self.rate_limiter.check(request)
            except RateLimitExceeded as e:
                response = JsonResponse(
                    {'error': e.message, 'retry_after': e.retry_after},
                    status=429
                )
                response['Retry-After'] = str(e.retry_after)
                return response
        
        # Read JSON body once. Used by both block-mode scan and sanitizer.
        body_obj: Any = None
        body_read = False
        if (self.block or self.sanitizer) and request.method in ('POST', 'PUT', 'PATCH'):
            content_type = request.content_type or ''
            if 'application/json' in content_type.lower():
                try:
                    body_obj = json.loads(request.body.decode('utf-8'))
                    body_read = True
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        # Block mode: scan body / query / path for attack patterns. Same
        # dry-run + on_sanitize semantics as FastAPI / Litestar.
        if self.block:
            threat = None
            if body_read and body_obj is not None:
                threat = scan_threats(body_obj)
            if threat is None:
                qp = dict(request.GET.items()) if request.GET else {}
                if qp:
                    threat = scan_threats(qp)
            if threat is None:
                threat = scan_threats(request.path or '')
            if threat is not None:
                vector, rule, matched = threat
                if self.on_sanitize is not None:
                    try:
                        self.on_sanitize({
                            'vector': vector,
                            'rule': rule,
                            'matched': matched,
                            'path': request.path or '',
                            'dry_run': self.dry_run,
                        })
                    except Exception:
                        logger.exception('on_sanitize callback raised')
                if self.dry_run:
                    logger.info(
                        'arcis dry-run: would block vector=%s rule=%s path=%s',
                        vector, rule, request.path or '',
                    )
                else:
                    return JsonResponse(
                        {
                            'error': 'Request blocked for security reasons',
                            'code': 'SECURITY_THREAT',
                            'vector': vector,
                        },
                        status=403,
                    )

        # Sanitize request body
        if self.sanitizer and body_read and body_obj is not None:
            try:
                request._arcis_sanitized_body = self.sanitizer(body_obj)
                # Also accessible as request.arcis_json
                request.arcis_json = request._arcis_sanitized_body
            except Exception:
                pass
        
        # Process request
        try:
            response = self.get_response(request)
        except Exception as e:
            if self.error_handler:
                error_response = self.error_handler.handle(e, 500)
                response = JsonResponse(error_response, status=500)
            else:
                raise
        
        # Add security headers
        if self.security_headers:
            for header, value in self.security_headers.get_headers().items():
                response[header] = value
        
        # Add rate limit headers
        if rate_limit_info:
            response['X-RateLimit-Limit'] = str(rate_limit_info['limit'])
            response['X-RateLimit-Remaining'] = str(rate_limit_info['remaining'])
            response['X-RateLimit-Reset'] = str(rate_limit_info['reset'])
        
        # Remove fingerprinting headers
        if 'Server' in response:
            del response['Server']
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
        
        return response


def get_sanitized_body(request: HttpRequest) -> Optional[Dict[str, Any]]:
    """
    Get the sanitized request body from a Django request.
    
    Usage:
        from arcis.django import get_sanitized_body
        
        def my_view(request):
            data = get_sanitized_body(request)
            # data is sanitized
    """
    return getattr(request, '_arcis_sanitized_body', None)


def get_json(request: HttpRequest) -> Optional[Dict[str, Any]]:
    """
    Alias for get_sanitized_body - more intuitive name.
    
    Usage:
        from arcis.django import get_json
        
        def my_view(request):
            data = get_json(request)
            # data is sanitized
    """
    return get_sanitized_body(request)


class ArcisSanitizeMiddleware(MiddlewareMixin):
    """
    Standalone sanitization middleware for Django.
    Use this if you only want sanitization without rate limiting.

    Usage:
        MIDDLEWARE = [
            'arcis.django.ArcisSanitizeMiddleware',
            ...
        ]
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        config = getattr(settings, 'ARCIS_CONFIG', {})
        self.sanitizer = Sanitizer(
            xss=config.get('sanitize_xss', True),
            sql=config.get('sanitize_sql', True),
            nosql=config.get('sanitize_nosql', True),
            path=config.get('sanitize_path', True),
        )
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method in ('POST', 'PUT', 'PATCH'):
            content_type = request.content_type or ''
            if 'application/json' in content_type.lower():
                try:
                    body = json.loads(request.body.decode('utf-8'))
                    request._arcis_sanitized_body = self.sanitizer(body)
                    request.arcis_json = request._arcis_sanitized_body
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        
        return self.get_response(request)


class ArcisRateLimitMiddleware(MiddlewareMixin):
    """
    Standalone rate limiting middleware for Django.

    Usage:
        MIDDLEWARE = [
            'arcis.django.ArcisRateLimitMiddleware',
            ...
        ]
    """

    _store = InMemoryStore()
    _rate_limiter: Optional[RateLimiter] = None

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        config = getattr(settings, 'ARCIS_CONFIG', {})

        if ArcisRateLimitMiddleware._rate_limiter is None:
            ArcisRateLimitMiddleware._rate_limiter = RateLimiter(
                max_requests=config.get('rate_limit_max', 100),
                window_ms=config.get('rate_limit_window_ms', 60000),
                key_func=lambda req: get_client_ip(req),
                store=self._store,
            )
        self.rate_limiter = ArcisRateLimitMiddleware._rate_limiter
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        try:
            rate_limit_info = self.rate_limiter.check(request)
        except RateLimitExceeded as e:
            response = JsonResponse(
                {'error': e.message, 'retry_after': e.retry_after},
                status=429
            )
            response['Retry-After'] = str(e.retry_after)
            return response
        
        response = self.get_response(request)
        
        response['X-RateLimit-Limit'] = str(rate_limit_info['limit'])
        response['X-RateLimit-Remaining'] = str(rate_limit_info['remaining'])
        response['X-RateLimit-Reset'] = str(rate_limit_info['reset'])
        
        return response


class ArcisHeadersMiddleware(MiddlewareMixin):
    """
    Standalone security headers middleware for Django.

    Usage:
        MIDDLEWARE = [
            'arcis.django.ArcisHeadersMiddleware',
            ...
        ]
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        config = getattr(settings, 'ARCIS_CONFIG', {})
        self.security_headers = SecurityHeaders(
            content_security_policy=config.get('csp'),
        )
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        
        for header, value in self.security_headers.get_headers().items():
            response[header] = value
        
        # Remove fingerprinting headers
        if 'Server' in response:
            del response['Server']
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
        
        return response


class ArcisErrorMiddleware(MiddlewareMixin):
    """
    Standalone error handling middleware for Django.
    Hides error details in production.

    Usage:
        MIDDLEWARE = [
            'arcis.django.ArcisErrorMiddleware',
            ...
        ]
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        config = getattr(settings, 'ARCIS_CONFIG', {})
        is_dev = config.get('is_dev', settings.DEBUG)
        self.error_handler = ErrorHandler(is_dev=is_dev)
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        try:
            return self.get_response(request)
        except Exception as e:
            error_response = self.error_handler.handle(e, 500)
            return JsonResponse(error_response, status=500)


# ============================================================================
# PROTECT FACTORIES (improvements.md §1.4)
# ============================================================================
# Per-framework wrappers around the composite login / signup / api checks
# plus a shared CorrelationWindow. Each factory returns a Django view
# decorator that auto-extracts the client IP (X-Forwarded-For first hop,
# then META REMOTE_ADDR) and the route path, forwards them into the base
# check with the right vector tag, and returns a JsonResponse on denial.
#
# Rate limiting stays a separate concern (Pattern 3): mount
# ArcisRateLimitMiddleware for the Node-parity limits (login 5/min, signup
# 3/min, api 100/min). These decorators own the correlation + bot +
# credential / threat wiring.


class _BodyRequest:
    """Wrapper exposing a parsed body dict + headers to the base checks.

    The base checks read the body via a synchronous ``body`` / ``json`` /
    ``form`` attribute and headers via a ``.get``-able mapping. A Django
    request stores its JSON body as raw bytes, so the decorator parses it
    once and hands the base check this duck-typed shim.
    """

    def __init__(self, body: Any, headers: Any) -> None:
        self.body = body
        self.headers = headers


def _django_json_body(request: HttpRequest) -> Any:
    """Best-effort parse of a JSON request body. Returns None on error."""
    content_type = (request.content_type or '').lower()
    if 'application/json' not in content_type:
        return None
    try:
        return json.loads(request.body.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


def _django_client_ip(request: HttpRequest) -> Optional[str]:
    """Resolve client IP: X-Forwarded-For first hop, then REMOTE_ADDR."""
    from .middleware.protect_factories import client_ip_from_xff_then

    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    fallback = request.META.get('REMOTE_ADDR')
    return client_ip_from_xff_then(xff, fallback)


def protect_login(
    *,
    username_field: str = 'username',
    password_field: str = 'password',
    require_credentials: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    correlation_window: Any = None,
    route: Optional[str] = None,
) -> Callable[[Callable], Callable]:
    """Django login-protection view decorator factory.

    Returns a decorator that runs the login check with the auto-extracted
    client IP, the route path, and the ``"login"`` vector, forwarding an
    optional shared :class:`CorrelationWindow`. On denial it returns a
    ``JsonResponse`` (429 for correlation, 403 for bot, 400 for missing
    credentials) with body ``{"error": reason}``; otherwise it calls the
    wrapped view.

    Args:
        username_field: Body field carrying the username.
        password_field: Body field carrying the password.
        require_credentials: Forwarded to the login check.
        check_bot: Forwarded to the login check.
        allowed_bot_categories: Forwarded to the login check.
        correlation_window: Optional shared window.
        route: Route label recorded in the window. Defaults to the
            request path.

    Returns:
        A view decorator.
    """
    from .middleware.protect_factories import block_status_code, check_login

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any):
            shim = _BodyRequest(_django_json_body(request), request.headers)
            result = check_login(
                shim,
                username_field=username_field,
                password_field=password_field,
                require_credentials=require_credentials,
                check_bot=check_bot,
                allowed_bot_categories=allowed_bot_categories,
                correlation_window=correlation_window,
                client_ip=_django_client_ip(request),
                route=route if route is not None else request.path,
            )
            if not result.allowed:
                return JsonResponse(
                    {'error': result.reason},
                    status=block_status_code(result.reason),
                )
            return view(request, *args, **kwargs)

        return wrapped

    return decorator


def protect_signup(
    *,
    email_field: str = 'email',
    check_email: bool = True,
    block_disposable: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    allowed_email_domains: Optional[List[str]] = None,
    blocked_email_domains: Optional[List[str]] = None,
    correlation_window: Any = None,
    route: Optional[str] = None,
) -> Callable[[Callable], Callable]:
    """Django signup-protection view decorator factory.

    Returns a decorator that runs the signup check (bot + email
    validation) then consults an optional shared
    :class:`CorrelationWindow` (vector ``"signup"``). On denial it returns
    a ``JsonResponse`` (429 for correlation, 403 for bot, 400 for email
    errors) with body ``{"error": reason}``; otherwise it calls the
    wrapped view.

    Args:
        email_field: Body field carrying the email.
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
        A view decorator.
    """
    from .middleware.protect_factories import (
        block_status_code,
        signup_check_with_correlation,
    )

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any):
            shim = _BodyRequest(_django_json_body(request), request.headers)
            result = signup_check_with_correlation(
                shim,
                correlation_window=correlation_window,
                client_ip=_django_client_ip(request),
                route=route if route is not None else request.path,
                email_field=email_field,
                check_email=check_email,
                block_disposable=block_disposable,
                check_bot=check_bot,
                allowed_bot_categories=allowed_bot_categories,
                allowed_email_domains=allowed_email_domains,
                blocked_email_domains=blocked_email_domains,
            )
            if not result.allowed:
                return JsonResponse(
                    {'error': result.reason},
                    status=block_status_code(result.reason),
                )
            return view(request, *args, **kwargs)

        return wrapped

    return decorator


def protect_api(
    *,
    expected_origins: Optional[List[str]] = None,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    scan_body: bool = True,
    correlation_window: Any = None,
    route: Optional[str] = None,
) -> Callable[[Callable], Callable]:
    """Django API-protection view decorator factory.

    Returns a decorator that runs the API check (origin + bot + body
    threat scan) with the auto-extracted client IP, the route path, and
    the ``"api"`` vector, forwarding an optional shared
    :class:`CorrelationWindow`. On denial it returns a ``JsonResponse``
    (429 for correlation, 403 for bot / bad-origin / threat) with body
    ``{"error": reason}``; otherwise it calls the wrapped view.

    Args:
        expected_origins: Forwarded to the API check.
        check_bot: Forwarded to the API check.
        allowed_bot_categories: Forwarded to the API check.
        scan_body: Forwarded to the API check.
        correlation_window: Optional shared window.
        route: Route label recorded in the window. Defaults to the
            request path.

    Returns:
        A view decorator.
    """
    from .middleware.protect_factories import block_status_code, check_api

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any):
            shim = _BodyRequest(_django_json_body(request), request.headers)
            result = check_api(
                shim,
                expected_origins=expected_origins,
                check_bot=check_bot,
                allowed_bot_categories=allowed_bot_categories,
                scan_body=scan_body,
                correlation_window=correlation_window,
                client_ip=_django_client_ip(request),
                route=route if route is not None else request.path,
            )
            if not result.allowed:
                return JsonResponse(
                    {'error': result.reason},
                    status=block_status_code(result.reason),
                )
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
