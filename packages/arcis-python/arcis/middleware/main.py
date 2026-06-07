"""
Arcis Middleware - Main Arcis class

Flask/WSGI integration — the primary entry point for framework integration.
"""

from typing import Optional

from ..sanitizers.sanitize import Sanitizer
from ..core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS
from .rate_limit import RateLimiter, RateLimitExceeded
from .headers import SecurityHeaders
from .error_handler import ErrorHandler
from ..logging.safe_logger import SafeLogger


class Arcis:
    """
    Main Arcis class - one-line security for Python web frameworks.

    Usage:
        # Flask
        from arcis import Arcis
        Arcis(app)

        # Or configure:
        Arcis(app, rate_limit_max=50, sanitize_sql=False)
    """

    def __init__(
        self,
        app=None,
        # Sanitizer options
        sanitize: bool = True,
        sanitize_xss: bool = True,
        sanitize_sql: bool = True,
        sanitize_nosql: bool = True,
        sanitize_path: bool = True,
        # Block mode: return 403 on detected attack instead of silently
        # sanitizing. FastAPI / Starlette only — Flask path keeps
        # sanitize-on-read semantics. Mirrors Node's `block:true`.
        # Added 2026-06-07 (benchmark T3): previously block mode was
        # only reachable by bypassing this wrapper and using
        # ArcisMiddleware + Sanitizer() directly.
        block: bool = False,
        # Rate limiter options
        rate_limit: bool = True,
        rate_limit_max: int = DEFAULT_MAX_REQUESTS,
        rate_limit_window_ms: int = DEFAULT_WINDOW_MS,
        # Security headers options
        headers: bool = True,
        csp: Optional[str] = None,
        # Logger
        safe_logging: bool = True,
        # Error handler
        error_handler: bool = True,
        is_dev: bool = False,
    ):
        self.block = block
        self.sanitizer = Sanitizer(
            xss=sanitize_xss,
            sql=sanitize_sql,
            nosql=sanitize_nosql,
            path=sanitize_path,
        ) if sanitize else None

        self.rate_limiter = RateLimiter(
            max_requests=rate_limit_max,
            window_ms=rate_limit_window_ms,
        ) if rate_limit else None

        self.security_headers = SecurityHeaders(
            content_security_policy=csp,
        ) if headers else None

        self.logger = SafeLogger() if safe_logging else None

        self.error_handler = ErrorHandler(
            is_dev=is_dev,
            logger=self.logger,
        ) if error_handler else None

        self._app = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize Arcis with a Flask or similar app."""
        self._app = app

        # Detect framework
        app_type = type(app).__name__

        if app_type == "Flask" or hasattr(app, 'before_request'):
            self._init_flask(app)
        elif app_type == "FastAPI" or hasattr(app, 'add_middleware'):
            self._init_fastapi(app)
        else:
            raise ValueError(f"Unsupported framework: {app_type}")

    def close(self):
        """Clean up resources. Call this when shutting down."""
        if self.rate_limiter:
            self.rate_limiter.close()

    def _init_flask(self, app):
        """Initialize for Flask."""
        from flask import request, g

        @app.before_request
        def arcis_before_request():
            # Rate limiting
            if self.rate_limiter:
                try:
                    result = self.rate_limiter.check(request)
                    g.rate_limit_info = result
                except RateLimitExceeded as e:
                    from flask import jsonify
                    response = jsonify({"error": e.message, "retry_after": e.retry_after})
                    response.status_code = 429
                    response.headers['Retry-After'] = str(e.retry_after)
                    return response

            # Sanitize request data
            if self.sanitizer:
                if request.is_json and request.json:
                    # Flask's request.json is immutable, store sanitized data in g
                    g.sanitized_json = self.sanitizer(request.json)
                    # Also make it accessible as g.json for convenience
                    g.json = g.sanitized_json

        @app.after_request
        def arcis_after_request(response):
            # Add security headers
            if self.security_headers:
                self.security_headers.apply(response)

            # Add rate limit headers
            if hasattr(g, 'rate_limit_info'):
                info = g.rate_limit_info
                response.headers['X-RateLimit-Limit'] = str(info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(info['remaining'])
                response.headers['X-RateLimit-Reset'] = str(info['reset'])

            # Remove fingerprinting headers
            response.headers.pop('Server', None)
            response.headers.pop('X-Powered-By', None)

            return response

        # Register error handler
        if self.error_handler:
            @app.errorhandler(Exception)
            def handle_exception(e):
                return self.error_handler.flask_handler(e)

    def _init_fastapi(self, app):
        """Initialize for FastAPI."""
        from ..fastapi import ArcisMiddleware
        app.add_middleware(
            ArcisMiddleware,
            sanitizer=self.sanitizer,
            rate_limiter=self.rate_limiter,
            security_headers=self.security_headers,
            error_handler=self.error_handler,
            block=self.block,
        )
