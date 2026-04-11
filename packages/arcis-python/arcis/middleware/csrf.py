"""
Arcis Middleware - CSRF Protection

Cross-Site Request Forgery protection using double-submit cookie pattern:
1. Server sets a CSRF token in a cookie
2. Client must send the same token in a header or form field
3. Middleware rejects requests where cookie token != header/field token

This works because an attacker's cross-origin form can include the cookie
automatically, but cannot read it (same-origin policy) to set the header.
"""

import hmac
import os
import secrets
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence


DEFAULT_COOKIE_NAME = "_csrf"
DEFAULT_HEADER_NAME = "x-csrf-token"
DEFAULT_FIELD_NAME = "_csrf"
DEFAULT_TOKEN_LENGTH = 32
DEFAULT_PROTECTED_METHODS = ("POST", "PUT", "PATCH", "DELETE")
HOST_PREFIX = "__Host-"


def generate_csrf_token(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """
    Generate a cryptographically random CSRF token.

    Args:
        length: Byte length (output is hex, so 2x chars). Default: 32

    Returns:
        Hex-encoded random token (64 chars by default)

    Example:
        token = generate_csrf_token()  # 64 hex chars
    """
    return secrets.token_hex(length)


def validate_csrf_token(cookie_token: str, request_token: str) -> bool:
    """
    Validate that two CSRF tokens match using constant-time comparison.

    Args:
        cookie_token: Token from the cookie
        request_token: Token from the header or form field

    Returns:
        True if tokens match
    """
    if not cookie_token or not request_token:
        return False
    return hmac.compare_digest(cookie_token, request_token)


@dataclass
class CsrfCookieOptions:
    """Cookie options for the CSRF token."""

    path: str = "/"
    http_only: bool = False  # Must be readable by client JS
    secure: Optional[bool] = None  # None = auto (production detection)
    same_site: str = "Lax"
    domain: Optional[str] = None


@dataclass
class CsrfOptions:
    """CSRF protection configuration."""

    cookie_name: str = DEFAULT_COOKIE_NAME
    header_name: str = DEFAULT_HEADER_NAME
    field_name: str = DEFAULT_FIELD_NAME
    token_length: int = DEFAULT_TOKEN_LENGTH
    protected_methods: Sequence[str] = DEFAULT_PROTECTED_METHODS
    exclude_paths: List[str] = field(default_factory=list)
    cookie: CsrfCookieOptions = field(default_factory=CsrfCookieOptions)


class CsrfProtection:
    """
    CSRF protection using double-submit cookie pattern.

    For safe methods (GET, HEAD, OPTIONS), sets a CSRF token cookie.
    For unsafe methods (POST, PUT, PATCH, DELETE), validates the token.

    Example (Flask):
        csrf = CsrfProtection()

        @app.before_request
        def check_csrf():
            error = csrf.flask_before_request()
            if error:
                return error

        @app.after_request
        def set_csrf_cookie(response):
            return csrf.flask_after_request(response)

    Example (client-side):
        token = document.cookie.match(/_csrf=([^;]+)/)?.[1]
        fetch('/api/data', {
            method: 'POST',
            headers: { 'X-CSRF-Token': token },
            credentials: 'same-origin'
        })
    """

    def __init__(
        self,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        header_name: str = DEFAULT_HEADER_NAME,
        field_name: str = DEFAULT_FIELD_NAME,
        token_length: int = DEFAULT_TOKEN_LENGTH,
        protected_methods: Optional[Sequence[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        cookie: Optional[CsrfCookieOptions] = None,
        on_error: Optional[Callable] = None,
        use_host_prefix: bool = False,
        skip_csrf: Optional[Callable] = None,
    ):
        # __Host- prefix: forces browser to enforce Secure + no Domain + Path=/
        self.cookie_name = f"{HOST_PREFIX}{cookie_name}" if use_host_prefix else cookie_name
        self.use_host_prefix = use_host_prefix
        self.skip_csrf = skip_csrf
        self.header_name = header_name
        self.field_name = field_name
        self.token_length = token_length
        self.protected_methods = set(
            m.upper() for m in (protected_methods or DEFAULT_PROTECTED_METHODS)
        )
        self.exclude_paths = exclude_paths or []
        self.cookie_opts = cookie or CsrfCookieOptions()
        self.on_error = on_error

    def _is_excluded(self, path: str) -> bool:
        """Check if a path is excluded from CSRF protection."""
        for excluded in self.exclude_paths:
            if path == excluded or path.startswith(excluded + "/"):
                return True
        return False

    def _build_cookie_header(self, token: str) -> str:
        """Build a Set-Cookie header value for the CSRF token."""
        parts = [f"{self.cookie_name}={token}"]
        parts.append(f"Path={self.cookie_opts.path}")
        if self.cookie_opts.http_only:
            parts.append("HttpOnly")

        secure = self.cookie_opts.secure
        if secure is None:
            secure = os.environ.get("FLASK_ENV") != "development"
        if secure:
            parts.append("Secure")

        parts.append(f"SameSite={self.cookie_opts.same_site}")
        if self.cookie_opts.domain:
            parts.append(f"Domain={self.cookie_opts.domain}")
        return "; ".join(parts)

    # ── Flask Integration ──────────────────────────────────────────────────

    def flask_before_request(self):
        """
        Flask before_request handler. Returns None on success, or a
        (response_body, status_code) tuple on CSRF failure.

        Example:
            @app.before_request
            def check_csrf():
                error = csrf.flask_before_request()
                if error:
                    return error
        """
        from flask import request

        # Per-request skip callback (API keys, signed webhooks, etc.)
        if self.skip_csrf and self.skip_csrf(request):
            return None

        if self._is_excluded(request.path):
            return None

        method = request.method.upper()
        if method not in self.protected_methods:
            return None

        cookie_token = request.cookies.get(self.cookie_name)
        if not cookie_token:
            return self._flask_error()

        request_token = self._get_flask_request_token(request)
        if not request_token:
            return self._flask_error()

        if not validate_csrf_token(cookie_token, request_token):
            return self._flask_error()

        return None

    def flask_after_request(self, response):
        """
        Flask after_request handler. Sets CSRF cookie on safe method responses
        if no cookie exists yet.

        Example:
            @app.after_request
            def set_csrf(response):
                return csrf.flask_after_request(response)
        """
        from flask import request

        method = request.method.upper()
        if method in self.protected_methods:
            return response

        existing = request.cookies.get(self.cookie_name)
        if not existing:
            token = generate_csrf_token(self.token_length)
            response.headers.add("Set-Cookie", self._build_cookie_header(token))

        return response

    def _get_flask_request_token(self, request) -> Optional[str]:
        """Extract CSRF token from Flask request (header or form body only)."""
        # Header
        header_token = request.headers.get(self.header_name)
        if header_token:
            return header_token

        # Form field
        form_token = request.form.get(self.field_name)
        if form_token:
            return form_token

        # JSON body
        if request.is_json:
            try:
                json_data = request.get_json(silent=True)
                if json_data and isinstance(json_data, dict):
                    token = json_data.get(self.field_name)
                    if token and isinstance(token, str):
                        return token
            except Exception:
                pass

        # SECURITY: Query string intentionally not supported — tokens in URLs leak
        # to server logs, Referer headers, browser history, and CDN/proxy logs.

        return None

    def _flask_error(self):
        """Return Flask CSRF error response."""
        if self.on_error:
            from flask import request
            return self.on_error(request)
        return {
            "error": "CSRF token validation failed",
            "message": "Invalid or missing CSRF token. Include the token "
                       "from the cookie in the X-CSRF-Token header.",
        }, 403

    # ── Generic / Framework-Agnostic ───────────────────────────────────────

    def check(
        self,
        method: str,
        path: str,
        cookie_token: Optional[str],
        request_token: Optional[str],
    ) -> bool:
        """
        Generic CSRF validation (framework-agnostic).

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            cookie_token: Token from the cookie
            request_token: Token from header or body

        Returns:
            True if request is valid (safe method or valid token)
        """
        if self._is_excluded(path):
            return True

        if method.upper() not in self.protected_methods:
            return True

        if not cookie_token or not request_token:
            return False

        return validate_csrf_token(cookie_token, request_token)

    def generate_token(self) -> str:
        """Generate a new CSRF token."""
        return generate_csrf_token(self.token_length)


def create_csrf(
    cookie_name: str = DEFAULT_COOKIE_NAME,
    header_name: str = DEFAULT_HEADER_NAME,
    field_name: str = DEFAULT_FIELD_NAME,
    token_length: int = DEFAULT_TOKEN_LENGTH,
    protected_methods: Optional[Sequence[str]] = None,
    exclude_paths: Optional[List[str]] = None,
    cookie: Optional[CsrfCookieOptions] = None,
    on_error: Optional[Callable] = None,
    use_host_prefix: bool = False,
    skip_csrf: Optional[Callable] = None,
) -> CsrfProtection:
    """
    Create a CSRF protection handler.

    Example:
        csrf = create_csrf(exclude_paths=['/api/webhooks'])
    """
    return CsrfProtection(
        cookie_name=cookie_name,
        header_name=header_name,
        field_name=field_name,
        token_length=token_length,
        protected_methods=protected_methods,
        exclude_paths=exclude_paths,
        cookie=cookie,
        on_error=on_error,
        use_host_prefix=use_host_prefix,
        skip_csrf=skip_csrf,
    )
