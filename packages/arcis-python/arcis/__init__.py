"""
Arcis Security Library for Python
===================================

One-line security for FastAPI, Django, Litestar (full pipeline) and Flask (sanitize-only) applications.

Usage:
    # Flask
    from arcis import Arcis
    app = Flask(__name__)
    arcis = Arcis(app)

    # Access sanitized JSON in routes
    from flask import g
    @app.route('/api', methods=['POST'])
    def api():
        data = g.json  # or g.sanitized_json

    # FastAPI
    from fastapi import FastAPI, Depends
    from arcis.fastapi import ArcisMiddleware, get_json

    app = FastAPI()
    app.add_middleware(ArcisMiddleware)

    @app.post("/api")
    async def api(data: dict = Depends(get_json)):
        pass  # data is sanitized

    # FastAPI with async rate limiter (new!)
    from arcis.fastapi import AsyncRateLimiter, create_rate_limit_dependency

    # Per-route rate limiting
    strict_limit = create_rate_limit_dependency(max_requests=10)

    @app.post("/login", dependencies=[Depends(strict_limit)])
    async def login():
        pass

    # Django (settings.py)
    MIDDLEWARE = ['arcis.django.ArcisMiddleware', ...]

    # In views:
    from arcis.django import get_json
    def my_view(request):
        data = get_json(request)

Cleanup:
    When your application shuts down, call arcis.close() to clean up
    background threads (rate limiter cleanup thread).

    # Flask example
    import atexit
    arcis = Arcis(app)
    atexit.register(arcis.close)
"""

# All imports now come from the restructured submodules.
# arcis.core is a package (arcis/core/__init__.py) that re-exports everything
# so existing ``from arcis.core import X`` statements continue to work.

from .core import (
    # Main class
    Arcis,
    # Core components
    Sanitizer,
    RateLimiter,
    RateLimitExceeded,
    RateLimitEntry,
    InMemoryStore,
    SecurityHeaders,
    Validator,
    ValidationError,
    SafeLogger,
    # Schema validation
    SchemaValidator,
    create_validator,
    # Error handling
    ErrorHandler,
    create_error_handler,
    # Exceptions
    InputTooLargeError,
    # Convenience functions
    sanitize_string,
    sanitize_dict,
    validate_email,
    validate_url,
    validate_uuid,
)

from .validation.url import (
    validate_url_ssrf,
    is_url_safe,
    ValidateUrlOptions,
    ValidateUrlResult,
)

from .validation.redirect import (
    validate_redirect,
    is_redirect_safe,
    ValidateRedirectOptions,
    ValidateRedirectResult,
)

from .sanitizers import (
    sanitize_xss,
    sanitize_sql,
    sanitize_nosql,
    sanitize_path,
    sanitize_command,
    detect_xss,
    detect_sql,
    detect_nosql,
    detect_path_traversal,
    detect_command_injection,
    detect_prototype_pollution,
    scan_threats,
    sanitize_ssti,
    detect_ssti,
    sanitize_xxe,
    detect_xxe,
    sanitize_jsonp_callback,
    detect_jsonp_injection,
    sanitize_header_value,
    sanitize_headers,
    detect_header_injection,
    scan_pii,
    detect_pii,
    redact_pii,
    scan_object_pii,
    redact_object_pii,
    encode_for_html,
    encode_for_attribute,
    encode_for_js,
    encode_for_url,
    encode_for_css,
    detect_prompt_injection,
    sanitize_prompt_injection,
    PromptInjectionMatch,
    DetectPromptInjectionResult,
)
# V33 deserialization marker detection (improvements.md §1.2).
# Standalone helper — not wired into sanitize_string because the right
# response to a serialized-payload signal is "refuse the request"
# not "strip the bytes and continue."
from .sanitizers.deserialization import (
    detect_deserialization,
    is_serialized_payload,
    DeserializeRuntime,
)

from .validation.email import (
    validate_email_address,
    verify_email_mx,
    verify_email_mx_async,
    is_valid_email_syntax,
    EmailValidationResult,
)

# Litestar adapter (and any ASGI host) — pure ASGI middleware, type-only
# litestar import. Lazy via attribute access to avoid a hard import on
# package load when the user is on the FastAPI / Flask / Django path.
from .litestar import ArcisMiddleware as ArcisLitestarMiddleware

from .middleware.rate_limit_sliding import SlidingWindowLimiter
from .middleware.rate_limit_token import TokenBucketLimiter
from .middleware.bot_detection import BotProtection, BotDenied, BotDetectionResult, detect_bot
from .middleware.token_budget import TokenBudget, TokenBudgetExceeded, token_budget
from .middleware.correlation import (
    CorrelationEvent,
    CorrelationDetections,
    CorrelationWindow,
)
from .guards import Guards, GuardsDecision
from .middleware.hpp import HppProtection, create_hpp
from .middleware.csrf import CsrfProtection, create_csrf, generate_csrf_token, validate_csrf_token
from .middleware.signup_protection import SignupProtection, SignupCheckResult, check_signup

from .utils import (
    parse_duration,
    format_duration,
    detect_client_ip,
    is_private_ip,
    fingerprint,
)

# Async components (for FastAPI)
try:
    from .fastapi import (
        AsyncRateLimiter,
        AsyncRateLimitExceeded,
        AsyncInMemoryStore,
        AsyncRateLimitStore,
        create_rate_limit_dependency,
    )
    _HAS_ASYNC = True
except ImportError:
    _HAS_ASYNC = False

__version__ = "1.6.4"
__all__ = [
    # Main class
    "Arcis",
    # Core components
    "Sanitizer",
    "RateLimiter",
    "RateLimitExceeded",
    "RateLimitEntry",
    "InMemoryStore",
    "SecurityHeaders",
    "Validator",
    "ValidationError",
    "SafeLogger",
    # Schema validation
    "SchemaValidator",
    "create_validator",
    # Error handling
    "ErrorHandler",
    "create_error_handler",
    # Exceptions
    "InputTooLargeError",
    # Convenience functions
    "sanitize_string",
    "sanitize_dict",
    "sanitize_xss",
    "sanitize_sql",
    "sanitize_nosql",
    "sanitize_path",
    "sanitize_command",
    "detect_xss",
    "detect_sql",
    "detect_nosql",
    "detect_path_traversal",
    "detect_command_injection",
    "detect_prototype_pollution",
    "scan_threats",
    "sanitize_ssti",
    "detect_ssti",
    "sanitize_header_value",
    "sanitize_headers",
    "detect_header_injection",
    "validate_url_ssrf",
    "is_url_safe",
    "ValidateUrlOptions",
    "ValidateUrlResult",
    "validate_redirect",
    "is_redirect_safe",
    "ValidateRedirectOptions",
    "ValidateRedirectResult",
    "validate_email",
    "validate_url",
    "validate_uuid",
    # Email validation (advanced)
    "validate_email_address",
    "verify_email_mx",
    "verify_email_mx_async",
    "is_valid_email_syntax",
    "EmailValidationResult",
    "ArcisLitestarMiddleware",
    # Rate limiters
    "SlidingWindowLimiter",
    "TokenBucketLimiter",
    # Bot detection
    "BotProtection",
    "BotDenied",
    "BotDetectionResult",
    "detect_bot",
    # LLM token-budget protection
    "TokenBudget",
    "TokenBudgetExceeded",
    "token_budget",
    # Stateful per-IP correlation window (improvements.md §1.3)
    "CorrelationEvent",
    "CorrelationDetections",
    "CorrelationWindow",
    # Guards API (non-HTTP contexts)
    "Guards",
    "GuardsDecision",
    # Signup protection (composite: email + bot + rate-limit)
    "SignupProtection",
    "SignupCheckResult",
    "check_signup",
    # PII detection and redaction
    "scan_pii",
    "detect_pii",
    "redact_pii",
    "scan_object_pii",
    "redact_object_pii",
    # Context-aware encoding
    "encode_for_html",
    "encode_for_attribute",
    "encode_for_js",
    "encode_for_url",
    "encode_for_css",
    # Utilities
    "parse_duration",
    "format_duration",
    "detect_client_ip",
    "is_private_ip",
    "fingerprint",
]

# Add async exports if available
if _HAS_ASYNC:
    __all__.extend([
        "AsyncRateLimiter",
        "AsyncRateLimitExceeded",
        "AsyncInMemoryStore",
        "AsyncRateLimitStore",
        "create_rate_limit_dependency",
    ])

# Redis store is available as a separate submodule (requires redis extra):
#   from arcis.stores.redis import RedisRateLimitStore       # sync (Flask/Django)
#   from arcis.stores.redis import AsyncRedisRateLimitStore  # async (FastAPI)
#
# Install with: pip install arcis[redis]
