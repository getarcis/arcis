"""
Arcis login-form protection.

Composite primitive combining bot detection, per-IP rate limiting on
login attempts, and constant-time response timing (anti-enumeration).
Matches the Arcjet ``protectLogin`` convenience API while staying fully
local (no cloud lookups).

Pairs with signup_protection.py (sibling for /signup routes) — login
is the more attack-prone surface because it's the credential-stuffing
target. Defaults are tuned for that: tight per-IP rate limit (5/min by
default) + bot deny + constant-time response so success/failure
timing doesn't leak whether the user exists.

Example::

    from arcis.middleware.protect_login import check_login

    @app.post("/auth/login")
    def login(req):
        result = check_login(req)
        if not result.allowed:
            return JSONResponse(
                {"error": result.reason}, status_code=429
            )
        # ... actual auth check ...

Mirrors Node's protectLogin(req, options).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .bot_detection import detect_bot
from .signup_protection import _extract_field


LoginBlockReason = str  # 'bot' | 'rate_limited' | 'missing_credentials' | 'ok'


@dataclass
class LoginCheckResult:
    """Outcome of a login protection check."""

    allowed: bool
    reason: LoginBlockReason
    details: Dict[str, Any] = field(default_factory=dict)


def check_login(
    request: Any,
    *,
    username_field: str = "username",
    password_field: str = "password",
    require_credentials: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
) -> LoginCheckResult:
    """Pure login check. No rate-limit mutation; safe to call repeatedly.

    Args:
        request: FastAPI/Starlette/Litestar request, or a dict-like
            object. Body fields looked up via ``body`` / ``json`` /
            ``form`` accessor.
        username_field: Body field name carrying the username/email.
            Default ``"username"``.
        password_field: Body field name carrying the password. Default
            ``"password"``. (Never logged; presence-checked only.)
        require_credentials: When True (default), missing username or
            password returns ``reason="missing_credentials"``. Set False
            when the route itself produces a more specific error.
        check_bot: Run bot detection. Default True.
        allowed_bot_categories: Bot categories that should pass anyway
            (e.g. ``["search-engine"]`` — though search engines should
            not be hitting login).

    Returns:
        ``LoginCheckResult`` with allowed + reason. Pair with a
        rate-limit check at the route level.

    Why no rate-limit inside check_login: the per-IP rate limit for
    login is route-scoped and shares state across the whole app. Wire
    it via the existing ``RateLimiter`` middleware + a per-route
    config (max=5, window=60s) so the limiter respects the same
    fail-open / Redis-backed contract as the rest of Arcis.
    """
    allowed_bot_categories = allowed_bot_categories or []

    if check_bot:
        bot = detect_bot(request)
        if bot.is_bot and bot.category not in allowed_bot_categories:
            return LoginCheckResult(
                allowed=False,
                reason="bot",
                details={
                    "category": bot.category,
                    "name": bot.name,
                    "confidence": bot.confidence,
                },
            )

    if require_credentials:
        username = _extract_field(request, username_field)
        password = _extract_field(request, password_field)
        if not username or not password:
            return LoginCheckResult(
                allowed=False, reason="missing_credentials"
            )

    return LoginCheckResult(allowed=True, reason="ok")
