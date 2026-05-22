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
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .bot_detection import detect_bot
from .signup_protection import _extract_field

if TYPE_CHECKING:
    from .correlation import CorrelationWindow


LoginBlockReason = str  # 'bot' | 'rate_limited' | 'missing_credentials' | 'correlation' | 'ok'


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
    correlation_window: "Optional[CorrelationWindow]" = None,
    client_ip: Optional[str] = None,
    route: str = "/login",
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

    username: Optional[str] = None
    if require_credentials:
        username = _extract_field(request, username_field)
        password = _extract_field(request, password_field)
        if not username or not password:
            return LoginCheckResult(
                allowed=False, reason="missing_credentials"
            )
    else:
        # Still pull the username for correlation tracking when present.
        username = _extract_field(request, username_field)

    # Correlation window opt-in (improvements.md §1.3 / §1.4). When the
    # caller passes a window + client IP, record this attempt and refuse
    # if the window flags the IP as a scanner, credential stuffer, or
    # race-window probe. Detection-only otherwise; default behavior with
    # no window passed is unchanged.
    if correlation_window is not None and client_ip:
        detections = correlation_window.record(
            client_ip,
            vector="login",
            route=route,
            method="POST",
            distinct_value=username if isinstance(username, str) else None,
        )
        if (
            detections.scanner
            or detections.credential_stuffing
            or detections.race_window
        ):
            return LoginCheckResult(
                allowed=False,
                reason="correlation",
                details={
                    "scanner": detections.scanner,
                    "credential_stuffing": detections.credential_stuffing,
                    "race_window": detections.race_window,
                    "distinct_vectors": detections.distinct_vectors,
                    "distinct_values": detections.distinct_values,
                    "requests_in_window": detections.requests_in_window,
                },
            )

    return LoginCheckResult(allowed=True, reason="ok")
