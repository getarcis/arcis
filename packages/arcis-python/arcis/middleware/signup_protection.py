"""
Arcis signup-form protection.

Composite primitive combining email validation (syntax + disposable),
bot detection, and a dedicated per-IP rate limit. Matches the Arcjet
`protectSignup` convenience API while staying fully local (no cloud
lookups).

Example:
    protection = SignupProtection(rate_limit_max=5, rate_limit_window_ms=60_000)
    result = protection.check(request)
    if not result.allowed:
        raise HTTPException(status_code=400, detail=result.reason)
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..validation.email import validate_email_address
from .bot_detection import detect_bot
from .rate_limit import RateLimiter, RateLimitExceeded


SignupBlockReason = str  # 'missing_email' | 'invalid_email' | 'disposable_email' | 'bot' | 'rate_limited' | 'ok'


@dataclass
class SignupCheckResult:
    """Outcome of a signup protection check."""
    allowed: bool
    reason: SignupBlockReason
    details: Dict[str, Any] = field(default_factory=dict)


def check_signup(
    request: Any,
    *,
    email_field: str = "email",
    check_email: bool = True,
    block_disposable: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    allowed_email_domains: Optional[List[str]] = None,
    blocked_email_domains: Optional[List[str]] = None,
) -> SignupCheckResult:
    """Pure signup check. No rate-limit mutation; safe to call repeatedly.

    `request` must expose either a dict-like `body`/`json`/`form` attribute
    or be a mapping itself. The email field is looked up in that order.
    """
    allowed_bot_categories = allowed_bot_categories or []

    if check_bot:
        bot = detect_bot(request)
        if bot.is_bot and bot.category not in allowed_bot_categories:
            return SignupCheckResult(
                allowed=False,
                reason="bot",
                details={"category": bot.category, "name": bot.name, "confidence": bot.confidence},
            )

    if check_email:
        email = _extract_field(request, email_field)
        if not isinstance(email, str) or not email:
            return SignupCheckResult(allowed=False, reason="missing_email")

        result = validate_email_address(
            email,
            check_disposable=block_disposable,
            allowed_domains=allowed_email_domains,
            blocked_domains=blocked_email_domains,
        )
        if not result.valid:
            reason = "disposable_email" if result.reason == "disposable" else "invalid_email"
            return SignupCheckResult(
                allowed=False,
                reason=reason,
                details={"email_reason": result.reason},
            )

    return SignupCheckResult(allowed=True, reason="ok")


def _extract_field(request: Any, field_name: str) -> Any:
    """Best-effort extraction of a body field across request shapes."""
    for attr in ("body", "json", "form"):
        container = getattr(request, attr, None)
        if callable(container):
            try:
                container = container()
            except Exception:
                container = None
        if isinstance(container, dict) and field_name in container:
            return container[field_name]
    if isinstance(request, dict) and field_name in request:
        return request[field_name]
    return None


class SignupProtection:
    """Stateful signup protection: bundles a rate limiter with the pure check.

    Call `.check(request)` per request; on exhaustion it returns a
    `SignupCheckResult` with reason='rate_limited' rather than raising.

    Remember to call `.close()` on shutdown so the rate-limiter cleanup
    thread exits cleanly.
    """

    def __init__(
        self,
        *,
        email_field: str = "email",
        check_email: bool = True,
        block_disposable: bool = True,
        check_bot: bool = True,
        allowed_bot_categories: Optional[List[str]] = None,
        allowed_email_domains: Optional[List[str]] = None,
        blocked_email_domains: Optional[List[str]] = None,
        rate_limit_max: Optional[int] = 5,
        rate_limit_window_ms: int = 60_000,
        rate_limit_key_func: Optional[Callable[[Any], str]] = None,
        on_blocked: Optional[Callable[[Any, SignupCheckResult], None]] = None,
    ):
        self._opts = dict(
            email_field=email_field,
            check_email=check_email,
            block_disposable=block_disposable,
            check_bot=check_bot,
            allowed_bot_categories=allowed_bot_categories,
            allowed_email_domains=allowed_email_domains,
            blocked_email_domains=blocked_email_domains,
        )
        self._on_blocked = on_blocked
        self._limiter: Optional[RateLimiter] = None
        if rate_limit_max is not None and rate_limit_max > 0:
            self._limiter = RateLimiter(
                max_requests=rate_limit_max,
                window_ms=rate_limit_window_ms,
                message="Too many signup attempts",
                key_func=rate_limit_key_func,
            )

    def check(self, request: Any) -> SignupCheckResult:
        result = check_signup(request, **self._opts)
        if not result.allowed:
            if self._on_blocked:
                self._on_blocked(request, result)
            return result

        if self._limiter is not None:
            try:
                self._limiter.check(request)
            except RateLimitExceeded as e:
                rl_result = SignupCheckResult(
                    allowed=False,
                    reason="rate_limited",
                    details={"retry_after": getattr(e, "retry_after", None)},
                )
                if self._on_blocked:
                    self._on_blocked(request, rl_result)
                return rl_result

        return result

    def close(self) -> None:
        if self._limiter is not None:
            self._limiter.close()
