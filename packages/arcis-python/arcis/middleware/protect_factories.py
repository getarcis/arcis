"""Per-framework protect factory glue (improvements.md §1.4).

The composite checks (:func:`check_login`, :func:`check_signup`,
:func:`check_api`) are framework-agnostic. They take a request object and
return an ``*CheckResult`` with ``allowed`` / ``reason`` / ``details``.
The per-framework adapters (FastAPI/Starlette, Litestar, Django) need a
thin wrapper that:

1. extracts the client IP (X-Forwarded-For first hop, then the socket
   peer / ``REMOTE_ADDR``),
2. extracts the route path,
3. forwards an optional shared :class:`CorrelationWindow` plus the right
   ``vector`` tag into the base check,
4. maps a denial to the framework's standard error response.

This module holds the shared glue so the adapter files stay short and
behave identically. No new security logic lives here: the actual
detection is owned by the base checks and the correlation window.

The signup base check (:func:`check_signup`) does not itself accept a
correlation window, so :func:`record_signup_correlation` performs the
recording in the wrapper instead, tagging the event ``vector="signup"``.
That keeps the signup surface at parity with login / api without
changing the base check signature.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from .correlation import CorrelationDetections, CorrelationWindow
from .protect_api import check_api
from .protect_login import check_login
from .signup_protection import SignupCheckResult, _extract_field, check_signup

# Mirrors the Node protect helper defaults table (login 5/min, signup
# 3/min, api 100/min). Python leaves rate limiting to the RateLimiter
# middleware, so these are exported only as documented reference defaults
# for callers wiring a per-route limiter alongside a factory.
DEFAULT_LOGIN_RATE_LIMIT: Tuple[int, int] = (5, 60_000)
DEFAULT_SIGNUP_RATE_LIMIT: Tuple[int, int] = (3, 60_000)
DEFAULT_API_RATE_LIMIT: Tuple[int, int] = (100, 60_000)

# Reasons that should map to HTTP 429 (rate / correlation pressure).
# Everything else that denies maps to 403 except client-input errors,
# which map to 400.
_STATUS_429_REASONS = frozenset({"correlation", "rate_limited"})
_STATUS_400_REASONS = frozenset(
    {"missing_credentials", "missing_email", "invalid_email", "disposable_email"}
)


def block_status_code(reason: str) -> int:
    """Map a composite-check block reason to an HTTP status code.

    Correlation and rate pressure return 429 (the client should slow
    down). Bot / bad-origin / threat denials return 403. Missing or
    malformed credentials return 400 (a client-input error).

    Args:
        reason: The ``reason`` field from a composite ``*CheckResult``.

    Returns:
        The HTTP status code for the denial response.
    """
    if reason in _STATUS_429_REASONS:
        return 429
    if reason in _STATUS_400_REASONS:
        return 400
    return 403


def client_ip_from_xff_then(
    xff_header: Optional[str], fallback: Optional[str]
) -> Optional[str]:
    """Resolve the client IP: X-Forwarded-For first hop, then a fallback.

    The factory wrappers honor the X-Forwarded-For first hop (the address
    the edge proxy saw the client connect from) and fall back to the
    framework's socket peer (``request.client.host`` /
    ``META['REMOTE_ADDR']``) when no forwarded header is present.

    Args:
        xff_header: Raw ``X-Forwarded-For`` header value, or None.
        fallback: Socket peer address to use when no forwarded header is
            present.

    Returns:
        The resolved client IP, or None when neither source yields one.
    """
    if xff_header:
        first = xff_header.split(",")[0].strip()
        if first:
            return first
    return fallback or None


def record_signup_correlation(
    request: Any,
    *,
    correlation_window: Optional[CorrelationWindow],
    client_ip: Optional[str],
    route: str,
    email_field: str = "email",
) -> Optional[CorrelationDetections]:
    """Record a signup attempt in the correlation window.

    :func:`check_signup` does not take a correlation window, so the
    factory wrapper records the event here to bring signup to parity with
    the login / api surfaces. The recorded ``distinct_value`` is the email
    (so a single IP cycling many emails at one signup route surfaces as
    credential-stuffing-shaped pressure).

    Args:
        request: The framework request, used to pull the email field.
        correlation_window: Shared window, or None to skip recording.
        client_ip: Resolved client IP. Recording is skipped when falsy.
        route: Route label recorded in the window.
        email_field: Body field carrying the email. Default ``"email"``.

    Returns:
        The :class:`CorrelationDetections` from the recording, or None
        when no window / IP was supplied.
    """
    if correlation_window is None or not client_ip:
        return None
    email = _extract_field(request, email_field)
    distinct_value = email if isinstance(email, str) and email else None
    return correlation_window.record(
        client_ip,
        vector="signup",
        route=route,
        method="POST",
        distinct_value=distinct_value,
    )


def signup_check_with_correlation(
    request: Any,
    *,
    correlation_window: Optional[CorrelationWindow],
    client_ip: Optional[str],
    route: str,
    email_field: str = "email",
    check_email: bool = True,
    block_disposable: bool = True,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    allowed_email_domains: Optional[List[str]] = None,
    blocked_email_domains: Optional[List[str]] = None,
) -> SignupCheckResult:
    """Run :func:`check_signup` then consult the correlation window.

    Thin composition used by every signup factory: the base signup check
    runs first (bot + email validation); if it passes, the attempt is
    recorded in the correlation window and a correlation denial overrides
    the pass. The base check's own denials (bot / email) are returned
    unchanged.

    Args:
        request: The framework request.
        correlation_window: Shared window, or None to skip correlation.
        client_ip: Resolved client IP.
        route: Route label recorded in the window.
        email_field: Body field carrying the email. Default ``"email"``.
        check_email: Forwarded to :func:`check_signup`.
        block_disposable: Forwarded to :func:`check_signup`.
        check_bot: Forwarded to :func:`check_signup`.
        allowed_bot_categories: Forwarded to :func:`check_signup`.
        allowed_email_domains: Forwarded to :func:`check_signup`.
        blocked_email_domains: Forwarded to :func:`check_signup`.

    Returns:
        A :class:`SignupCheckResult`. Reason ``"correlation"`` when the
        window flagged the IP, otherwise the base check's result.
    """
    result = check_signup(
        request,
        email_field=email_field,
        check_email=check_email,
        block_disposable=block_disposable,
        check_bot=check_bot,
        allowed_bot_categories=allowed_bot_categories,
        allowed_email_domains=allowed_email_domains,
        blocked_email_domains=blocked_email_domains,
    )
    if not result.allowed:
        return result

    detections = record_signup_correlation(
        request,
        correlation_window=correlation_window,
        client_ip=client_ip,
        route=route,
        email_field=email_field,
    )
    if detections is not None and (
        detections.scanner
        or detections.credential_stuffing
        or detections.race_window
    ):
        return SignupCheckResult(
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
    return result


__all__ = [
    "DEFAULT_LOGIN_RATE_LIMIT",
    "DEFAULT_SIGNUP_RATE_LIMIT",
    "DEFAULT_API_RATE_LIMIT",
    "block_status_code",
    "client_ip_from_xff_then",
    "record_signup_correlation",
    "signup_check_with_correlation",
    "check_login",
    "check_api",
    "check_signup",
]
