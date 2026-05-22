"""
Arcis API-endpoint protection.

Composite primitive combining bot detection (with sane allowlist for
legitimate API clients), CORS origin validation, and request-body
threat scanning. Matches the Arcjet ``protectApi`` convenience API
while staying fully local.

Differs from signup_protection / protect_login in that API endpoints
often serve legitimate non-browser clients (SDK, mobile, server-to-
server). Default ``allowed_bot_categories`` includes common SDK user
agents so a Python `requests` library call from a customer's server
isn't denied as "bot".

Example::

    from arcis.middleware.protect_api import check_api

    @app.post("/api/transfer")
    def transfer(req):
        result = check_api(req, expected_origins=["https://app.example.com"])
        if not result.allowed:
            return JSONResponse({"error": result.reason}, status_code=403)
        # ... handler logic ...

Mirrors Node's protectApi(req, options).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..sanitizers.sanitize import scan_threats
from .bot_detection import detect_bot

if TYPE_CHECKING:
    from .correlation import CorrelationWindow


ApiBlockReason = str  # 'bot' | 'bad_origin' | 'threat' | 'correlation' | 'ok'


# Legitimate non-browser categories that should be allowed by default.
# Uses the BotDetector taxonomy from bot_detection.py: SEARCH_ENGINE,
# SOCIAL, MONITORING, AI_CRAWLER, SCRAPER, AUTOMATED, UNKNOWN, HUMAN.
# MONITORING (uptime probes, health checks) is the only one a customer
# API endpoint reasonably accepts by default; SCRAPER / AUTOMATED stay
# blocked because they're the credential-stuffing / scrape vectors.
DEFAULT_ALLOWED_API_BOTS: List[str] = [
    "MONITORING",
]


@dataclass
class ApiCheckResult:
    """Outcome of an API protection check."""

    allowed: bool
    reason: ApiBlockReason
    details: Dict[str, Any] = field(default_factory=dict)


def check_api(
    request: Any,
    *,
    expected_origins: Optional[List[str]] = None,
    check_bot: bool = True,
    allowed_bot_categories: Optional[List[str]] = None,
    scan_body: bool = True,
    correlation_window: "Optional[CorrelationWindow]" = None,
    client_ip: Optional[str] = None,
    route: str = "/api",
) -> ApiCheckResult:
    """Pure API check. No rate-limit mutation; safe to call repeatedly.

    Args:
        request: FastAPI/Starlette/Litestar request, or a dict-like
            object exposing ``headers`` and ``body``/``json``.
        expected_origins: When set, the ``Origin`` header must be in
            this list (case-insensitive). Unset = no origin check.
            Use ``[]`` (empty list) to deny ALL Origin-bearing requests.
        check_bot: Run bot detection. Default True. Set False on
            internal RPC endpoints between services.
        allowed_bot_categories: Bot categories to allow through. When
            None, uses ``DEFAULT_ALLOWED_API_BOTS`` (sdk-client +
            monitoring).
        scan_body: Run scan_threats on the request body. Default True.
            Pulled from request.body / request.json / request.form in
            that order; first dict/list/str found is scanned.

    Returns:
        ``ApiCheckResult`` with allowed + reason. Pair with a
        rate-limiter at the route level.
    """
    if allowed_bot_categories is None:
        allowed_bot_categories = list(DEFAULT_ALLOWED_API_BOTS)

    # Origin check first — fail-fast on cross-origin attacks that
    # don't carry a legitimate Origin.
    if expected_origins is not None:
        origin = _extract_header(request, "origin") or ""
        origin_lower = origin.lower().rstrip("/")
        allowed_set = {h.lower().rstrip("/") for h in expected_origins}
        if not origin_lower or origin_lower not in allowed_set:
            return ApiCheckResult(
                allowed=False,
                reason="bad_origin",
                details={"origin": origin},
            )

    if check_bot:
        bot = detect_bot(request)
        if bot.is_bot and bot.category not in allowed_bot_categories:
            return ApiCheckResult(
                allowed=False,
                reason="bot",
                details={
                    "category": bot.category,
                    "name": bot.name,
                    "confidence": bot.confidence,
                },
            )

    detected_threat_vector: Optional[str] = None
    if scan_body:
        body = _extract_body(request)
        if body is not None:
            threat = scan_threats(body)
            if threat is not None:
                vector, rule, matched = threat
                detected_threat_vector = vector
                # Record the threat in the correlation window first so a
                # scanner that hits this endpoint multiple times shows up
                # as one. THEN fail the request.
                if correlation_window is not None and client_ip:
                    correlation_window.record(
                        client_ip,
                        vector=vector,
                        route=route,
                        method="POST",
                    )
                return ApiCheckResult(
                    allowed=False,
                    reason="threat",
                    details={
                        "vector": vector,
                        "rule": rule,
                        "matched": matched,
                    },
                )

    # Correlation window opt-in (improvements.md §1.3 / §1.4). Record the
    # non-threat request as "api" so cross-route scanning is detectable.
    if correlation_window is not None and client_ip:
        detections = correlation_window.record(
            client_ip,
            vector=detected_threat_vector or "api",
            route=route,
            method="POST",
        )
        if (
            detections.scanner
            or detections.credential_stuffing
            or detections.race_window
        ):
            return ApiCheckResult(
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

    return ApiCheckResult(allowed=True, reason="ok")


def _extract_body(request: Any) -> Any:
    """Best-effort extraction of the request body across framework shapes."""
    for attr in ("body", "json", "form"):
        container = getattr(request, attr, None)
        if callable(container):
            try:
                container = container()
            except Exception:
                container = None
        if container is not None and (
            isinstance(container, (dict, list, str))
        ):
            return container
    return None


def _extract_header(request: Any, name: str) -> Optional[str]:
    """Pull a header value across the framework request shapes Arcis
    supports. Returns None when not present."""
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    name_lower = name.lower()
    # FastAPI/Starlette/Litestar: headers is a mapping-like with
    # case-insensitive get.
    if hasattr(headers, "get"):
        value = headers.get(name) or headers.get(name_lower) or headers.get(
            name.title()
        )
        return value if isinstance(value, str) else None
    # Django shape: request.META["HTTP_ORIGIN"]
    meta = getattr(request, "META", None) or {}
    if isinstance(meta, dict):
        return meta.get("HTTP_" + name.upper().replace("-", "_"))
    return None
