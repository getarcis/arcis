"""
Arcis Middleware - Bot Detection

Local-only bot detection using User-Agent and behavioral signals.
Categorizes requests into bot types and allows/denies based on config.
No cloud calls — everything runs locally.

Examples:
    detector = BotDetector()
    result = detector.detect(request)
    if result.is_bot and result.category == 'AUTOMATED':
        return deny_response()
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

from ..utils.request import get_request_header


# =============================================================================
# BOT CATEGORIES
# =============================================================================

SEARCH_ENGINE = 'SEARCH_ENGINE'
SOCIAL = 'SOCIAL'
MONITORING = 'MONITORING'
AI_CRAWLER = 'AI_CRAWLER'
SCRAPER = 'SCRAPER'
AUTOMATED = 'AUTOMATED'
UNKNOWN = 'UNKNOWN'
HUMAN = 'HUMAN'

ALL_CATEGORIES = frozenset([
    SEARCH_ENGINE, SOCIAL, MONITORING, AI_CRAWLER,
    SCRAPER, AUTOMATED, UNKNOWN, HUMAN,
])


@dataclass
class BotDetectionResult:
    """Result of bot detection."""
    is_bot: bool
    category: str
    name: Optional[str] = None
    confidence: float = 0.0
    signals: List[str] = field(default_factory=list)


# =============================================================================
# BOT DATABASE
# =============================================================================

_BotPattern = tuple  # (compiled_regex, name, category)

def _compile_patterns() -> List[_BotPattern]:
    """Compile bot patterns once at import time."""
    raw = [
        # --- SEARCH ENGINES (specific variants before generic) ---
        (r'Googlebot-Image', 'Googlebot-Image', SEARCH_ENGINE),
        (r'Googlebot-Video', 'Googlebot-Video', SEARCH_ENGINE),
        (r'Googlebot-News', 'Googlebot-News', SEARCH_ENGINE),
        (r'Googlebot', 'Googlebot', SEARCH_ENGINE),
        (r'AdsBot-Google', 'AdsBot-Google', SEARCH_ENGINE),
        (r'Mediapartners-Google', 'Mediapartners-Google', SEARCH_ENGINE),
        (r'Bingbot', 'Bingbot', SEARCH_ENGINE),
        (r'msnbot', 'msnbot', SEARCH_ENGINE),
        (r'Slurp', 'Yahoo Slurp', SEARCH_ENGINE),
        (r'DuckDuckBot', 'DuckDuckBot', SEARCH_ENGINE),
        (r'Baiduspider', 'Baiduspider', SEARCH_ENGINE),
        (r'YandexBot', 'YandexBot', SEARCH_ENGINE),
        (r'YandexImages', 'YandexImages', SEARCH_ENGINE),
        (r'Sogou', 'Sogou', SEARCH_ENGINE),
        (r'Exabot', 'Exabot', SEARCH_ENGINE),
        (r'ia_archiver', 'Alexa', SEARCH_ENGINE),
        (r'Applebot', 'Applebot', SEARCH_ENGINE),
        (r'Qwantify', 'Qwantify', SEARCH_ENGINE),
        (r'PetalBot', 'PetalBot', SEARCH_ENGINE),
        (r'SeznamBot', 'SeznamBot', SEARCH_ENGINE),

        # --- SOCIAL ---
        (r'Twitterbot', 'Twitterbot', SOCIAL),
        (r'facebookexternalhit', 'Facebook', SOCIAL),
        (r'Facebot', 'Facebot', SOCIAL),
        (r'LinkedInBot', 'LinkedInBot', SOCIAL),
        (r'Pinterest', 'Pinterest', SOCIAL),
        (r'Slackbot', 'Slackbot', SOCIAL),
        (r'TelegramBot', 'TelegramBot', SOCIAL),
        (r'WhatsApp', 'WhatsApp', SOCIAL),
        (r'Discordbot', 'Discordbot', SOCIAL),
        (r'Redditbot', 'Redditbot', SOCIAL),
        (r'Embedly', 'Embedly', SOCIAL),
        (r'Quora Link Preview', 'Quora', SOCIAL),
        (r'Mastodon', 'Mastodon', SOCIAL),

        # --- MONITORING ---
        (r'UptimeRobot', 'UptimeRobot', MONITORING),
        (r'Pingdom', 'Pingdom', MONITORING),
        (r'Site24x7', 'Site24x7', MONITORING),
        (r'StatusCake', 'StatusCake', MONITORING),
        (r'Datadog', 'Datadog', MONITORING),
        (r'NewRelicPinger', 'New Relic', MONITORING),
        (r'Better Uptime Bot', 'Better Uptime', MONITORING),
        (r'GTmetrix', 'GTmetrix', MONITORING),
        (r'PageSpeed', 'PageSpeed Insights', MONITORING),

        # --- AI CRAWLERS ---
        (r'GPTBot', 'GPTBot', AI_CRAWLER),
        (r'ChatGPT-User', 'ChatGPT-User', AI_CRAWLER),
        (r'Claude-Web', 'Claude-Web', AI_CRAWLER),
        (r'ClaudeBot', 'ClaudeBot', AI_CRAWLER),
        (r'anthropic-ai', 'Anthropic', AI_CRAWLER),
        (r'Bytespider', 'Bytespider', AI_CRAWLER),
        (r'CCBot', 'CCBot', AI_CRAWLER),
        (r'cohere-ai', 'Cohere', AI_CRAWLER),
        (r'PerplexityBot', 'PerplexityBot', AI_CRAWLER),
        (r'YouBot', 'YouBot', AI_CRAWLER),
        (r'Google-Extended', 'Google-Extended', AI_CRAWLER),
        (r'Diffbot', 'Diffbot', AI_CRAWLER),
        (r'Amazonbot', 'Amazonbot', AI_CRAWLER),
        (r'meta-externalagent', 'Meta AI', AI_CRAWLER),

        # --- AUTOMATED TOOLS ---
        (r'HeadlessChrome', 'Headless Chrome', AUTOMATED),
        (r'PhantomJS', 'PhantomJS', AUTOMATED),
        (r'Selenium', 'Selenium', AUTOMATED),
        (r'Puppeteer', 'Puppeteer', AUTOMATED),
        (r'Playwright', 'Playwright', AUTOMATED),
        (r'Cypress', 'Cypress', AUTOMATED),
        (r'webdriver', 'WebDriver', AUTOMATED),
        (r'MSIE 6\.0', 'Fake IE6', AUTOMATED),

        # --- SCRAPERS / CLI TOOLS ---
        (r'^curl/', 'curl', SCRAPER),
        (r'^wget/', 'wget', SCRAPER),
        (r'^python-requests/', 'python-requests', SCRAPER),
        (r'^python-httpx/', 'python-httpx', SCRAPER),
        (r'^Python-urllib', 'Python-urllib', SCRAPER),
        (r'^aiohttp/', 'aiohttp', SCRAPER),
        (r'^Go-http-client', 'Go-http-client', SCRAPER),
        (r'^Java/', 'Java HttpClient', SCRAPER),
        (r'^Apache-HttpClient', 'Apache HttpClient', SCRAPER),
        (r'^okhttp/', 'OkHttp', SCRAPER),
        (r'^node-fetch/', 'node-fetch', SCRAPER),
        (r'^axios/', 'axios', SCRAPER),
        (r'^got/', 'got', SCRAPER),
        (r'^libwww-perl', 'libwww-perl', SCRAPER),
        (r'^Ruby', 'Ruby', SCRAPER),
        (r'^PHP/', 'PHP', SCRAPER),
        (r'Scrapy', 'Scrapy', SCRAPER),
        (r'^Postman', 'Postman', SCRAPER),
        (r'^Insomnia', 'Insomnia', SCRAPER),
        (r'^HTTPie/', 'HTTPie', SCRAPER),
    ]
    return [(re.compile(p, re.IGNORECASE), name, cat) for p, name, cat in raw]


BOT_PATTERNS = _compile_patterns()


# =============================================================================
# DETECTION ENGINE
# =============================================================================

def _detect_behavioral_signals(request) -> List[str]:
    """Detect behavioral signals that suggest a bot."""
    signals = []

    ua = get_request_header(request, 'user-agent')
    if not ua:
        signals.append('missing_user_agent')

    if not get_request_header(request, 'accept'):
        signals.append('missing_accept')

    if not get_request_header(request, 'accept-language'):
        signals.append('missing_accept_language')

    if not get_request_header(request, 'accept-encoding'):
        signals.append('missing_accept_encoding')

    connection = get_request_header(request, 'connection', '')
    if connection and connection.lower() == 'close':
        signals.append('connection_close')

    return signals


def detect_bot(request) -> BotDetectionResult:
    """
    Detect what kind of bot (if any) is making the request.

    Args:
        request: HTTP request object (Flask, Django, FastAPI).

    Returns:
        BotDetectionResult with category, name, confidence, and signals.

    Examples:
        >>> result = detect_bot(request)
        >>> if result.is_bot and result.category == 'AUTOMATED':
        ...     block_request()
    """
    raw_ua = get_request_header(request, 'user-agent', '') or ''
    # Truncate to prevent CPU abuse from very long UA strings
    ua = raw_ua[:2048] if len(raw_ua) > 2048 else raw_ua
    signals = _detect_behavioral_signals(request)

    # No User-Agent
    if not ua:
        return BotDetectionResult(
            is_bot=True,
            category=UNKNOWN,
            name=None,
            confidence=0.8,
            signals=signals,
        )

    # Match against known bot patterns
    for pattern, name, category in BOT_PATTERNS:
        if pattern.search(ua):
            return BotDetectionResult(
                is_bot=True,
                category=category,
                name=name,
                confidence=0.95,
                signals=signals,
            )

    # Behavioral analysis
    behavior_score = len(signals)
    if behavior_score >= 3:
        return BotDetectionResult(
            is_bot=True,
            category=UNKNOWN,
            name=None,
            confidence=min(1.0, 0.6 + (behavior_score * 0.1)),
            signals=signals,
        )

    return BotDetectionResult(
        is_bot=False,
        category=HUMAN,
        name=None,
        confidence=max(0.0, 1.0 - (behavior_score * 0.15)),
        signals=signals,
    )


class BotProtection:
    """
    Bot protection middleware component.

    Can be used standalone or integrated into Arcis middleware.

    Example:
        bot_guard = BotProtection(
            allow=['SEARCH_ENGINE', 'SOCIAL', 'MONITORING'],
            deny=['AUTOMATED', 'SCRAPER'],
        )
        result = bot_guard.check(request)
        # result is a BotDetectionResult; raises BotDenied if blocked
    """

    def __init__(
        self,
        allow: Optional[List[str]] = None,
        deny: Optional[List[str]] = None,
        default_action: str = 'allow',
        message: str = 'Access denied.',
    ):
        self.allow: Set[str] = set(allow or [SEARCH_ENGINE, SOCIAL, MONITORING])
        self.deny: Set[str] = set(deny or [AUTOMATED])
        self.default_action = default_action
        self.message = message

    def check(self, request) -> BotDetectionResult:
        """
        Check request for bot activity.

        Returns:
            BotDetectionResult.

        Raises:
            BotDenied: If the bot category is denied.
        """
        result = detect_bot(request)

        if not result.is_bot:
            return result

        if result.category in self.allow:
            return result

        if result.category in self.deny:
            self._tag_marker(request, result)
            raise BotDenied(self.message, result)

        if self.default_action == 'deny':
            self._tag_marker(request, result)
            raise BotDenied(self.message, result)

        return result

    def _tag_marker(self, request, result: BotDetectionResult) -> None:
        """Tag the per-request telemetry marker so the dashboard groups
        bot denials under ``vector=bot`` rather than ``vector=null``.
        Lazy-imported to avoid circular dependency at module load."""
        try:
            from .telemetry import tag_marker
            tag_marker(
                request,
                vector="bot",
                rule=f"bot/{result.category.lower()}",
                reason=f"Bot detected: {result.name}" if result.name else "Bot detected",
                severity="medium",
            )
        except Exception:
            pass  # never let telemetry break the deny path


class BotDenied(Exception):
    """Exception raised when a bot is denied access."""
    def __init__(self, message: str = 'Access denied.', result: Optional[BotDetectionResult] = None):
        self.message = message
        self.result = result
        super().__init__(self.message)
