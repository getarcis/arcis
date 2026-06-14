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

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ..utils.request import get_request_header


# =============================================================================
# BOT CATEGORIES
# =============================================================================

SEARCH_ENGINE = 'SEARCH_ENGINE'
SOCIAL = 'SOCIAL'
MONITORING = 'MONITORING'
AI_CRAWLER = 'AI_CRAWLER'
SCRAPER = 'SCRAPER'
SECURITY_SCANNER = 'SECURITY_SCANNER'
AUTOMATED = 'AUTOMATED'
UNKNOWN = 'UNKNOWN'
HUMAN = 'HUMAN'

ALL_CATEGORIES = frozenset([
    SEARCH_ENGINE, SOCIAL, MONITORING, AI_CRAWLER,
    SCRAPER, SECURITY_SCANNER, AUTOMATED, UNKNOWN, HUMAN,
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

@dataclass
class _BotEntry:
    """A compiled bot signature: ALL accepted patterns must match AND no
    forbidden pattern may match for an entry to fire."""
    entry_id: str
    name: str
    category: str
    accepted: Tuple[re.Pattern, ...]
    forbidden: Tuple[re.Pattern, ...]


def _load_bot_patterns() -> List[_BotEntry]:
    """Load and compile the bot-corpus shipped with the package.

    Source: ``arcis/data/bot_patterns.json`` — derived from
    arcjet/well-known-bots (MIT) plus a supplementary list of browser
    automation tools and CLI scrapers. Regenerate via
    ``python packages/core/generate-bot-patterns.py`` after upgrading.
    """
    data_path = Path(__file__).resolve().parent.parent / "data" / "bot_patterns.json"
    with data_path.open() as f:
        raw = json.load(f)
    out: List[_BotEntry] = []
    for entry in raw:
        out.append(_BotEntry(
            entry_id=entry["id"],
            name=entry["name"],
            category=entry["category"],
            accepted=tuple(re.compile(p, re.IGNORECASE) for p in entry["patterns"]),
            forbidden=tuple(re.compile(p, re.IGNORECASE) for p in entry["forbidden"]),
        ))
    return out


BOT_PATTERNS = _load_bot_patterns()

# Snapshot of the bundled set, captured before any cloud merge, so tests can
# restore a clean baseline.
_BUNDLED_PATTERNS = list(BOT_PATTERNS)


def merge_bot_patterns(entries) -> int:
    """Merge cloud-fetched bot-corpus entries on top of the bundled corpus
    (Phase C cloud refresh). New ids are appended; existing ids are replaced in
    place. An entry with an uncompilable pattern or missing field is skipped
    (fail-open) -- this never raises into the refresh path. Process-global by
    design, mirroring the bundled import. Returns the number merged.
    """
    merged = 0
    for entry in entries:
        try:
            compiled = _BotEntry(
                entry_id=entry["id"],
                name=entry["name"],
                category=entry["category"],
                accepted=tuple(re.compile(p, re.IGNORECASE) for p in entry["patterns"]),
                forbidden=tuple(re.compile(p, re.IGNORECASE) for p in entry.get("forbidden", [])),
            )
        except (re.error, KeyError, TypeError):
            continue
        for i, existing in enumerate(BOT_PATTERNS):
            if existing.entry_id == compiled.entry_id:
                BOT_PATTERNS[i] = compiled
                break
        else:
            BOT_PATTERNS.append(compiled)
        merged += 1
    return merged


def _reset_bot_patterns_for_test() -> None:
    """Test hook -- restore the bundled corpus, dropping cloud-merged entries."""
    BOT_PATTERNS[:] = _BUNDLED_PATTERNS


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

    # Match against known bot patterns. ALL accepted patterns must match
    # (multi-pattern entries like iMessage Preview need every token present)
    # AND no forbidden pattern may match.
    for entry in BOT_PATTERNS:
        if not entry.accepted:
            continue
        if not all(p.search(ua) for p in entry.accepted):
            continue
        if any(p.search(ua) for p in entry.forbidden):
            continue
        return BotDetectionResult(
            is_bot=True,
            category=entry.category,
            name=entry.name,
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
