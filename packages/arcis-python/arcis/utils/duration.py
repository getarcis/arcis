"""
Arcis Utilities - Duration Parsing

Parse human-readable duration strings into milliseconds.

Examples:
    >>> parse_duration('5m')
    300000
    >>> parse_duration('2h')
    7200000
    >>> parse_duration(60000)
    60000
    >>> parse_duration('500ms')
    500
"""

import re
import math
from typing import Union

MAX_DURATION_MS = 4_294_967_295  # uint32 max (~49.7 days)

_DURATION_REGEX = re.compile(r'^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$', re.IGNORECASE)

_UNIT_TO_MS = {
    'ms': 1,
    's': 1_000,
    'm': 60_000,
    'h': 3_600_000,
    'd': 86_400_000,
}


def parse_duration(value: Union[str, int, float]) -> int:
    """
    Parse a duration string or number into milliseconds.

    Args:
        value: Duration string (e.g. "5m", "2h", "30s") or number (ms).

    Returns:
        Duration in milliseconds.

    Raises:
        ValueError: If the value is not a valid duration.

    Examples:
        >>> parse_duration('15m')
        900000
        >>> parse_duration('1d')
        86400000
        >>> parse_duration(60000)
        60000
    """
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"Invalid duration: {value}. Must be a non-negative finite number.")
        return min(int(value), MAX_DURATION_MS)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f'Invalid duration: "{value}". Expected a duration string (e.g. "5m", "2h") or number.'
        )

    match = _DURATION_REGEX.match(value.strip())
    if not match:
        raise ValueError(
            f'Invalid duration: "{value}". Expected format: <number><unit> where unit is ms, s, m, h, or d.'
        )

    amount = float(match.group(1))
    unit = match.group(2).lower()
    ms = int(amount * _UNIT_TO_MS[unit])

    if ms < 0 or ms > MAX_DURATION_MS:
        raise ValueError(
            f'Duration "{value}" exceeds maximum allowed ({MAX_DURATION_MS}ms / ~49.7 days).'
        )

    return ms


def format_duration(ms: int) -> str:
    """
    Format milliseconds into a human-readable duration string.

    Args:
        ms: Duration in milliseconds.

    Returns:
        Human-readable string (e.g. "5m", "2h 30m").
    """
    if not isinstance(ms, (int, float)) or not math.isfinite(ms) or ms < 0:
        return '0ms'

    if ms < 1000:
        return f'{ms}ms'

    days = ms // 86_400_000
    hours = (ms % 86_400_000) // 3_600_000
    minutes = (ms % 3_600_000) // 60_000
    seconds = (ms % 60_000) // 1_000

    parts = []
    if days > 0:
        parts.append(f'{days}d')
    if hours > 0:
        parts.append(f'{hours}h')
    if minutes > 0:
        parts.append(f'{minutes}m')
    if seconds > 0:
        parts.append(f'{seconds}s')

    return ' '.join(parts) or '0ms'
