"""
Arcis JSONP callback sanitization.

Validates and sanitizes JSONP callback parameters to prevent
XSS injection via ?callback= query parameters.
"""

import re
from typing import Optional

# Valid JSONP callback: alphanumeric, underscore, dollar, dot only.
# Brackets rejected — enables bypasses like `cb[x` (unbalanced) and not needed in practice.
_SAFE_CALLBACK_PATTERN = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$.]*$")

# Dangerous patterns within an otherwise-valid callback
_DANGEROUS_CALLBACK_PATTERNS = [
    re.compile(r"\.\."),        # prototype chain traversal
]


def sanitize_jsonp_callback(callback: str, max_length: int = 128) -> Optional[str]:
    """
    Validate and sanitize a JSONP callback parameter.

    Returns the callback name if safe, or None if the callback is dangerous.

    Args:
        callback: The callback parameter value
        max_length: Maximum allowed length (default: 128)

    Returns:
        The safe callback name, or None if invalid
    """
    if not isinstance(callback, str) or len(callback) == 0:
        return None

    if len(callback) > max_length:
        return None

    if not _SAFE_CALLBACK_PATTERN.match(callback):
        return None

    for pattern in _DANGEROUS_CALLBACK_PATTERNS:
        if pattern.search(callback):
            return None

    return callback


def detect_jsonp_injection(callback: str) -> bool:
    """
    Check if a JSONP callback parameter contains dangerous content.

    Args:
        callback: The callback parameter value

    Returns:
        True if the callback is dangerous / invalid
    """
    if not isinstance(callback, str) or len(callback) == 0:
        return False

    if not _SAFE_CALLBACK_PATTERN.match(callback):
        return True

    for pattern in _DANGEROUS_CALLBACK_PATTERNS:
        if pattern.search(callback):
            return True

    return False
