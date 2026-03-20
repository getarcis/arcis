"""
Arcis XXE (XML External Entity) injection prevention.

Detects and sanitizes XXE payloads including DOCTYPE declarations,
ENTITY definitions, SYSTEM/PUBLIC references, parameter entities,
and CDATA abuse.
"""

import re

# Detection patterns — used by detect_xxe()
_XXE_DETECT_PATTERNS = [
    # DOCTYPE declaration
    re.compile(r"<!DOCTYPE\b", re.IGNORECASE),
    # ENTITY declaration
    re.compile(r"<!ENTITY\b", re.IGNORECASE),
    # SYSTEM keyword with URI
    re.compile(r"\bSYSTEM\s+[\"']", re.IGNORECASE),
    # PUBLIC keyword with URI
    re.compile(r"\bPUBLIC\s+[\"']", re.IGNORECASE),
    # Parameter entity reference (%entity;)
    re.compile(r"%\s*\w+\s*;"),
    # CDATA section
    re.compile(r"<!\[CDATA\[", re.IGNORECASE),
]

# Removal patterns — used by sanitize_xxe()
_XXE_REMOVE_PATTERNS = [
    # Full DOCTYPE block with optional internal subset: <!DOCTYPE ... [...]>
    re.compile(r"<!DOCTYPE\s[^[>]*(?:\[[^\]]*\]\s*)?>|<!DOCTYPE\s[^>]*>", re.IGNORECASE),
    # Full ENTITY declaration: <!ENTITY ... >
    re.compile(r"<!ENTITY[^>]*>", re.IGNORECASE),
    # CDATA sections: <![CDATA[ ... ]]>
    re.compile(r"<!\[CDATA\[[\s\S]*?\]\]>", re.IGNORECASE),
]


def detect_xxe(value: str) -> bool:
    """
    Check if a string contains XXE patterns.

    Returns True if any XXE injection pattern is detected.
    Does not modify the input — use sanitize_xxe() for that.
    """
    if not isinstance(value, str):
        return False

    for pattern in _XXE_DETECT_PATTERNS:
        if pattern.search(value):
            return True

    return False


def sanitize_xxe(value: str) -> str:
    """
    Sanitize a string by removing XXE payloads.

    Strips DOCTYPE declarations, ENTITY definitions, and CDATA sections.
    """
    if not isinstance(value, str):
        raise TypeError(f"sanitize_xxe expects str, got {type(value).__name__}")

    result = value
    for pattern in _XXE_REMOVE_PATTERNS:
        result = pattern.sub("", result)

    return result
