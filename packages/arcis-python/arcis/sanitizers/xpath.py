"""
XPath injection prevention (sdk-vectors.md tier 1 #23).

XPath 1.0 has no escape syntax for string literals. The only way to
embed user input safely is parameterised queries via variable bindings
(`/foo[@name = $username]`). Neither libxml2 nor the Python standard
library's `xml.etree.ElementTree` expose a canonical escape function
for XPath. The pragmatic answer everyone ships:

- Detect: scan for unescaped quotes or expression-control characters
  that suggest the user is trying to break out of a string literal.
- Sanitize: strip the offending control characters. Lossy by design;
  callers that need lossless input should bind variables instead.

Detection is the load-bearing surface for this vector. Sanitization is
a fallback for users running existing XPath strings through user input
who can't switch to bound parameters today.

Mirrors `arcis-node/src/sanitizers/xpath.ts` byte-for-byte on the
detection contract — same regex pair, same fast-path skip on the
control-char pre-check.
"""

import re

# XPath expression-control characters that an attacker uses to escape
# a string literal: single quote, double quote, comma (changes function
# arity), the union operator |, and parens (used in `) or (` toggles
# against XPath function calls).
_XPATH_INJECTION_CHARS = re.compile(r"['\"|,()]")

# Common operator-injection patterns: unescaped boolean injection
# (`' or '1'='1`), function tampering (`,`), and union (`|`).
_XPATH_INJECTION_PATTERN = re.compile(
    r"('\s*(or|and)\s*'|\"\s*(or|and)\s*\"|\)\s*(or|and)\s*\(|\|\s*/)",
    re.IGNORECASE,
)

# Sanitization strips the dangerous control characters. Lossy.
_XPATH_STRIP = re.compile(r"['\"|,]")


def detect_xpath_injection(value: str) -> bool:
    """Return True when the input looks like XPath injection.

    Conservative on purpose: triggers only when a control character is
    present AND combined with a boolean / function-arity / union
    pattern. Plain user names and emails (no quotes, no pipes) pass
    clean.

    Args:
        value: The string to check.

    Returns:
        True if XPath-injection-shaped patterns are present.

    Example:
        detect_xpath_injection("' or '1'='1")     # True
        detect_xpath_injection("john")             # False
        detect_xpath_injection("john@example.com")  # False
    """
    if not isinstance(value, str) or not value:
        return False
    # Fast path: skip the regex test entirely when no control chars exist.
    if not _XPATH_INJECTION_CHARS.search(value):
        return False
    return bool(_XPATH_INJECTION_PATTERN.search(value))


def sanitize_xpath(value: str) -> str:
    """Strip XPath expression-control characters.

    Lossy. `O'Brien` becomes `OBrien`. Use only when migrating legacy
    code that concatenates user input into XPath; new code should bind
    variables via the underlying XPath library instead.

    Args:
        value: The untrusted string to sanitize.

    Returns:
        The string with quote / pipe / comma characters removed.

    Example:
        sanitize_xpath("' or '1'='1")  # Returns: " or 1=1"
        sanitize_xpath("O'Brien")       # Returns: "OBrien"
    """
    if not isinstance(value, str):
        return str(value)
    return _XPATH_STRIP.sub("", value)
