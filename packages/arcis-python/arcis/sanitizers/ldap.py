"""
LDAP injection prevention.

LDAP special characters in filter context: * ( ) \\ NUL  (RFC 4515)
LDAP special characters in DN context:     , + < > ; " = / \\ NUL  (RFC 4514)

Sanitization escapes rather than strips — preserves the original value
while making it safe to embed in LDAP queries.
"""

import re

# Detection: unescaped LDAP filter special chars
_LDAP_DETECT = re.compile(r'[*()\\\x00]')

# Detection: OR/AND bypass and wildcard abuse patterns
_LDAP_INJECTION = re.compile(r'\)\s*\(|\*\s*\)\s*\(')

# Filter chars per RFC 4515
_FILTER_CHARS = re.compile(r'[*()\\\x00]')

# DN chars per RFC 4514 (superset)
_DN_CHARS = re.compile(r'[,+<>;"=/\\\x00]')


def _escape_char(char: str) -> str:
    return '\\' + format(ord(char), '02x')


def sanitize_ldap_filter(value: str) -> str:
    """
    Sanitize a string for safe use in LDAP filter expressions.
    Escapes * ( ) \\ and NUL per RFC 4515.

    Args:
        value: The untrusted string to sanitize.

    Returns:
        The escaped string safe for use in LDAP filter expressions.

    Example:
        sanitize_ldap_filter("user*(admin)")
        # Returns: "user\\2a\\28admin\\29"
    """
    if not isinstance(value, str):
        return str(value)
    return _FILTER_CHARS.sub(lambda m: _escape_char(m.group()), value)


def sanitize_ldap_dn(value: str) -> str:
    """
    Sanitize a string for safe use in LDAP Distinguished Names (DN).
    Escapes , + < > ; " = / \\ and NUL per RFC 4514.

    Args:
        value: The untrusted string to sanitize.

    Returns:
        The escaped string safe for use in LDAP DN context.

    Example:
        sanitize_ldap_dn("cn=admin,dc=example")
        # Returns: "cn\\3dadmin\\2cdc\\3dexample"
    """
    if not isinstance(value, str):
        return str(value)
    return _DN_CHARS.sub(lambda m: _escape_char(m.group()), value)


def detect_ldap_injection(value: str) -> bool:
    """
    Detect potential LDAP injection patterns in a string.
    Does not sanitize — use sanitize_ldap_filter() or sanitize_ldap_dn() for that.

    Args:
        value: The string to check.

    Returns:
        True if LDAP injection patterns detected.

    Example:
        detect_ldap_injection("*)(uid=*))(|(uid=*")  # True
        detect_ldap_injection("john")                # False
    """
    if not isinstance(value, str):
        return False
    return bool(_LDAP_DETECT.search(value) or _LDAP_INJECTION.search(value))


def detect_ldap_injection_strict(value: str) -> bool:
    """
    Strict LDAP injection check, safe for request-boundary scanning.

    Uses only the attack-specific filter-break shapes ')(' and '*)(' that
    don't false-positive on legitimate user input containing parens.
    Use this from scan_threats / request-boundary scanners.

    The looser detect_ldap_injection() also checks for any LDAP special
    character ([*()\\\\\\x00]); that's safe to use when you KNOW the value
    is heading into an LDAP filter context, but not at the request
    boundary where any parenthesised string would trip it.

    Args:
        value: The string to check.

    Returns:
        True only when an LDAP filter-break pattern is present.

    Example:
        detect_ldap_injection_strict("*)(uid=*))(|(uid=*")   # True
        detect_ldap_injection_strict("john")                  # False
        detect_ldap_injection_strict("call me (when you can)")  # False
    """
    if not isinstance(value, str):
        return False
    return bool(_LDAP_INJECTION.search(value))
