"""
Arcis Core - Constants and pattern loading

Pattern loading utilities and embedded fallback patterns.
"""

import json
from typing import Dict, Optional
from pathlib import Path


def _find_patterns_path() -> Optional[Path]:
    """Find patterns.json in development or installed locations."""
    # Development path: packages/arcis-python/arcis/core/constants.py -> packages/core/patterns.json
    dev_path = Path(__file__).parent.parent.parent.parent / "core" / "patterns.json"
    if dev_path.exists():
        return dev_path

    # Installed path: bundled in package data
    pkg_path = Path(__file__).parent.parent / "data" / "patterns.json"
    if pkg_path.exists():
        return pkg_path

    return None


def load_patterns() -> Dict:
    """Load security patterns from core package or embedded fallback."""
    patterns_path = _find_patterns_path()
    if patterns_path:
        try:
            with open(patterns_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    # Fallback to embedded patterns
    return get_embedded_patterns()

def get_embedded_patterns() -> Dict:
    """Fallback embedded patterns if core not available.

    Note: These patterns are used when patterns.json cannot be loaded
    (e.g., pip-installed packages). Keep in sync with patterns.json.

    IMPORTANT: This must match patterns.json exactly to ensure pip-installed
    packages have the same protection as development installations.
    """
    return {
        "patterns": {
            "xss": {
                "rules": [
                    # ReDoS-safe script tag pattern (avoid nested quantifiers)
                    {"pattern": r"<script[^>]*>[\s\S]*?</script>", "flags": "gi"},
                    {"pattern": r"javascript:", "flags": "gi"},
                    {"pattern": r"vbscript:", "flags": "gi"},
                    {"pattern": r"on\w+\s*=", "flags": "gi"},
                    {"pattern": r"<iframe", "flags": "gi"},
                    {"pattern": r"<object", "flags": "gi"},
                    {"pattern": r"<embed", "flags": "gi"},
                    {"pattern": r'(?:^|[\s"\'=])data:', "flags": "gi"},  # data: URIs only
                    {"pattern": r"%3Cscript", "flags": "gi"},  # URL-encoded <script
                    {"pattern": r"<svg[^>]*onload", "flags": "gi"},  # SVG with onload
                ],
                "encoding": {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
            },
            "sql_injection": {
                "rules": [
                    {"pattern": r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b", "flags": "gi"},
                    {"pattern": r"(--|/\*|\*/)", "flags": "g"},
                    {"pattern": r"(;|\|\||&&)", "flags": "g"},
                    {"pattern": r"\bOR\s+\d+\s*=\s*\d+", "flags": "gi"},
                    {"pattern": r'\bOR\s+[\'"][^\'\"]+[\'"\]\s*=\s*[\'"][^\'\"]+[\'"]', "flags": "gi"},  # OR 'a'='a'
                    {"pattern": r"\bAND\s+\d+\s*=\s*\d+", "flags": "gi"},
                    {"pattern": r'\bAND\s+[\'"][^\'\"]+[\'"\]\s*=\s*[\'"][^\'\"]+[\'"]', "flags": "gi"},  # AND 'a'='a'
                    # Time-based blind SQL injection
                    {"pattern": r"\bSLEEP\s*\(\s*\d+\s*\)", "flags": "gi"},
                    {"pattern": r"\bBENCHMARK\s*\(", "flags": "gi"},
                ]
            },
            "nosql_injection": {
                "dangerous_keys": ["$gt", "$gte", "$lt", "$lte", "$ne", "$eq", "$in", "$nin",
                                   "$and", "$or", "$not", "$exists", "$type", "$regex", "$where", "$expr"]
            },
            "command_injection": {
                "rules": [
                    {"pattern": r"[;&|`$()]", "flags": "g"},
                    {"pattern": r"\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php|node|powershell|cmd)\b", "flags": "gi"},
                    {"pattern": r"(>>|<<|>|<)\s*[/\w]", "flags": "g"},  # Shell redirection
                ]
            },
            "path_traversal": {
                "rules": [
                    {"pattern": r"\.\./", "flags": "g"},
                    {"pattern": r"\.\.\\", "flags": "g"},
                    {"pattern": r"%2e%2e", "flags": "gi"},
                    {"pattern": r"%252e", "flags": "gi"},
                    {"pattern": r"%00", "flags": "gi"},  # Null byte injection
                ]
            },
            "ldap_injection": {
                "rules": [
                    {"pattern": r"[()\\*]", "flags": "g"},  # LDAP special characters
                ]
            },
            "xml_injection": {
                "rules": [
                    {"pattern": r"<!DOCTYPE", "flags": "gi"},
                    {"pattern": r"<!ENTITY", "flags": "gi"},
                    {"pattern": r'SYSTEM\s+["\']', "flags": "gi"},
                ]
            },
            "prototype_pollution": {
                "dangerous_keys": ["__proto__", "constructor", "prototype",
                                   "__definegetter__", "__definesetter__",
                                   "__lookupgetter__", "__lookupsetter__"]
            }
        },
        "security_headers": {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "0",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
        "sensitive_keys": [
            "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "apiKey",
            "authorization", "auth", "credit_card", "creditcard", "cc", "ssn",
            "social_security", "private_key", "privateKey", "access_token",
            "accessToken", "refresh_token", "refreshToken", "bearer", "jwt",
            "session", "cookie", "x-api-key", "x-auth-token", "credentials"
        ]
    }


PATTERNS = load_patterns()

# Constants
DEFAULT_MAX_INPUT_SIZE = 1_000_000  # 1MB
MAX_RECURSION_DEPTH = 10
DEFAULT_MAX_REQUESTS = 100
DEFAULT_WINDOW_MS = 60_000
DEFAULT_RATE_LIMIT_MESSAGE = "Too many requests, please try again later."
DEFAULT_LOG_MAX_LENGTH = 10_000
HSTS_DEFAULT_MAX_AGE = 31_536_000  # 1 year in seconds
