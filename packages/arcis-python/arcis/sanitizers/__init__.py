"""
Arcis sanitizers package.

Provides the Sanitizer class and per-type convenience functions.
"""

from .sanitize import (
    Sanitizer,
    detect_xss,
    detect_sql,
    detect_nosql,
    detect_path_traversal,
    detect_command_injection,
    detect_prototype_pollution,
    scan_threats,
)
from .ssti import detect_ssti, sanitize_ssti
from .xxe import detect_xxe, sanitize_xxe
from .jsonp import sanitize_jsonp_callback, detect_jsonp_injection
from .headers import sanitize_header_value, sanitize_headers, detect_header_injection
from .pii import (
    scan_pii, detect_pii, redact_pii,
    scan_object_pii, redact_object_pii,
    PiiMatch, PiiObjectMatch,
)
from .encode import (
    encode_for_html,
    encode_for_attribute,
    encode_for_js,
    encode_for_url,
    encode_for_css,
)
from .ldap import sanitize_ldap_filter, sanitize_ldap_dn, detect_ldap_injection
from .prompt_injection import (
    detect_prompt_injection,
    sanitize_prompt_injection,
    PromptInjectionMatch,
    DetectPromptInjectionResult,
)
from typing import Dict


def sanitize_string(value: str, **options) -> str:
    """Sanitize a single string."""
    return Sanitizer(**options).sanitize_string(value)

def sanitize_dict(data: Dict, **options) -> Dict:
    """Sanitize a dictionary."""
    return Sanitizer(**options).sanitize_dict(data)

# Specific sanitization functions
def sanitize_xss(value: str) -> str:
    """Sanitize string for XSS only."""
    return Sanitizer(xss=True, sql=False, nosql=False, path=False).sanitize_string(value)

def sanitize_sql(value: str) -> str:
    """Sanitize string for SQL injection only."""
    return Sanitizer(xss=False, sql=True, nosql=False, path=False).sanitize_string(value)

def sanitize_nosql(data: dict) -> dict:
    """Sanitize dict for NoSQL injection only."""
    return Sanitizer(xss=False, sql=False, nosql=True, path=False).sanitize_dict(data)

def sanitize_path(value: str) -> str:
    """Sanitize string for path traversal only."""
    return Sanitizer(xss=False, sql=False, nosql=False, path=True).sanitize_string(value)

def sanitize_command(value: str) -> str:
    """Sanitize string for command injection."""
    return Sanitizer(xss=False, sql=False, nosql=False, path=False, command=True).sanitize_string(value)

__all__ = [
    "Sanitizer",
    "sanitize_string",
    "sanitize_dict",
    "sanitize_xss",
    "sanitize_sql",
    "sanitize_nosql",
    "sanitize_path",
    "sanitize_command",
    "detect_xss",
    "detect_sql",
    "detect_nosql",
    "detect_path_traversal",
    "detect_command_injection",
    "detect_prototype_pollution",
    "scan_threats",
    "sanitize_ssti",
    "detect_ssti",
    "sanitize_xxe",
    "detect_xxe",
    "sanitize_jsonp_callback",
    "detect_jsonp_injection",
    "sanitize_header_value",
    "sanitize_headers",
    "detect_header_injection",
    "scan_pii",
    "detect_pii",
    "redact_pii",
    "scan_object_pii",
    "redact_object_pii",
    "PiiMatch",
    "PiiObjectMatch",
    "encode_for_html",
    "encode_for_attribute",
    "encode_for_js",
    "encode_for_url",
    "encode_for_css",
    "detect_prompt_injection",
    "sanitize_prompt_injection",
    "PromptInjectionMatch",
    "DetectPromptInjectionResult",
]
