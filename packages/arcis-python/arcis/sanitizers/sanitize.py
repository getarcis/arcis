"""
Arcis Sanitizer

Input sanitizer that prevents XSS, SQL injection, NoSQL injection,
path traversal, and command injection.
"""

import re
import types
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.constants import PATTERNS, DEFAULT_MAX_INPUT_SIZE, MAX_RECURSION_DEPTH
from ..core.errors import InputTooLargeError


# ── Module-level compiled detectors ────────────────────────────────────
# Mirrors Node's per-vector detect* functions. These reuse the shared
# patterns.json contract so detection stays consistent with sanitization.

def _compile_rules(category: str) -> List[re.Pattern]:
    compiled: List[re.Pattern] = []
    cat = PATTERNS.get("patterns", {}).get(category, {})
    for rule in cat.get("rules", []):
        flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
        pattern_str = rule.get("pattern_safe") or rule.get("pattern")
        if pattern_str:
            compiled.append(re.compile(pattern_str, flags))
    return compiled


_XSS_DETECT = _compile_rules("xss")
_SQL_DETECT = _compile_rules("sql_injection")
_PATH_DETECT = _compile_rules("path_traversal")
_COMMAND_DETECT = _compile_rules("command_injection")
_NOSQL_DETECT = _compile_rules("nosql_injection")
_NOSQL_KEYS = {
    k.lower() for k in PATTERNS.get("patterns", {}).get("nosql_injection", {}).get("dangerous_keys", [])
}
_PROTO_KEYS = {
    k.lower() for k in PATTERNS.get("patterns", {}).get("prototype_pollution", {}).get("dangerous_keys", [])
} or {"__proto__", "constructor", "prototype", "__definegetter__", "__definesetter__", "__lookupgetter__", "__lookupsetter__"}


def _first_match(value: str, patterns: List[re.Pattern]) -> Optional[str]:
    for p in patterns:
        m = p.search(value)
        if m:
            return p.pattern
    return None


def detect_xss(value: str) -> bool:
    """Return True if `value` contains an XSS pattern."""
    if not isinstance(value, str):
        return False
    return _first_match(value, _XSS_DETECT) is not None


def detect_sql(value: str) -> bool:
    """Return True if `value` contains a SQL-injection pattern."""
    if not isinstance(value, str):
        return False
    return _first_match(value, _SQL_DETECT) is not None


def detect_path_traversal(value: str) -> bool:
    """Return True if `value` contains a path-traversal pattern."""
    if not isinstance(value, str):
        return False
    normalized = unicodedata.normalize('NFKC', value)
    return _first_match(normalized, _PATH_DETECT) is not None


def detect_command_injection(value: str) -> bool:
    """Return True if `value` contains shell metacharacters / cmd-injection."""
    if not isinstance(value, str):
        return False
    return _first_match(value, _COMMAND_DETECT) is not None


def detect_nosql(data: Any) -> bool:
    """Return True if `data` (str or dict) contains NoSQL operators or keys."""
    if isinstance(data, str):
        return _first_match(data, _NOSQL_DETECT) is not None
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and k.lower() in _NOSQL_KEYS:
                return True
            if detect_nosql(v):
                return True
        return False
    if isinstance(data, list):
        return any(detect_nosql(item) for item in data)
    return False


def detect_prototype_pollution(data: Any) -> bool:
    """Return True if `data` contains a prototype-pollution dangerous key."""
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and k.lower() in _PROTO_KEYS:
                return True
            if detect_prototype_pollution(v):
                return True
        return False
    if isinstance(data, list):
        return any(detect_prototype_pollution(item) for item in data)
    return False


def scan_threats(data: Any) -> Optional[Tuple[str, str, str]]:
    """Walk dict/list/str and return the first (vector, rule, matched_pattern)
    triple found, or None if nothing matched. Vector names match the dashboard
    taxonomy.

    Coverage: prototype, nosql (key-based, any nesting); xss, sql, path,
    command, ssti, xxe (string-based).

    NOT included — sink-context vectors that produce too many false positives
    when applied to arbitrary request strings:
        * ldap — every parens-containing string trips ``[*()\\\\\\x00]``
        * header — CRLF/null bytes are only attacks when reflected into a
                   response header, not when present in a request body

    These should be enforced at the call sites that pass user input to LDAP
    filters or response header writes (use ``detect_ldap_injection`` /
    ``detect_header_injection`` directly).
    """
    # Lazy imports avoid a circular dependency: ssti/xxe share core.constants
    # which is loaded by this module's top.
    from .ssti import detect_ssti
    from .xxe import detect_xxe

    # Key-based vectors first (apply at any nesting level)
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str):
                kl = k.lower()
                if kl in _PROTO_KEYS:
                    return ("prototype", "prototype/match", k)
                if kl in _NOSQL_KEYS:
                    return ("nosql", "nosql/match", k)
            inner = scan_threats(v)
            if inner is not None:
                return inner
        return None
    if isinstance(data, list):
        for item in data:
            inner = scan_threats(item)
            if inner is not None:
                return inner
        return None
    if not isinstance(data, str):
        return None

    # String vectors — order: most specific → least specific so a payload
    # carrying multiple signals classifies under the highest-severity bucket.
    m = _first_match(data, _XSS_DETECT)
    if m:
        return ("xss", "xss/match", m)
    if detect_ssti(data):
        return ("ssti", "ssti/match", data[:80])
    if detect_xxe(data):
        return ("xxe", "xxe/match", data[:80])
    m = _first_match(data, _SQL_DETECT)
    if m:
        return ("sql", "sql/match", m)
    normalized = unicodedata.normalize('NFKC', data)
    m = _first_match(normalized, _PATH_DETECT)
    if m:
        return ("path", "path/match", m)
    m = _first_match(data, _COMMAND_DETECT)
    if m:
        return ("command", "command/match", m)
    m = _first_match(data, _NOSQL_DETECT)
    if m:
        return ("nosql", "nosql/match", m)
    return None


class Sanitizer:
    """
    Input sanitizer that prevents XSS, SQL injection, NoSQL injection,
    path traversal, and command injection.

    Example:
        sanitizer = Sanitizer()
        safe_data = sanitizer(user_input)
    """

    def __init__(
        self,
        xss: bool = True,
        sql: bool = True,
        nosql: bool = True,
        path: bool = True,
        command: bool = True,
        max_input_size: int = DEFAULT_MAX_INPUT_SIZE,
        freeze: bool = False,
        html_encode: bool = False,
    ):
        self.xss = xss
        self.sql = sql
        self.nosql = nosql
        self.path = path
        self.command = command
        self.max_input_size = max_input_size
        self.freeze = freeze
        # Do NOT encode by default — this is a REST API middleware; encoding
        # here corrupts JSON data with HTML entities (&lt;, &amp;, etc.) that
        # consumers receive verbatim. Set html_encode=True for SSR/template contexts.
        self.html_encode = html_encode

        # Compile XSS patterns (prefer ReDoS-safe variants)
        self._xss_patterns = []
        if "xss" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["xss"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                # Prefer pattern_safe when available (ReDoS-safe variant)
                pattern_str = rule.get("pattern_safe") or rule.get("pattern")
                self._xss_patterns.append(re.compile(pattern_str, flags))

        # Compile SQL patterns
        self._sql_patterns = []
        if "sql_injection" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["sql_injection"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                self._sql_patterns.append(re.compile(rule["pattern"], flags))

        # NoSQL dangerous keys
        self._nosql_keys: Set[str] = set()
        if "nosql_injection" in PATTERNS.get("patterns", {}):
            self._nosql_keys = set(PATTERNS["patterns"]["nosql_injection"].get("dangerous_keys", []))

        # Prototype pollution dangerous keys
        self._proto_keys: Set[str] = set(
            PATTERNS.get("patterns", {}).get("prototype_pollution", {}).get("dangerous_keys", [])
        ) or {"__proto__", "constructor", "prototype", "__definegetter__", "__definesetter__", "__lookupgetter__", "__lookupsetter__"}

        # Path traversal patterns
        self._path_patterns = []
        if "path_traversal" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["path_traversal"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                self._path_patterns.append(re.compile(rule["pattern"], flags))

        # Command injection patterns (loaded from PATTERNS, like other categories)
        self._command_patterns = []
        if command and "command_injection" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["command_injection"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                self._command_patterns.append(re.compile(rule["pattern"], flags))

        # XSS encoding map
        self._xss_encoding = PATTERNS.get("patterns", {}).get("xss", {}).get("encoding", {
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"
        })

    def sanitize_string(self, value: str) -> str:
        """Sanitize a string value."""
        if not isinstance(value, str):
            raise TypeError(f"sanitize_string expects str, got {type(value).__name__}")

        # Input size limit to prevent DoS
        if len(value) > self.max_input_size:
            raise InputTooLargeError(len(value), self.max_input_size)

        result = value

        # XSS prevention - remove patterns FIRST (while detectable), then optionally encode
        if self.xss:
            # Remove dangerous patterns FIRST
            for pattern in self._xss_patterns:
                result = pattern.sub("", result)

            # HTML-encode only when explicitly requested (SSR/template context).
            # Do NOT encode by default — REST API middleware; encoding corrupts JSON
            # data with HTML entities (&lt;, &amp;, etc.) received verbatim by clients.
            if self.html_encode:
                if '&' in self._xss_encoding:
                    result = result.replace('&', self._xss_encoding['&'])
                for char, replacement in self._xss_encoding.items():
                    if char != '&':
                        result = result.replace(char, replacement)

        # SQL injection prevention
        if self.sql:
            for pattern in self._sql_patterns:
                result = pattern.sub(" ", result)

        # Path traversal prevention — loop until stable to prevent bypass via
        # nested sequences: "....//".replace("../","") → "../"
        if self.path:
            # SECURITY: Normalize Unicode to NFKC before path pattern matching.
            # Fullwidth dot U+FF0E normalizes to '.', preventing bypass of ../ detection.
            result = unicodedata.normalize('NFKC', result)
            prev = None
            while prev != result:
                prev = result
                for pattern in self._path_patterns:
                    result = pattern.sub("", result)

        # Command injection prevention
        if self.command:
            for pattern in self._command_patterns:
                result = pattern.sub(" ", result)

        return result

    def sanitize_dict(self, data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """Sanitize a dictionary, including nested structures."""
        if depth > MAX_RECURSION_DEPTH:
            return data

        if not isinstance(data, dict):
            if isinstance(data, str):
                return self.sanitize_string(data)
            elif isinstance(data, list):
                return [self.sanitize_dict(item, depth + 1) for item in data]
            return data

        result = {}
        for key, value in data.items():
            # Prototype pollution prevention - always block dangerous keys
            if key.lower() in self._proto_keys:
                continue

            # NoSQL injection prevention - skip dangerous keys
            if self.nosql and key.lower() in self._nosql_keys:
                continue

            # Sanitize the key
            sanitized_key = self.sanitize_string(key) if isinstance(key, str) else key

            # Recursively sanitize value
            if isinstance(value, dict):
                result[sanitized_key] = self.sanitize_dict(value, depth + 1)
            elif isinstance(value, list):
                result[sanitized_key] = [self.sanitize_dict(item, depth + 1) for item in value]
            elif isinstance(value, str):
                result[sanitized_key] = self.sanitize_string(value)
            else:
                result[sanitized_key] = value

        if self.freeze and depth == 0:
            return types.MappingProxyType(result)
        return result

    def __call__(self, data: Any) -> Any:
        """Make sanitizer callable."""
        if isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, str):
            return self.sanitize_string(data)
        elif isinstance(data, list):
            return [self(item) for item in data]
        return data
