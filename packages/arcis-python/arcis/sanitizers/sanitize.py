"""
Arcis Sanitizer

Input sanitizer that prevents XSS, SQL injection, NoSQL injection,
path traversal, and command injection.
"""

import re
import types
from typing import Any, Dict, List, Set

from ..core.constants import PATTERNS, DEFAULT_MAX_INPUT_SIZE, MAX_RECURSION_DEPTH
from ..core.errors import InputTooLargeError


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
    ):
        self.xss = xss
        self.sql = sql
        self.nosql = nosql
        self.path = path
        self.command = command
        self.max_input_size = max_input_size
        self.freeze = freeze

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

        # XSS prevention - remove patterns FIRST (while detectable), then encode
        if self.xss:
            # Remove dangerous patterns FIRST
            for pattern in self._xss_patterns:
                result = pattern.sub("", result)

            # THEN encode remaining content (& first to avoid double-encoding)
            if '&' in self._xss_encoding:
                result = result.replace('&', self._xss_encoding['&'])
            for char, replacement in self._xss_encoding.items():
                if char != '&':
                    result = result.replace(char, replacement)

        # SQL injection prevention
        if self.sql:
            for pattern in self._sql_patterns:
                result = pattern.sub(" ", result)

        # Path traversal prevention
        if self.path:
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
