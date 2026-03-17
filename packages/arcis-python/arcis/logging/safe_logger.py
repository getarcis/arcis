"""
Arcis Logging - SafeLogger

Safe logger that redacts sensitive information and prevents log injection.
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Set

from ..core.constants import PATTERNS, MAX_RECURSION_DEPTH, DEFAULT_LOG_MAX_LENGTH


class SafeLogger:
    """
    Safe logger that redacts sensitive information and prevents log injection.

    Example:
        logger = SafeLogger()
        logger.info("User login", {"email": "test@test.com", "password": "secret"})
        # Output: {"timestamp": "...", "level": "info", "message": "User login", "data": {"email": "test@test.com", "password": "[REDACTED]"}}
    """

    SENSITIVE_KEYS: Set[str] = set(k.lower() for k in PATTERNS.get("sensitive_keys", []))

    def __init__(
        self,
        name: str = "arcis",
        redact_keys: Optional[List[str]] = None,
        max_length: int = DEFAULT_LOG_MAX_LENGTH,
    ):
        self.logger = logging.getLogger(name)
        self.max_length = max_length

        if redact_keys:
            self.sensitive_keys = self.SENSITIVE_KEYS | set(k.lower() for k in redact_keys)
        else:
            self.sensitive_keys = self.SENSITIVE_KEYS

    def _redact(self, data: Any, depth: int = 0) -> Any:
        """Redact sensitive data."""
        if depth > MAX_RECURSION_DEPTH:
            return "[MAX_DEPTH]"

        if isinstance(data, str):
            # Remove control characters (log injection prevention)
            safe = re.sub(r'[\r\n\t]', ' ', data)
            safe = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', safe)
            if len(safe) > self.max_length:
                safe = safe[:self.max_length] + "...[TRUNCATED]"
            return safe

        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if str(key).lower() in self.sensitive_keys:
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self._redact(value, depth + 1)
            return result

        if isinstance(data, list):
            return [self._redact(item, depth + 1) for item in data]

        return data

    def _log(self, level: str, message: str, data: Optional[Dict] = None):
        """Internal log method."""
        # Early exit: skip redaction work if logger won't emit at this level
        log_level = getattr(logging, level.upper(), logging.INFO)
        if not self.logger.isEnabledFor(log_level):
            return

        import datetime
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": level,
            "message": self._redact(message),
        }
        if data is not None:
            entry["data"] = self._redact(data)

        log_line = json.dumps(entry)
        getattr(self.logger, level)(log_line)

    def info(self, message: str, data: Optional[Dict] = None):
        """Log info message with redacted data."""
        self._log("info", message, data)

    def warning(self, message: str, data: Optional[Dict] = None):
        """Log warning message with redacted data."""
        self._log("warning", message, data)

    def warn(self, message: str, data: Optional[Dict] = None):
        """Alias for warning."""
        self.warning(message, data)

    def error(self, message: str, data: Optional[Dict] = None):
        """Log error message with redacted data."""
        self._log("error", message, data)

    def debug(self, message: str, data: Optional[Dict] = None):
        """Log debug message with redacted data."""
        self._log("debug", message, data)
