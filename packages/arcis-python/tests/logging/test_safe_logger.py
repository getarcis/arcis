"""
SafeLogger tests — extracted from tests/test_core.py.
"""

from arcis.core import SafeLogger


class TestSafeLogger:
    """Test safe logging functionality."""

    def test_redacts_sensitive_keys(self):
        """Should redact password, token, apikey, etc."""
        logger = SafeLogger()

        data = {"email": "test@test.com", "password": "secret123"}
        redacted = logger._redact(data)

        assert redacted["password"] == "[REDACTED]"
        assert redacted["email"] == "test@test.com"

    def test_redacts_multiple_sensitive_keys(self):
        """Should redact multiple sensitive fields."""
        logger = SafeLogger()

        data = {"user": "john", "token": "abc123", "apiKey": "key123"}
        redacted = logger._redact(data)

        assert redacted["token"] == "[REDACTED]"
        assert redacted["user"] == "john"

    def test_removes_log_injection(self):
        """Should remove newlines and control characters."""
        logger = SafeLogger()

        message = "User: attacker\nAdmin logged in: true"
        safe = logger._redact(message)

        assert '\n' not in safe

    def test_removes_carriage_return(self):
        """Should remove carriage returns."""
        logger = SafeLogger()

        message = "Normal log\r\nFake entry"
        safe = logger._redact(message)

        assert '\r' not in safe
        assert '\n' not in safe

    def test_truncates_long_messages(self):
        """Should truncate messages exceeding max length."""
        logger = SafeLogger(max_length=50)

        long_message = "a" * 100
        truncated = logger._redact(long_message)

        assert len(truncated) < 100
        assert "[TRUNCATED]" in truncated
