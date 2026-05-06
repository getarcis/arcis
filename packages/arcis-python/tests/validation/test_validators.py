"""
Validator tests — extracted from tests/test_core.py.
"""

from arcis.core import Validator


class TestValidator:
    """Test validation functionality."""

    def test_email_validation_invalid(self):
        """Invalid email should fail validation."""
        assert Validator.email("invalid") is False
        assert Validator.email("no-at-sign.com") is False

    def test_email_validation_valid(self):
        """Valid email should pass validation."""
        assert Validator.email("test@example.com") is True
        assert Validator.email("user.name@domain.co.uk") is True

    def test_url_validation(self):
        """URL validation should work correctly."""
        assert Validator.url("https://example.com") is True
        assert Validator.url("http://test.org/path") is True
        assert Validator.url("not-a-url") is False

    def test_uuid_validation(self):
        """UUID validation should work correctly."""
        assert Validator.uuid("550e8400-e29b-41d4-a716-446655440000") is True
        assert Validator.uuid("not-a-uuid") is False

    def test_length_validation(self):
        """String length validation should work."""
        assert Validator.length("ab", min_len=3) is False
        assert Validator.length("abc", min_len=3) is True
        assert Validator.length("toolong", max_len=5) is False
        assert Validator.length("short", max_len=10) is True

    def test_number_range_validation(self):
        """Number range validation should work."""
        assert Validator.number_range(-5, min_val=0) is False
        assert Validator.number_range(5, min_val=0) is True
        assert Validator.number_range(200, max_val=150) is False
        assert Validator.number_range(100, max_val=150) is True
