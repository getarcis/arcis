"""
Arcis Validation - Validators

Validator class and standalone validate_* convenience functions.
"""

import re
from typing import Optional

# ValidationError is in core.errors but re-exported from here for convenience
from ..core.errors import ValidationError  # noqa: F401


class Validator:
    """
    Input validator with common validation rules.

    Example:
        if not Validator.email(user_input):
            raise ValidationError(["Invalid email format"])
    """

    EMAIL_PATTERN = re.compile(r"^(?!\.)(?!.*\.\.)(?!.*\.@)[^\s@]+@[^\s@]+\.[^\s@]+$")
    URL_PATTERN = re.compile(r"^https?://[^\s/$.?#][^\s]*$")
    UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

    @classmethod
    def email(cls, value: str) -> bool:
        """Validate email format."""
        return bool(cls.EMAIL_PATTERN.match(value))

    @classmethod
    def url(cls, value: str) -> bool:
        """Validate URL format."""
        return bool(cls.URL_PATTERN.match(value))

    @classmethod
    def uuid(cls, value: str) -> bool:
        """Validate UUID format."""
        return bool(cls.UUID_PATTERN.match(value))

    @classmethod
    def length(cls, value: str, min_len: int = 0, max_len: Optional[int] = None) -> bool:
        """Validate string length."""
        if len(value) < min_len:
            return False
        if max_len is not None and len(value) > max_len:
            return False
        return True

    @classmethod
    def number_range(cls, value: float, min_val: Optional[float] = None, max_val: Optional[float] = None) -> bool:
        """Validate number range."""
        if min_val is not None and value < min_val:
            return False
        if max_val is not None and value > max_val:
            return False
        return True


def validate_email(value: str) -> bool:
    """Validate email format."""
    return Validator.email(value)

def validate_url(value: str) -> bool:
    """Validate URL format."""
    return Validator.url(value)

def validate_uuid(value: str) -> bool:
    """Validate UUID format."""
    return Validator.uuid(value)
