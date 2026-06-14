"""
Arcis Core package — re-exports everything that was in core.py for backward compatibility.

All existing ``from arcis.core import X`` statements continue to work unchanged.
"""

# Constants / pattern loading
from .constants import (
    _find_patterns_path,
    load_patterns,
    PATTERNS,
    DEFAULT_MAX_INPUT_SIZE,
    MAX_RECURSION_DEPTH,
)

# Error classes
from .errors import InputTooLargeError, ValidationError

# Shared types
from .types import RateLimitEntry

# Sanitizer
from ..sanitizers.sanitize import Sanitizer

# Stores
from ..stores.memory import InMemoryStore

# Rate limiting
from ..middleware.rate_limit import RateLimitExceeded, RateLimiter

# Security headers
from ..middleware.headers import SecurityHeaders

# Validators
from ..validation.validators import Validator
from ..validation.schema import SchemaValidator, create_validator

# Safe logger
from ..logging.safe_logger import SafeLogger

# Error handler
from ..middleware.error_handler import ErrorHandler, create_error_handler

# Main Arcis class
from ..middleware.main import Arcis

# Convenience functions
from ..sanitizers import sanitize_string, sanitize_dict
from ..validation.validators import validate_email, validate_url, validate_uuid

__all__ = [
    # Pattern loading
    "_find_patterns_path",
    "load_patterns",
    "PATTERNS",
    "DEFAULT_MAX_INPUT_SIZE",
    "MAX_RECURSION_DEPTH",
    # Errors
    "InputTooLargeError",
    "ValidationError",
    # Types
    "RateLimitEntry",
    # Core components
    "Sanitizer",
    "InMemoryStore",
    "RateLimitExceeded",
    "RateLimiter",
    "SecurityHeaders",
    "Validator",
    "SchemaValidator",
    "create_validator",
    "SafeLogger",
    "ErrorHandler",
    "create_error_handler",
    "Arcis",
    # Convenience functions
    "sanitize_string",
    "sanitize_dict",
    "validate_email",
    "validate_url",
    "validate_uuid",
]
