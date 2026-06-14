"""
Arcis validation package.
"""

from .validators import Validator, ValidationError, validate_email, validate_url, validate_uuid
from .schema import SchemaValidator, create_validator
from .url import validate_url_ssrf, is_url_safe, ValidateUrlOptions, ValidateUrlResult
from .redirect import validate_redirect, is_redirect_safe, ValidateRedirectOptions, ValidateRedirectResult
from .host_header import validate_host, is_host_allowed, ValidateHostResult
from .file import validate_file, sanitize_filename, is_dangerous_extension, ValidateFileResult
from .email import validate_email_address, verify_email_mx, verify_email_mx_async, is_valid_email_syntax, EmailValidationResult

__all__ = [
    "Validator",
    "ValidationError",
    "validate_email",
    "validate_url",
    "validate_uuid",
    "SchemaValidator",
    "create_validator",
    "validate_url_ssrf",
    "is_url_safe",
    "ValidateUrlOptions",
    "ValidateUrlResult",
    "validate_redirect",
    "is_redirect_safe",
    "ValidateRedirectOptions",
    "ValidateRedirectResult",
    "validate_host",
    "is_host_allowed",
    "ValidateHostResult",
    "validate_file",
    "sanitize_filename",
    "is_dangerous_extension",
    "ValidateFileResult",
    "validate_email_address",
    "verify_email_mx",
    "verify_email_mx_async",
    "is_valid_email_syntax",
    "EmailValidationResult",
]
