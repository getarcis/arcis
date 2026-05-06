"""
Arcis Validation - Schema Validator

SchemaValidator and create_validator factory function.
"""

import re
from typing import Any, Dict, List

from ..sanitizers.sanitize import Sanitizer
from .validators import Validator


class SchemaValidator:
    """
    Schema-based validator with mass assignment prevention.

    Example:
        schema = {
            'email': {'type': 'email', 'required': True},
            'age': {'type': 'number', 'min': 0, 'max': 150},
            'role': {'type': 'string', 'enum': ['user', 'admin']}
        }
        validator = SchemaValidator(schema)
        validated_data, errors = validator.validate(request_data)
    """

    def __init__(self, schema: Dict[str, Dict[str, Any]], sanitize: bool = True):
        self.schema = schema
        self.sanitizer = Sanitizer() if sanitize else None

    def validate(self, data: Dict[str, Any]) -> tuple:
        """
        Validate data against schema.
        Returns (validated_data, errors) tuple.
        Only fields in schema are returned (mass assignment prevention).
        """
        errors: List[str] = []
        validated: Dict[str, Any] = {}

        for field, rules in self.schema.items():
            value = data.get(field)

            # Required check
            if rules.get('required') and (value is None or value == ''):
                errors.append(f"{field} is required")
                continue

            # Skip optional empty fields
            if value is None:
                continue

            typed_value = value
            is_valid = True
            field_type = rules.get('type', 'string')

            # Type validation and coercion
            if field_type == 'string':
                if not isinstance(value, str):
                    errors.append(f"{field} must be a string")
                    is_valid = False
                else:
                    min_len = rules.get('min')
                    max_len = rules.get('max')
                    if min_len is not None and len(value) < min_len:
                        errors.append(f"{field} must be at least {min_len} characters")
                        is_valid = False
                    if max_len is not None and len(value) > max_len:
                        errors.append(f"{field} must be at most {max_len} characters")
                        is_valid = False
                    pattern = rules.get('pattern')
                    if pattern and not re.match(pattern, value):
                        errors.append(f"{field} format is invalid")
                        is_valid = False
                    if is_valid and self.sanitizer and rules.get('sanitize', True):
                        typed_value = self.sanitizer.sanitize_string(value)

            elif field_type == 'number':
                try:
                    typed_value = float(value) if '.' in str(value) else int(value)
                except (ValueError, TypeError):
                    errors.append(f"{field} must be a number")
                    is_valid = False
                else:
                    min_val = rules.get('min')
                    max_val = rules.get('max')
                    if min_val is not None and typed_value < min_val:
                        errors.append(f"{field} must be at least {min_val}")
                        is_valid = False
                    if max_val is not None and typed_value > max_val:
                        errors.append(f"{field} must be at most {max_val}")
                        is_valid = False

            elif field_type == 'boolean':
                if value in (True, 'true', '1', 1):
                    typed_value = True
                elif value in (False, 'false', '0', 0):
                    typed_value = False
                else:
                    errors.append(f"{field} must be a boolean")
                    is_valid = False

            elif field_type == 'email':
                if not Validator.email(str(value)):
                    errors.append(f"{field} must be a valid email")
                    is_valid = False
                else:
                    typed_value = str(value).lower().strip()
                    if self.sanitizer:
                        typed_value = self.sanitizer.sanitize_string(typed_value)

            elif field_type == 'url':
                if not Validator.url(str(value)):
                    errors.append(f"{field} must be a valid URL")
                    is_valid = False
                elif self.sanitizer:
                    typed_value = self.sanitizer.sanitize_string(str(value))

            elif field_type == 'uuid':
                if not Validator.uuid(str(value)):
                    errors.append(f"{field} must be a valid UUID")
                    is_valid = False

            elif field_type == 'array':
                if not isinstance(value, list):
                    errors.append(f"{field} must be an array")
                    is_valid = False
                else:
                    min_len = rules.get('min')
                    max_len = rules.get('max')
                    if min_len is not None and len(value) < min_len:
                        errors.append(f"{field} must have at least {min_len} items")
                        is_valid = False
                    if max_len is not None and len(value) > max_len:
                        errors.append(f"{field} must have at most {max_len} items")
                        is_valid = False

            elif field_type == 'object':
                if not isinstance(value, dict):
                    errors.append(f"{field} must be an object")
                    is_valid = False

            # Enum validation
            enum_values = rules.get('enum')
            if is_valid and enum_values and typed_value not in enum_values:
                errors.append(f"{field} must be one of: {', '.join(map(str, enum_values))}")
                is_valid = False

            # Custom validation function
            custom = rules.get('custom')
            if is_valid and custom and callable(custom):
                custom_result = custom(typed_value)
                if custom_result is not True:
                    error_msg = custom_result if isinstance(custom_result, str) else f"{field} is invalid"
                    errors.append(error_msg)
                    is_valid = False

            if is_valid:
                validated[field] = typed_value

        return validated, errors


def create_validator(schema: Dict[str, Dict[str, Any]], sanitize: bool = True):
    """
    Create a schema validator function.

    Example:
        validate_user = create_validator({
            'email': {'type': 'email', 'required': True},
            'name': {'type': 'string', 'min': 2, 'max': 50},
        })
        validated, errors = validate_user(request.json)
    """
    validator = SchemaValidator(schema, sanitize)
    return validator.validate
