"""
SchemaValidator tests — extracted from tests/test_core.py.
"""

from arcis.core import SchemaValidator


class TestSchemaValidator:
    """Test SchemaValidator functionality aligned with TEST_VECTORS.json."""

    def test_required_field_missing(self):
        """TEST_VECTORS: required field missing should return error."""
        schema = {"email": {"type": "email", "required": True}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({})

        assert len(errors) > 0
        assert any("email" in e and "required" in e for e in errors)

    def test_email_validation_invalid(self):
        """TEST_VECTORS: invalid email should fail validation."""
        schema = {"email": {"type": "email", "required": True}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"email": "invalid"})

        assert len(errors) > 0
        assert any("email" in e.lower() for e in errors)

    def test_email_validation_valid(self):
        """TEST_VECTORS: valid email should pass validation."""
        schema = {"email": {"type": "email", "required": True}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"email": "test@example.com"})

        assert len(errors) == 0
        assert "email" in validated

    def test_string_length_too_short(self):
        """TEST_VECTORS: string shorter than min should fail."""
        schema = {"name": {"type": "string", "min": 3, "max": 10}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"name": "ab"})

        assert len(errors) > 0
        assert any("at least 3" in e for e in errors)

    def test_string_length_too_long(self):
        """TEST_VECTORS: string longer than max should fail."""
        schema = {"name": {"type": "string", "min": 3, "max": 10}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"name": "this is way too long"})

        assert len(errors) > 0
        assert any("at most 10" in e for e in errors)

    def test_number_range_below_min(self):
        """TEST_VECTORS: number below min should fail."""
        schema = {"age": {"type": "number", "min": 0, "max": 150}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"age": -5})

        assert len(errors) > 0
        assert any("at least 0" in e for e in errors)

    def test_number_range_above_max(self):
        """TEST_VECTORS: number above max should fail."""
        schema = {"age": {"type": "number", "min": 0, "max": 150}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"age": 200})

        assert len(errors) > 0
        assert any("at most 150" in e for e in errors)

    def test_enum_validation_invalid(self):
        """TEST_VECTORS: value not in enum should fail."""
        schema = {"role": {"type": "string", "enum": ["user", "admin"]}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"role": "superadmin"})

        assert len(errors) > 0
        assert any("one of" in e for e in errors)

    def test_enum_validation_valid(self):
        """TEST_VECTORS: value in enum should pass."""
        schema = {"role": {"type": "string", "enum": ["user", "admin"]}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({"role": "admin"})

        assert len(errors) == 0
        assert validated["role"] == "admin"

    def test_mass_assignment_prevention(self):
        """TEST_VECTORS: fields not in schema should be stripped."""
        schema = {"email": {"type": "email", "required": True}}
        validator = SchemaValidator(schema)
        validated, errors = validator.validate({
            "email": "test@test.com",
            "isAdmin": True,
            "role": "admin",
        })

        assert len(errors) == 0
        assert "email" in validated
        assert "isAdmin" not in validated
        assert "role" not in validated
