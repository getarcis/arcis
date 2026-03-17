package validation

import (
	"strings"
	"testing"
)

func containsString(errors []string, substr string) bool {
	for _, e := range errors {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func TestValidator_RequiredField(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{})
	if err == nil {
		t.Error("Should fail when required field is missing")
	}
	if err != nil && !containsString(err.Errors, "required") {
		t.Errorf("Error should mention 'required', got: %v", err.Errors)
	}
}

func TestValidator_EmailInvalid(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"email": "invalid"})
	if err == nil {
		t.Error("Should fail for invalid email")
	}
}

func TestValidator_EmailValid(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	validated, err := validator.Validate(map[string]interface{}{"email": "test@example.com"})
	if err != nil {
		t.Errorf("Valid email should pass: %v", err)
	}
	if validated["email"] == nil {
		t.Error("Validated data should contain email")
	}
}

func TestValidator_StringLengthTooShort(t *testing.T) {
	minLen := float64(3)
	schema := ValidationSchema{
		"name": {Type: "string", Min: &minLen},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"name": "ab"})
	if err == nil {
		t.Error("Should fail when string is too short")
	}
}

func TestValidator_StringLengthTooLong(t *testing.T) {
	minLen := float64(3)
	maxLen := float64(10)
	schema := ValidationSchema{
		"name": {Type: "string", Min: &minLen, Max: &maxLen},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"name": "this is way too long"})
	if err == nil {
		t.Error("Should fail when string is too long")
	}
}

func TestValidator_NumberBelowMin(t *testing.T) {
	minVal := float64(0)
	schema := ValidationSchema{
		"age": {Type: "number", Min: &minVal},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"age": -5})
	if err == nil {
		t.Error("Should fail when number is below min")
	}
}

func TestValidator_EnumInvalid(t *testing.T) {
	schema := ValidationSchema{
		"role": {Type: "string", Enum: []string{"user", "admin"}},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"role": "superadmin"})
	if err == nil {
		t.Error("Should fail for invalid enum value")
	}
}

func TestValidator_EnumValid(t *testing.T) {
	schema := ValidationSchema{
		"role": {Type: "string", Enum: []string{"user", "admin"}},
	}
	validator := NewValidator(schema)

	validated, err := validator.Validate(map[string]interface{}{"role": "admin"})
	if err != nil {
		t.Errorf("Valid enum value should pass: %v", err)
	}
	if validated["role"] != "admin" {
		t.Error("Validated data should contain role")
	}
}

func TestValidator_MassAssignmentPrevention(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	validated, err := validator.Validate(map[string]interface{}{
		"email":   "test@test.com",
		"isAdmin": true,
		"role":    "admin",
	})
	if err != nil {
		t.Errorf("Should pass validation: %v", err)
	}

	if validated["email"] == nil {
		t.Error("email should be in validated output")
	}
	if _, exists := validated["isAdmin"]; exists {
		t.Error("isAdmin should NOT be in validated output")
	}
	if _, exists := validated["role"]; exists {
		t.Error("role should NOT be in validated output")
	}
}
