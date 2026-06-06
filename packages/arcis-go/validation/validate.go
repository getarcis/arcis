package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/getarcis/arcis/v2/sanitizers"
)

// Validation patterns
var (
	emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	urlPattern   = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	uuidPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// FieldType represents the type of a field for validation.
type FieldType string

const (
	TypeString  FieldType = "string"
	TypeNumber  FieldType = "number"
	TypeBoolean FieldType = "boolean"
	TypeEmail   FieldType = "email"
	TypeURL     FieldType = "url"
	TypeUUID    FieldType = "uuid"
	TypeArray   FieldType = "array"
	TypeObject  FieldType = "object"
)

// FieldRule defines validation rules for a single field.
type FieldRule struct {
	Type     FieldType
	Required bool
	Min      *float64
	Max      *float64
	Pattern  *regexp.Regexp
	Enum     []string
	Sanitize bool
	Custom   func(value interface{}) (bool, string)
}

// ValidationSchema defines validation rules for multiple fields.
type ValidationSchema map[string]FieldRule

// ValidationError represents a validation error.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Errors, ", ")
}

// Validator validates request data against a schema.
type Validator struct {
	schema    ValidationSchema
	sanitizer *sanitizers.Sanitizer
}

// NewValidator creates a new Validator with the given schema.
func NewValidator(schema ValidationSchema) *Validator {
	return &Validator{
		schema:    schema,
		sanitizer: sanitizers.NewSanitizerWithOptions(true, true, true, true, true),
	}
}

// Validate validates data against the schema.
// Returns validated data (only fields in schema) and any errors.
func (v *Validator) Validate(data map[string]interface{}) (map[string]interface{}, *ValidationError) {
	errors := []string{}
	validated := make(map[string]interface{})

	for field, rules := range v.schema {
		value, exists := data[field]

		if rules.Required && (!exists || value == nil || value == "") {
			errors = append(errors, fmt.Sprintf("%s is required", field))
			continue
		}

		if !exists || value == nil {
			continue
		}

		typedValue := value
		isValid := true

		switch rules.Type {
		case TypeString:
			str, ok := value.(string)
			if !ok {
				errors = append(errors, fmt.Sprintf("%s must be a string", field))
				isValid = false
			} else {
				if rules.Min != nil && float64(len(str)) < *rules.Min {
					errors = append(errors, fmt.Sprintf("%s must be at least %.0f characters", field, *rules.Min))
					isValid = false
				}
				if rules.Max != nil && float64(len(str)) > *rules.Max {
					errors = append(errors, fmt.Sprintf("%s must be at most %.0f characters", field, *rules.Max))
					isValid = false
				}
				if rules.Pattern != nil && !rules.Pattern.MatchString(str) {
					errors = append(errors, fmt.Sprintf("%s format is invalid", field))
					isValid = false
				}
				if isValid && (rules.Sanitize || rules.Type == TypeString) {
					typedValue = v.sanitizer.SanitizeString(str)
				}
			}

		case TypeNumber:
			var num float64
			switch n := value.(type) {
			case float64:
				num = n
			case float32:
				num = float64(n)
			case int:
				num = float64(n)
			case int64:
				num = float64(n)
			case string:
				var err error
				num, err = strconv.ParseFloat(n, 64)
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s must be a number", field))
					isValid = false
				}
			default:
				errors = append(errors, fmt.Sprintf("%s must be a number", field))
				isValid = false
			}
			if isValid {
				if rules.Min != nil && num < *rules.Min {
					errors = append(errors, fmt.Sprintf("%s must be at least %.0f", field, *rules.Min))
					isValid = false
				}
				if rules.Max != nil && num > *rules.Max {
					errors = append(errors, fmt.Sprintf("%s must be at most %.0f", field, *rules.Max))
					isValid = false
				}
				typedValue = num
			}

		case TypeBoolean:
			switch b := value.(type) {
			case bool:
				typedValue = b
			case string:
				if b == "true" || b == "1" {
					typedValue = true
				} else if b == "false" || b == "0" {
					typedValue = false
				} else {
					errors = append(errors, fmt.Sprintf("%s must be a boolean", field))
					isValid = false
				}
			case int:
				typedValue = b != 0
			default:
				errors = append(errors, fmt.Sprintf("%s must be a boolean", field))
				isValid = false
			}

		case TypeEmail:
			str, ok := value.(string)
			if !ok || !emailPattern.MatchString(str) {
				errors = append(errors, fmt.Sprintf("%s must be a valid email", field))
				isValid = false
			} else {
				typedValue = v.sanitizer.SanitizeString(strings.ToLower(strings.TrimSpace(str)))
			}

		case TypeURL:
			str, ok := value.(string)
			if !ok || !urlPattern.MatchString(str) {
				errors = append(errors, fmt.Sprintf("%s must be a valid URL", field))
				isValid = false
			} else {
				typedValue = v.sanitizer.SanitizeString(str)
			}

		case TypeUUID:
			str, ok := value.(string)
			if !ok || !uuidPattern.MatchString(str) {
				errors = append(errors, fmt.Sprintf("%s must be a valid UUID", field))
				isValid = false
			}

		case TypeArray:
			arr, ok := value.([]interface{})
			if !ok {
				errors = append(errors, fmt.Sprintf("%s must be an array", field))
				isValid = false
			} else {
				if rules.Min != nil && float64(len(arr)) < *rules.Min {
					errors = append(errors, fmt.Sprintf("%s must have at least %.0f items", field, *rules.Min))
					isValid = false
				}
				if rules.Max != nil && float64(len(arr)) > *rules.Max {
					errors = append(errors, fmt.Sprintf("%s must have at most %.0f items", field, *rules.Max))
					isValid = false
				}
			}

		case TypeObject:
			_, ok := value.(map[string]interface{})
			if !ok {
				errors = append(errors, fmt.Sprintf("%s must be an object", field))
				isValid = false
			}
		}

		// Enum validation
		if isValid && len(rules.Enum) > 0 {
			found := false
			strVal := fmt.Sprintf("%v", typedValue)
			for _, e := range rules.Enum {
				if strVal == e {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, fmt.Sprintf("%s must be one of: %s", field, strings.Join(rules.Enum, ", ")))
				isValid = false
			}
		}

		// Custom validation
		if isValid && rules.Custom != nil {
			ok, msg := rules.Custom(typedValue)
			if !ok {
				if msg == "" {
					msg = fmt.Sprintf("%s is invalid", field)
				}
				errors = append(errors, msg)
				isValid = false
			}
		}

		if isValid {
			validated[field] = typedValue
		}
	}

	if len(errors) > 0 {
		return nil, &ValidationError{Errors: errors}
	}

	return validated, nil
}

// ValidateHandler creates middleware that validates request body.
// Only fields in the schema are passed to the handler (mass assignment prevention).
func ValidateHandler(schema ValidationSchema, next http.Handler) http.Handler {
	validator := NewValidator(schema)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"Failed to read request body"},
			})
			return
		}

		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"Invalid JSON"},
			})
			return
		}

		validated, validationErr := validator.Validate(data)
		if validationErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": validationErr.Errors,
			})
			return
		}

		ctx := context.WithValue(r.Context(), validatedBodyKey, validated)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

const validatedBodyKey contextKey = "arcis_validated_body"

// GetValidatedBody retrieves the validated body from request context.
func GetValidatedBody(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(validatedBodyKey); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

// Float is a helper for creating FieldRule with Min/Max.
func Float(v float64) *float64 {
	return &v
}
