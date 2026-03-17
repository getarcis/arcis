package arcis

import (
	"strings"
	"testing"
)

func TestSafeLogger_RedactsSensitiveKeys(t *testing.T) {
	logger := NewSafeLogger()

	data := map[string]interface{}{
		"email":    "test@test.com",
		"password": "secret123",
	}
	redacted := logger.Redact(data)

	if redacted["password"] != "[REDACTED]" {
		t.Error("Password should be redacted")
	}
	if redacted["email"] != "test@test.com" {
		t.Error("Email should not be redacted")
	}
}

func TestSafeLogger_RedactsMultipleKeys(t *testing.T) {
	logger := NewSafeLogger()

	data := map[string]interface{}{
		"user":  "john",
		"token": "abc123",
	}
	redacted := logger.Redact(data)

	if redacted["token"] != "[REDACTED]" {
		t.Error("Token should be redacted")
	}
	if redacted["user"] != "john" {
		t.Error("User should not be redacted")
	}
}

func TestSafeLogger_RemovesLogInjection(t *testing.T) {
	logger := NewSafeLogger()

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{"removes newlines", "User: attacker\nAdmin logged in: true", "\n"},
		{"removes carriage returns", "Normal log\r\nFake entry", "\r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logger.RedactString(tt.input)
			if strings.Contains(result, tt.notContains) {
				t.Errorf("Result should not contain %q", tt.notContains)
			}
		})
	}
}

func TestSafeLogger_Truncates(t *testing.T) {
	logger := NewSafeLoggerWithKeys(nil, 50)

	longMessage := strings.Repeat("a", 100)
	truncated := logger.RedactString(longMessage)

	if len(truncated) >= 100 {
		t.Error("Message should be truncated")
	}
	if !strings.Contains(truncated, "[TRUNCATED]") {
		t.Error("Message should contain [TRUNCATED] marker")
	}
}
