package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestErrorHandler_HidesDetailsInProduction(t *testing.T) {
	eh := NewErrorHandler(false)
	rec := httptest.NewRecorder()
	err := &testError{msg: "Database connection failed"}

	eh.Handle(rec, err, http.StatusInternalServerError)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if body["error"] != "Internal Server Error" {
		t.Error("Should show generic error in production")
	}
	if _, exists := body["details"]; exists {
		t.Error("Should not expose details in production")
	}
}

func TestErrorHandler_ShowsDetailsInDev(t *testing.T) {
	eh := NewErrorHandler(true)
	rec := httptest.NewRecorder()
	err := &testError{msg: "Something broke"}

	eh.Handle(rec, err, http.StatusInternalServerError)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if body["details"] != "Something broke" {
		t.Error("Should show details in dev mode")
	}
}

func TestContainsSensitiveInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"SQL error", "SQLSTATE[42S02]: table not found", true},
		{"MongoDB error", "MongoError: connection refused", true},
		{"Redis error", "WRONGTYPE operation against key", true},
		{"connection string", "postgres://user:pass@host/db", true},
		{"internal IP", "Connection to 10.0.0.5 refused", true},
		{"stack trace", "at handler.go:42", true},
		{"safe message", "Invalid email format", false},
		{"generic error", "Something went wrong", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsSensitiveInfo(tt.input)
			if result != tt.expected {
				t.Errorf("ContainsSensitiveInfo(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrorHandler_ScrubsSensitiveIn4xx(t *testing.T) {
	eh := NewErrorHandler(false)
	rec := httptest.NewRecorder()
	err := &testError{msg: "Failed: SQLSTATE[42S02] table missing"}

	eh.Handle(rec, err, http.StatusBadRequest)

	var body map[string]interface{}
	if parseErr := json.Unmarshal(rec.Body.Bytes(), &body); parseErr != nil {
		t.Fatalf("Failed to parse response: %v", parseErr)
	}
	if body["error"] != "Internal Server Error" {
		t.Errorf("Should scrub sensitive 4xx errors in production, got: %v", body["error"])
	}
}
