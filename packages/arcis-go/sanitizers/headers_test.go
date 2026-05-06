package sanitizers

import "testing"

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"safe value unchanged", "application/json", "application/json"},
		{"strips CRLF", "value\r\nX-Injected: evil", "valueX-Injected: evil"},
		{"strips bare CR", "value\revil", "valueevil"},
		{"strips bare LF", "value\nevil", "valueevil"},
		{"strips null byte", "value\x00evil", "valueevil"},
		{"strips multiple", "a\r\nb\nc\rd\x00e", "abcde"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeHeaderValue(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeHeaderValue(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeHeaders(t *testing.T) {
	t.Run("sanitizes keys and values", func(t *testing.T) {
		headers := map[string]string{
			"X-Custom":     "safe",
			"X-Bad\r\n":    "value\r\ninjected",
			"Content-Type": "text/html",
		}
		result := SanitizeHeaders(headers)
		if result["X-Custom"] != "safe" {
			t.Error("Safe value should be unchanged")
		}
		if result["X-Bad"] != "valueinjected" {
			t.Errorf("Expected sanitized value, got key=%v", result)
		}
	})

	t.Run("nil input returns empty map", func(t *testing.T) {
		result := SanitizeHeaders(nil)
		if result == nil || len(result) != 0 {
			t.Error("Expected empty map for nil input")
		}
	})
}

func TestDetectHeaderInjection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"safe string", "application/json", false},
		{"CRLF detected", "value\r\nevil", true},
		{"bare LF detected", "value\nevil", true},
		{"bare CR detected", "value\revil", true},
		{"null byte detected", "value\x00evil", true},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectHeaderInjection(tt.input)
			if result != tt.expected {
				t.Errorf("DetectHeaderInjection(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
