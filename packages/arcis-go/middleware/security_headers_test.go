package middleware

import (
	"strings"
	"testing"

	"github.com/GagancM/arcis/core"
)

func TestSecurityHeaders_DefaultHeaders(t *testing.T) {
	config := core.DefaultConfig()
	headers := NewSecurityHeaders(config)
	h := headers.GetHeaders()

	required := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-XSS-Protection":      "1; mode=block",
	}

	for header, expected := range required {
		if h[header] != expected {
			t.Errorf("Expected %s: %s, got: %s", header, expected, h[header])
		}
	}

	if _, exists := h["Content-Security-Policy"]; !exists {
		t.Error("Content-Security-Policy should be set")
	}
	if hsts, exists := h["Strict-Transport-Security"]; !exists || !strings.Contains(hsts, "max-age=") {
		t.Error("Strict-Transport-Security should contain max-age=")
	}
}

func TestSecurityHeaders_CustomCSP(t *testing.T) {
	config := core.DefaultConfig()
	config.CSP = "default-src 'none'"
	headers := NewSecurityHeaders(config)

	h := headers.GetHeaders()
	if h["Content-Security-Policy"] != "default-src 'none'" {
		t.Errorf("Expected custom CSP, got: %s", h["Content-Security-Policy"])
	}
}

func TestSecurityHeaders_CacheControl(t *testing.T) {
	config := core.DefaultConfig()
	headers := NewSecurityHeaders(config)
	h := headers.GetHeaders()

	if h["Cache-Control"] == "" {
		t.Error("Cache-Control should be set by default")
	}
	if h["Pragma"] != "no-cache" {
		t.Error("Pragma should be no-cache")
	}
}
