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
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "0",
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

func TestSecurityHeaders_CrossOriginHeaders(t *testing.T) {
	config := core.DefaultConfig()
	headers := NewSecurityHeaders(config)
	h := headers.GetHeaders()

	expected := map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Origin-Agent-Cluster":         "?1",
		"X-DNS-Prefetch-Control":       "off",
	}

	for header, value := range expected {
		if h[header] != value {
			t.Errorf("Expected %s: %s, got: %s", header, value, h[header])
		}
	}
}

func TestSecurityHeaders_CrossOriginDisabled(t *testing.T) {
	config := core.DefaultConfig()
	config.CrossOriginOpenerPolicy = ""
	config.CrossOriginResourcePolicy = ""
	config.CrossOriginEmbedderPolicy = ""
	config.OriginAgentCluster = false
	config.DNSPrefetchControl = false
	headers := NewSecurityHeaders(config)
	h := headers.GetHeaders()

	absent := []string{
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Cross-Origin-Embedder-Policy",
		"Origin-Agent-Cluster",
		"X-DNS-Prefetch-Control",
	}

	for _, header := range absent {
		if _, exists := h[header]; exists {
			t.Errorf("%s should not be set when disabled", header)
		}
	}
}

func TestSecurityHeaders_CrossOriginCustomValues(t *testing.T) {
	config := core.DefaultConfig()
	config.CrossOriginOpenerPolicy = "same-origin-allow-popups"
	config.CrossOriginResourcePolicy = "cross-origin"
	config.CrossOriginEmbedderPolicy = "credentialless"
	headers := NewSecurityHeaders(config)
	h := headers.GetHeaders()

	if h["Cross-Origin-Opener-Policy"] != "same-origin-allow-popups" {
		t.Errorf("Expected custom COOP, got: %s", h["Cross-Origin-Opener-Policy"])
	}
	if h["Cross-Origin-Resource-Policy"] != "cross-origin" {
		t.Errorf("Expected custom CORP, got: %s", h["Cross-Origin-Resource-Policy"])
	}
	if h["Cross-Origin-Embedder-Policy"] != "credentialless" {
		t.Errorf("Expected custom COEP, got: %s", h["Cross-Origin-Embedder-Policy"])
	}
}
