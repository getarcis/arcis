/*
Arcis Go — Integration & Middleware Tests

Tests the main Arcis facade and HTTP middleware behavior.
Unit tests for individual components are in their respective *_test.go files.
Run with: go test -v ./...
*/
package arcis

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// MIDDLEWARE INTEGRATION TESTS
// ============================================================================

func TestMiddleware_SetsSecurityHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s := New()
	defer s.Close()

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler(handler).ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be set")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be set")
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy should be set")
	}
}

func TestMiddleware_SetsRateLimitHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultConfig()
	config.RateLimitMax = 100
	s := NewWithConfig(config)
	defer s.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	s.Handler(handler).ServeHTTP(rec, req)

	if rec.Header().Get("X-RateLimit-Limit") != "100" {
		t.Errorf("X-RateLimit-Limit should be 100, got: %s", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining should be set")
	}
}

func TestMiddleware_BlocksRateLimitExceeded(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultConfig()
	config.RateLimitMax = 2
	s := NewWithConfig(config)
	defer s.Close()

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		s.Handler(handler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d should return 200", i+1)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	s.Handler(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request should return 429, got: %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response body: %v", err)
	}
	if _, exists := body["error"]; !exists {
		t.Error("Response should contain error message")
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Response should have Retry-After header")
	}
}

func TestMiddleware_RemovesFingerprintHeaders(t *testing.T) {
	// Middleware removes Server/X-Powered-By before calling the handler.
	// Verify that headers set by upstream middleware (before Arcis) are stripped.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler does NOT set Server/X-Powered-By — they should already be gone.
		if w.Header().Get("Server") != "" {
			t.Error("Server header should be removed before handler runs")
		}
		if w.Header().Get("X-Powered-By") != "" {
			t.Error("X-Powered-By header should be removed before handler runs")
		}
		w.WriteHeader(http.StatusOK)
	})

	s := New()
	defer s.Close()

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Simulate upstream middleware setting fingerprint headers
	rec.Header().Set("Server", "Apache/2.4.41")
	rec.Header().Set("X-Powered-By", "PHP/7.4")

	s.Handler(handler).ServeHTTP(rec, req)
}
