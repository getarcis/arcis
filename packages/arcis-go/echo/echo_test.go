/*
Arcis Echo Adapter Tests
=========================

Tests for Echo middleware integration aligned with TEST_VECTORS.json spec.
Run with: go test -v ./echo/...

Requires: github.com/labstack/echo/v4
*/
package echo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// ============================================================================
// CONFIG TESTS
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if !config.Sanitize {
		t.Error("Sanitize should be true by default")
	}
	if !config.RateLimit {
		t.Error("RateLimit should be true by default")
	}
	if config.RateLimitMax != 100 {
		t.Errorf("Expected RateLimitMax 100, got %d", config.RateLimitMax)
	}
	if config.RateLimitWindow != time.Minute {
		t.Errorf("Expected RateLimitWindow 1 minute, got %v", config.RateLimitWindow)
	}
	if !config.Headers {
		t.Error("Headers should be true by default")
	}
	if config.FrameOptions != "DENY" {
		t.Errorf("Expected FrameOptions DENY, got %s", config.FrameOptions)
	}
}

// ============================================================================
// MIDDLEWARE TESTS
// ============================================================================

func TestMiddleware_SetsSecurityHeaders(t *testing.T) {
	e := echo.New()
	e.Use(Middleware())
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// Check security headers (from TEST_VECTORS.json)
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}
	if rec.Header().Get("X-XSS-Protection") != "0" {
		t.Error("X-XSS-Protection should be 0")
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy should be set")
	}
	if !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Error("Strict-Transport-Security should contain max-age=")
	}
}

func TestMiddleware_SetsRateLimitHeaders(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(MiddlewareWithConfig(Config{
		RateLimit:       true,
		RateLimitMax:    100,
		RateLimitWindow: time.Minute,
		Headers:         false,
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// Check rate limit headers (from TEST_VECTORS.json)
	if rec.Header().Get("X-RateLimit-Limit") != "100" {
		t.Errorf("X-RateLimit-Limit should be 100, got %s", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining should be set")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("X-RateLimit-Reset should be set")
	}
}

func TestMiddleware_AllowsUnderLimit(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(MiddlewareWithConfig(Config{
		RateLimit:       true,
		RateLimitMax:    5,
		RateLimitWindow: time.Minute,
		Headers:         false,
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// Make 3 requests (all should pass per TEST_VECTORS)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d should return 200, got %d", i+1, rec.Code)
		}
	}
}

func TestMiddleware_BlocksOverLimit(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(MiddlewareWithConfig(Config{
		RateLimit:       true,
		RateLimitMax:    3,
		RateLimitWindow: time.Minute,
		Headers:         false,
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// Make 3 requests (all should pass)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d should return 200", i+1)
		}
	}

	// 4th request should be blocked (per TEST_VECTORS)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("4th request should return 429, got %d", rec.Code)
	}

	// Check error response
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if _, exists := body["error"]; !exists {
		t.Error("Response should contain error key")
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Response should have Retry-After header")
	}
}

func TestMiddleware_DifferentIPsSeparateLimits(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(MiddlewareWithConfig(Config{
		RateLimit:       true,
		RateLimitMax:    2,
		RateLimitWindow: time.Minute,
		Headers:         false,
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// 3 different IPs, 2 requests each - all should pass (per TEST_VECTORS)
	ips := []string{"192.168.1.1:12345", "192.168.1.2:12345", "192.168.1.3:12345"}
	for _, ip := range ips {
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = ip
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("Request from %s should pass", ip)
			}
		}
	}
}

func TestMiddleware_SkipFunction(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(MiddlewareWithConfig(Config{
		RateLimit:       true,
		RateLimitMax:    1,
		RateLimitWindow: time.Minute,
		Headers:         false,
		RateLimitSkip: func(c echo.Context) bool {
			return c.Request().Header.Get("X-Admin") == "true"
		},
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// First request uses the limit
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Error("First request should pass")
	}

	// Second request should be blocked
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Error("Second request should be blocked")
	}

	// Admin request should skip rate limiting
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Admin", "true")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Error("Admin request should pass (skipped)")
	}
}

func TestMiddleware_CustomCSP(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(MiddlewareWithConfig(Config{
		Headers:   true,
		RateLimit: false,
		CSP:       "default-src 'none'",
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("Expected custom CSP, got: %s", rec.Header().Get("Content-Security-Policy"))
	}
}

// ============================================================================
// GRANULAR MIDDLEWARE TESTS
// ============================================================================

func TestHeaders_Middleware(t *testing.T) {
	e := echo.New()
	e.Use(Headers())
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}
}

func TestRateLimit_Middleware(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(RateLimit(2, time.Minute))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// Make 2 requests (should pass)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d should pass", i+1)
		}
	}

	// 3rd request should be blocked
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request should be blocked, got %d", rec.Code)
	}
}

func TestRateLimitWithSkip_Middleware(t *testing.T) {
	defer Cleanup()

	skip := func(c echo.Context) bool {
		return c.QueryParam("bypass") == "true"
	}

	e := echo.New()
	e.Use(RateLimitWithSkip(1, time.Minute, skip))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// First request uses the limit
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Error("First request should pass")
	}

	// Second request blocked
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Error("Second request should be blocked")
	}

	// Bypassed request should pass
	req = httptest.NewRequest("GET", "/?bypass=true", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Error("Bypassed request should pass")
	}
}

func TestSanitizer_Middleware(t *testing.T) {
	e := echo.New()
	e.Use(Sanitizer())
	e.GET("/", func(c echo.Context) error {
		sanitizer := GetSanitizer(c)
		if sanitizer == nil {
			t.Error("Sanitizer should be available in context")
		}
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// ============================================================================
// SANITIZATION HELPER TESTS
// ============================================================================

func TestSanitizeJSON(t *testing.T) {
	e := echo.New()
	e.Use(Sanitizer())
	e.POST("/", func(c echo.Context) error {
		data := map[string]interface{}{
			"name": "<script>alert('xss')</script>",
		}
		sanitized := SanitizeJSON(c, data)

		if strings.Contains(sanitized["name"].(string), "<script>") {
			t.Error("XSS should be sanitized")
		}
		return c.JSON(http.StatusOK, sanitized)
	})

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestSanitizeString(t *testing.T) {
	e := echo.New()
	e.Use(Sanitizer())
	e.GET("/", func(c echo.Context) error {
		input := "<script>alert('xss')</script>"
		sanitized := SanitizeString(c, input)

		if strings.Contains(sanitized, "<script>") {
			t.Error("XSS should be sanitized")
		}
		return c.String(http.StatusOK, sanitized)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestGetSanitizer_WithoutMiddleware(t *testing.T) {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		// Should return default sanitizer even without middleware
		sanitizer := GetSanitizer(c)
		if sanitizer == nil {
			t.Error("Should return default sanitizer")
		}
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// ============================================================================
// ERROR HANDLER TESTS
// ============================================================================

func TestErrorHandler_AsHTTPErrorHandler(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = ErrorHandler(false)
	e.GET("/", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", rec.Code)
	}
}

func TestErrorMiddleware_HidesDetailsInProduction(t *testing.T) {
	e := echo.New()
	e.Use(ErrorMiddleware(false))
	e.GET("/", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection failed")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "Database") {
		t.Error("Should not expose database error in production")
	}
}

func TestErrorMiddleware_ShowsDetailsInDev(t *testing.T) {
	e := echo.New()
	e.Use(ErrorMiddleware(true))
	e.GET("/", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, "Something broke")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Something broke") {
		t.Error("Should show details in dev mode")
	}
}

// ============================================================================
// CLEANUP TESTS
// ============================================================================

func TestCleanup(t *testing.T) {
	// Create middleware which adds to activeInstances
	_ = Middleware()
	_ = RateLimit(10, time.Minute)

	if len(activeInstances) == 0 {
		t.Error("Should have active instances")
	}

	Cleanup()

	if len(activeInstances) != 0 {
		t.Error("Cleanup should clear all instances")
	}
}

// ============================================================================
// FINGERPRINT REMOVAL TESTS
// ============================================================================

func TestMiddleware_RemovesFingerprintHeaders(t *testing.T) {
	defer Cleanup()

	e := echo.New()
	e.Use(Middleware())
	e.GET("/", func(c echo.Context) error {
		// Try to set these headers (Arcis should remove them)
		c.Response().Header().Set("Server", "Apache/2.4.41")
		c.Response().Header().Set("X-Powered-By", "PHP/7.4")
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// These should be removed (per TEST_VECTORS removed_headers)
	if rec.Header().Get("Server") != "" {
		t.Error("Server header should be removed")
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("X-Powered-By header should be removed")
	}
}

// ============================================================================
// CONTEXT KEY TESTS
// ============================================================================

func TestContextKeys(t *testing.T) {
	if SanitizerKey != "arcis_sanitizer" {
		t.Errorf("Expected SanitizerKey 'arcis_sanitizer', got %s", SanitizerKey)
	}
	if ValidatedBodyKey != "arcis_validated_body" {
		t.Errorf("Expected ValidatedBodyKey 'arcis_validated_body', got %s", ValidatedBodyKey)
	}
}

func TestGetValidatedBody_WithoutValidation(t *testing.T) {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		body := GetValidatedBody(c)
		if body != nil {
			t.Error("Should return nil without validation middleware")
		}
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}
