package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSlidingWindow_AllowsUnderLimit(t *testing.T) {
	sw := NewSlidingWindowLimiter(5, time.Minute)
	defer sw.Close()

	for i := 0; i < 5; i++ {
		result := sw.CheckKey("test-ip")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
}

func TestSlidingWindow_BlocksOverLimit(t *testing.T) {
	sw := NewSlidingWindowLimiter(3, time.Minute)
	defer sw.Close()

	for i := 0; i < 3; i++ {
		result := sw.CheckKey("test-ip")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	result := sw.CheckKey("test-ip")
	if result.Allowed {
		t.Error("4th request should be blocked")
	}
}

func TestSlidingWindow_ReturnsHeaders(t *testing.T) {
	sw := NewSlidingWindowLimiter(100, time.Minute)
	defer sw.Close()

	result := sw.CheckKey("test-ip")

	if result.Limit != 100 {
		t.Errorf("Expected limit 100, got %d", result.Limit)
	}
	if result.Remaining != 99 {
		t.Errorf("Expected remaining 99, got %d", result.Remaining)
	}
	if result.Reset <= 0 {
		t.Errorf("Expected positive reset time, got %v", result.Reset)
	}
}

func TestSlidingWindow_RemainingDecreases(t *testing.T) {
	sw := NewSlidingWindowLimiter(5, time.Minute)
	defer sw.Close()

	for i := 0; i < 5; i++ {
		result := sw.CheckKey("test-ip")
		expectedRemaining := 5 - i - 1
		if result.Remaining != expectedRemaining {
			t.Errorf("Request %d: expected remaining %d, got %d", i+1, expectedRemaining, result.Remaining)
		}
	}
}

func TestSlidingWindow_BlockedRemainingIsZero(t *testing.T) {
	sw := NewSlidingWindowLimiter(2, time.Minute)
	defer sw.Close()

	sw.CheckKey("test-ip")
	sw.CheckKey("test-ip")

	result := sw.CheckKey("test-ip")
	if result.Allowed {
		t.Error("Should be blocked")
	}
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}
}

func TestSlidingWindow_DifferentKeysSeparateLimits(t *testing.T) {
	sw := NewSlidingWindowLimiter(2, time.Minute)
	defer sw.Close()

	for i := 0; i < 2; i++ {
		result := sw.CheckKey("user-a")
		if !result.Allowed {
			t.Errorf("user-a request %d should be allowed", i+1)
		}
	}

	// user-a should be blocked
	result := sw.CheckKey("user-a")
	if result.Allowed {
		t.Error("user-a should be blocked")
	}

	// user-b should still be allowed
	result = sw.CheckKey("user-b")
	if !result.Allowed {
		t.Error("user-b should be allowed")
	}
}

func TestSlidingWindow_RejectedDoesNotConsume(t *testing.T) {
	sw := NewSlidingWindowLimiter(2, time.Minute)
	defer sw.Close()

	sw.CheckKey("test")
	sw.CheckKey("test")

	// These should all be blocked but not consume quota
	for i := 0; i < 5; i++ {
		result := sw.CheckKey("test")
		if result.Allowed {
			t.Errorf("Request %d should be blocked", i+3)
		}
	}
}

func TestSlidingWindow_CheckWithRequest(t *testing.T) {
	sw := NewSlidingWindowLimiter(5, time.Minute)
	defer sw.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	result := sw.Check(req)
	if !result.Allowed {
		t.Error("Request should be allowed")
	}
	if result.Limit != 5 {
		t.Errorf("Expected limit 5, got %d", result.Limit)
	}
}

func TestSlidingWindow_SkipFunc(t *testing.T) {
	sw := NewSlidingWindowLimiter(1, time.Minute)
	defer sw.Close()

	sw.SetSkipFunc(func(r *http.Request) bool {
		return r.Header.Get("X-Skip") == "true"
	})

	// Use the 1 allowed request
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	sw.Check(req1)

	// Normal request should be blocked
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	result := sw.Check(req2)
	if result.Allowed {
		t.Error("Should be blocked")
	}

	// Skipped request should be allowed
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "1.2.3.4:1234"
	req3.Header.Set("X-Skip", "true")
	result = sw.Check(req3)
	if !result.Allowed {
		t.Error("Skipped request should be allowed")
	}
	if result.Remaining != 1 {
		t.Errorf("Expected remaining to equal max (1), got %d", result.Remaining)
	}
}

func TestSlidingWindow_CustomKeyFunc(t *testing.T) {
	sw := NewSlidingWindowLimiter(2, time.Minute)
	defer sw.Close()

	sw.SetKeyFunc(func(r *http.Request) string {
		return r.Header.Get("X-API-Key")
	})

	// Same IP but different API keys should have separate limits
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	req1.Header.Set("X-API-Key", "key-a")

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	req2.Header.Set("X-API-Key", "key-b")

	sw.Check(req1)
	sw.Check(req1)

	result := sw.Check(req1)
	if result.Allowed {
		t.Error("key-a should be blocked")
	}

	result = sw.Check(req2)
	if !result.Allowed {
		t.Error("key-b should be allowed")
	}
}

func TestSlidingWindow_ResetTime(t *testing.T) {
	sw := NewSlidingWindowLimiter(5, time.Minute)
	defer sw.Close()

	result := sw.CheckKey("test")
	if result.Reset <= 0 {
		t.Errorf("Expected positive reset, got %v", result.Reset)
	}
	if result.Reset > time.Minute {
		t.Errorf("Expected reset <= 1 minute, got %v", result.Reset)
	}
}

func TestSlidingWindow_LimitOfOne(t *testing.T) {
	sw := NewSlidingWindowLimiter(1, time.Minute)
	defer sw.Close()

	result := sw.CheckKey("test")
	if !result.Allowed {
		t.Error("First request should be allowed")
	}
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}

	result = sw.CheckKey("test")
	if result.Allowed {
		t.Error("Second request should be blocked")
	}
}

func BenchmarkSlidingWindow_Check(b *testing.B) {
	sw := NewSlidingWindowLimiter(100000, time.Minute)
	defer sw.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sw.CheckKey("test-ip")
	}
}
