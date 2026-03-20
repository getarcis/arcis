package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenBucket_AllowsBurst(t *testing.T) {
	tb := NewTokenBucketLimiter(5, 1)
	defer tb.Close()

	for i := 0; i < 5; i++ {
		result := tb.CheckKey("test")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed (burst)", i+1)
		}
	}
}

func TestTokenBucket_BlocksAfterBurst(t *testing.T) {
	tb := NewTokenBucketLimiter(3, 1)
	defer tb.Close()

	for i := 0; i < 3; i++ {
		tb.CheckKey("test")
	}

	result := tb.CheckKey("test")
	if result.Allowed {
		t.Error("Should be blocked after burst exhausted")
	}
}

func TestTokenBucket_ReturnsCorrectRemaining(t *testing.T) {
	tb := NewTokenBucketLimiter(5, 1)
	defer tb.Close()

	for i := 0; i < 5; i++ {
		result := tb.CheckKey("test")
		if result.Remaining != 5-i-1 {
			t.Errorf("Request %d: expected remaining %d, got %d", i+1, 5-i-1, result.Remaining)
		}
	}
}

func TestTokenBucket_ReturnsRetryAfter(t *testing.T) {
	tb := NewTokenBucketLimiter(1, 1)
	defer tb.Close()

	tb.CheckKey("test")

	result := tb.CheckKey("test")
	if result.Allowed {
		t.Error("Should be blocked")
	}
	if result.Reset <= 0 {
		t.Errorf("Expected positive retry-after, got %v", result.Reset)
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	tb := NewTokenBucketLimiter(2, 1000) // 1000 tokens/sec for fast refill
	defer tb.Close()

	tb.CheckKey("test")
	tb.CheckKey("test")

	// Should be blocked
	result := tb.CheckKey("test")
	if result.Allowed {
		t.Error("Should be blocked immediately after exhaustion")
	}

	// Wait briefly for refill
	time.Sleep(10 * time.Millisecond)

	result = tb.CheckKey("test")
	if !result.Allowed {
		t.Error("Should be allowed after refill")
	}
}

func TestTokenBucket_DifferentKeysSeparate(t *testing.T) {
	tb := NewTokenBucketLimiter(1, 1)
	defer tb.Close()

	result := tb.CheckKey("user-a")
	if !result.Allowed {
		t.Error("user-a first request should be allowed")
	}

	result = tb.CheckKey("user-a")
	if result.Allowed {
		t.Error("user-a should be blocked")
	}

	result = tb.CheckKey("user-b")
	if !result.Allowed {
		t.Error("user-b should be allowed")
	}
}

func TestTokenBucket_CustomCost(t *testing.T) {
	tb := NewTokenBucketLimiterWithCost(10, 1, 5)
	defer tb.Close()

	// First request costs 5 tokens, leaving 5
	result := tb.CheckKey("test")
	if !result.Allowed {
		t.Error("First request should be allowed")
	}
	if result.Remaining != 5 {
		t.Errorf("Expected remaining 5, got %d", result.Remaining)
	}

	// Second request costs 5 tokens, leaving 0
	result = tb.CheckKey("test")
	if !result.Allowed {
		t.Error("Second request should be allowed")
	}
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}

	// Third request: no tokens left
	result = tb.CheckKey("test")
	if result.Allowed {
		t.Error("Third request should be blocked")
	}
}

func TestTokenBucket_CostClampedToCapacity(t *testing.T) {
	// Cost > capacity gets clamped to capacity
	tb := NewTokenBucketLimiterWithCost(5, 1, 10)
	defer tb.Close()

	result := tb.CheckKey("test")
	if !result.Allowed {
		t.Error("Should be allowed (cost clamped to capacity)")
	}

	result = tb.CheckKey("test")
	if result.Allowed {
		t.Error("Should be blocked after single request")
	}
}

func TestTokenBucket_MinCostIsOne(t *testing.T) {
	tb := NewTokenBucketLimiterWithCost(5, 1, 0)
	defer tb.Close()

	result := tb.CheckKey("test")
	if !result.Allowed {
		t.Error("Should be allowed")
	}
	// Cost should be 1, so remaining = 4
	if result.Remaining != 4 {
		t.Errorf("Expected remaining 4 (cost=1), got %d", result.Remaining)
	}
}

func TestTokenBucket_MinCapacity(t *testing.T) {
	tb := NewTokenBucketLimiter(0, 1) // capacity clamped to 1
	defer tb.Close()

	result := tb.CheckKey("test")
	if !result.Allowed {
		t.Error("First request should be allowed")
	}

	result = tb.CheckKey("test")
	if result.Allowed {
		t.Error("Second request should be blocked")
	}
}

func TestTokenBucket_MinRefillRate(t *testing.T) {
	tb := NewTokenBucketLimiter(5, 0) // refillRate clamped to 1
	defer tb.Close()

	result := tb.CheckKey("test")
	if !result.Allowed {
		t.Error("Should be allowed")
	}
}

func TestTokenBucket_CheckWithRequest(t *testing.T) {
	tb := NewTokenBucketLimiter(5, 1)
	defer tb.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	result := tb.Check(req)
	if !result.Allowed {
		t.Error("Should be allowed")
	}
	if result.Limit != 5 {
		t.Errorf("Expected limit 5, got %d", result.Limit)
	}
}

func TestTokenBucket_SkipFunc(t *testing.T) {
	tb := NewTokenBucketLimiter(1, 1)
	defer tb.Close()

	tb.SetSkipFunc(func(r *http.Request) bool {
		return r.Header.Get("X-Admin") == "true"
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	tb.Check(req)

	// Normal request should be blocked
	result := tb.Check(req)
	if result.Allowed {
		t.Error("Should be blocked")
	}

	// Admin request should be skipped
	adminReq := httptest.NewRequest(http.MethodGet, "/", nil)
	adminReq.RemoteAddr = "1.2.3.4:1234"
	adminReq.Header.Set("X-Admin", "true")
	result = tb.Check(adminReq)
	if !result.Allowed {
		t.Error("Admin should be allowed (skipped)")
	}
}

func TestTokenBucket_CustomKeyFunc(t *testing.T) {
	tb := NewTokenBucketLimiter(1, 1)
	defer tb.Close()

	tb.SetKeyFunc(func(r *http.Request) string {
		return r.Header.Get("X-API-Key")
	})

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-API-Key", "key-a")

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-API-Key", "key-b")

	tb.Check(req1)

	result := tb.Check(req1)
	if result.Allowed {
		t.Error("key-a should be blocked")
	}

	result = tb.Check(req2)
	if !result.Allowed {
		t.Error("key-b should be allowed")
	}
}

func TestTokenBucket_BlockedRemainingIsZero(t *testing.T) {
	tb := NewTokenBucketLimiter(1, 1)
	defer tb.Close()

	tb.CheckKey("test")

	result := tb.CheckKey("test")
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}
}

func TestTokenBucket_CapacityIsLimit(t *testing.T) {
	tb := NewTokenBucketLimiter(50, 10)
	defer tb.Close()

	result := tb.CheckKey("test")
	if result.Limit != 50 {
		t.Errorf("Expected limit 50, got %d", result.Limit)
	}
}

func BenchmarkTokenBucket_Check(b *testing.B) {
	tb := NewTokenBucketLimiter(100000, 100000)
	defer tb.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.CheckKey("test-ip")
	}
}
