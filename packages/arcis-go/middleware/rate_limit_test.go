package middleware

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	defer rl.Close()

	for i := 0; i < 3; i++ {
		result := rl.CheckKey("test-ip")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_ReturnsHeaders(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Close()

	result := rl.CheckKey("test-ip")

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

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	defer rl.Close()

	for i := 0; i < 3; i++ {
		result := rl.CheckKey("192.168.1.1")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	result := rl.CheckKey("192.168.1.1")
	if result.Allowed {
		t.Error("4th request should be blocked")
	}
}

func TestRateLimiter_DifferentIPsSeparateLimits(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Close()

	for ip := 0; ip < 3; ip++ {
		key := "192.168.1." + string(rune('0'+ip))
		for i := 0; i < 2; i++ {
			result := rl.CheckKey(key)
			if !result.Allowed {
				t.Errorf("Request from %s should be allowed", key)
			}
		}
	}
}

func BenchmarkRateLimiter_Check(b *testing.B) {
	rl := NewRateLimiter(100000, time.Minute)
	defer rl.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.CheckKey("test-ip")
	}
}
