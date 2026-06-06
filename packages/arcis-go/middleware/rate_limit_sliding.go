package middleware

import (
	"context"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/getarcis/arcis/v2/core"
	"github.com/getarcis/arcis/v2/utils"
)

// SlidingWindowLimiter implements a weighted sliding window rate limiter.
// It provides smoother rate limiting than fixed windows by weighting
// the previous window's count based on how far into the current window we are.
type SlidingWindowLimiter struct {
	max      int
	window   time.Duration
	current  map[string]*slidingEntry
	previous map[string]*slidingEntry
	mu       sync.Mutex
	keyFunc  func(*http.Request) string
	skipFunc func(*http.Request) bool
	ctx      context.Context
	cancel   context.CancelFunc
}

type slidingEntry struct {
	count int
	start time.Time
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter.
func NewSlidingWindowLimiter(max int, window time.Duration) *SlidingWindowLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	sw := &SlidingWindowLimiter{
		max:      max,
		window:   window,
		current:  make(map[string]*slidingEntry),
		previous: make(map[string]*slidingEntry),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Cleanup goroutine
	cleanupInterval := window
	if cleanupInterval < 10*time.Second {
		cleanupInterval = 10 * time.Second
	}
	if cleanupInterval > 300*time.Second {
		cleanupInterval = 300 * time.Second
	}

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sw.cleanup()
			}
		}
	}()

	return sw
}

// SetKeyFunc sets a custom function to extract the rate limit key from requests.
func (sw *SlidingWindowLimiter) SetKeyFunc(fn func(*http.Request) string) {
	sw.keyFunc = fn
}

// SetSkipFunc sets a function that determines whether to skip rate limiting.
func (sw *SlidingWindowLimiter) SetSkipFunc(fn func(*http.Request) bool) {
	sw.skipFunc = fn
}

// Check checks if a request is within the rate limit.
func (sw *SlidingWindowLimiter) Check(r *http.Request) core.RateLimitResult {
	if sw.skipFunc != nil && sw.skipFunc(r) {
		return core.RateLimitResult{
			Allowed:   true,
			Limit:     sw.max,
			Remaining: sw.max,
			Reset:     sw.window,
		}
	}

	key := utils.GetClientIP(r)
	if sw.keyFunc != nil {
		key = sw.keyFunc(r)
	}

	return sw.CheckKey(key)
}

// CheckKey checks rate limit for a specific key using the sliding window algorithm.
func (sw *SlidingWindowLimiter) CheckKey(key string) core.RateLimitResult {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowSec := sw.window.Seconds()

	// Calculate current window boundaries
	windowStart := time.Unix(int64(math.Floor(float64(now.Unix())/windowSec)*windowSec), 0)

	// Rotate windows if needed
	if entry, exists := sw.current[key]; exists {
		if entry.start.Before(windowStart) {
			sw.previous[key] = entry
			sw.current[key] = &slidingEntry{count: 0, start: windowStart}
		}
	}

	// Get previous and current counts
	prevCount := 0
	if prev, exists := sw.previous[key]; exists {
		prevCount = prev.count
	}

	currentCount := 0
	if curr, exists := sw.current[key]; exists {
		currentCount = curr.count
	}

	// Calculate weighted estimate
	elapsed := now.Sub(windowStart).Seconds()
	weight := math.Max(0, (windowSec-elapsed)/windowSec)
	estimatedCount := float64(prevCount)*weight + float64(currentCount) + 1

	// Calculate reset time
	resetDuration := windowStart.Add(sw.window).Sub(now)

	remaining := int(math.Max(0, math.Floor(float64(sw.max)-estimatedCount)))

	if estimatedCount > float64(sw.max) {
		return core.RateLimitResult{
			Allowed:   false,
			Limit:     sw.max,
			Remaining: 0,
			Reset:     resetDuration,
		}
	}

	// Only increment if allowed
	if _, exists := sw.current[key]; !exists {
		sw.current[key] = &slidingEntry{count: 0, start: windowStart}
	}
	sw.current[key].count++

	return core.RateLimitResult{
		Allowed:   true,
		Limit:     sw.max,
		Remaining: remaining,
		Reset:     resetDuration,
	}
}

// Close stops the cleanup goroutine and releases resources.
func (sw *SlidingWindowLimiter) Close() {
	sw.cancel()
}

func (sw *SlidingWindowLimiter) cleanup() {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowSec := sw.window.Seconds()
	windowStart := time.Unix(int64(math.Floor(float64(now.Unix())/windowSec)*windowSec), 0)

	// Remove stale previous entries
	for key, entry := range sw.previous {
		if entry.start.Before(windowStart.Add(-sw.window)) {
			delete(sw.previous, key)
		}
	}

	// Remove stale current entries (promote to previous if needed)
	for key, entry := range sw.current {
		if entry.start.Before(windowStart) {
			sw.previous[key] = entry
			delete(sw.current, key)
		}
	}
}
