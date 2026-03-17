package arcis

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// RateLimitResult holds the result of a rate limit check.
type RateLimitResult struct {
	Allowed   bool
	Limit     int
	Remaining int
	Reset     time.Duration
}

// RateLimitEntry holds the data for a single rate limit record.
// Used by RateLimitStore implementations.
type RateLimitEntry struct {
	Count     int
	ResetTime time.Time
}

// RateLimitStore defines the interface for pluggable rate limit store backends.
// The default implementation is an in-memory store. Implement this interface
// to use a distributed backend such as Redis for multi-instance deployments.
type RateLimitStore interface {
	Get(key string) *RateLimitEntry
	Set(key string, entry *RateLimitEntry)
	Increment(key string) int
	Cleanup()
}

// RateLimiter handles rate limiting with configurable limits and windows.
type RateLimiter struct {
	max         int
	window      time.Duration
	store       map[string]*rateLimitEntry
	customStore RateLimitStore
	mu          sync.RWMutex
	skipFunc    func(*http.Request) bool
	ctx         context.Context
	cancel      context.CancelFunc
}

type rateLimitEntry struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates a new RateLimiter with the given limit and window
// using the default in-memory store.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		max:    max,
		window: window,
		store:  make(map[string]*rateLimitEntry),
		ctx:    ctx,
		cancel: cancel,
	}

	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	}()

	return rl
}

// NewRateLimiterWithStore creates a new RateLimiter backed by the provided store.
func NewRateLimiterWithStore(max int, window time.Duration, store RateLimitStore) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		max:         max,
		window:      window,
		customStore: store,
		ctx:         ctx,
		cancel:      cancel,
	}

	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.Cleanup()
			}
		}
	}()

	return rl
}

// SetSkipFunc sets a function that determines whether to skip rate limiting.
func (rl *RateLimiter) SetSkipFunc(fn func(*http.Request) bool) {
	rl.skipFunc = fn
}

// Check checks if a request is within the rate limit.
func (rl *RateLimiter) Check(r *http.Request) RateLimitResult {
	if rl.skipFunc != nil && rl.skipFunc(r) {
		return RateLimitResult{
			Allowed:   true,
			Limit:     rl.max,
			Remaining: rl.max,
			Reset:     rl.window,
		}
	}

	key := getClientIP(r)
	return rl.CheckKey(key)
}

// CheckKey checks rate limit for a specific key.
func (rl *RateLimiter) CheckKey(key string) RateLimitResult {
	if rl.customStore != nil {
		return rl.checkKeyWithStore(key)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	entry, exists := rl.store[key]
	if !exists || entry.resetTime.Before(now) {
		rl.store[key] = &rateLimitEntry{
			count:     1,
			resetTime: now.Add(rl.window),
		}
		return RateLimitResult{
			Allowed:   true,
			Limit:     rl.max,
			Remaining: rl.max - 1,
			Reset:     rl.window,
		}
	}

	entry.count++
	remaining := rl.max - entry.count
	if remaining < 0 {
		remaining = 0
	}
	reset := entry.resetTime.Sub(now)

	return RateLimitResult{
		Allowed:   entry.count <= rl.max,
		Limit:     rl.max,
		Remaining: remaining,
		Reset:     reset,
	}
}

func (rl *RateLimiter) checkKeyWithStore(key string) RateLimitResult {
	now := time.Now()

	entry := rl.customStore.Get(key)
	if entry == nil {
		resetTime := now.Add(rl.window)
		rl.customStore.Set(key, &RateLimitEntry{Count: 1, ResetTime: resetTime})
		return RateLimitResult{
			Allowed:   true,
			Limit:     rl.max,
			Remaining: rl.max - 1,
			Reset:     rl.window,
		}
	}

	count := rl.customStore.Increment(key)
	remaining := rl.max - count
	if remaining < 0 {
		remaining = 0
	}
	reset := entry.ResetTime.Sub(now)

	return RateLimitResult{
		Allowed:   count <= rl.max,
		Limit:     rl.max,
		Remaining: remaining,
		Reset:     reset,
	}
}

// Close stops the cleanup goroutine and releases resources.
func (rl *RateLimiter) Close() {
	rl.cancel()
}

func (rl *RateLimiter) cleanup() {
	if rl.customStore != nil {
		rl.customStore.Cleanup()
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, entry := range rl.store {
		if entry.resetTime.Before(now) {
			delete(rl.store, key)
		}
	}
}
