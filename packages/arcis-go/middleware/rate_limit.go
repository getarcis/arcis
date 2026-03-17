package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/GagancM/arcis/core"
	"github.com/GagancM/arcis/utils"
)

// RateLimiter handles rate limiting with configurable limits and windows.
type RateLimiter struct {
	max         int
	window      time.Duration
	store       map[string]*rateLimitEntry
	customStore core.RateLimitStore
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
func NewRateLimiterWithStore(max int, window time.Duration, store core.RateLimitStore) *RateLimiter {
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
func (rl *RateLimiter) Check(r *http.Request) core.RateLimitResult {
	if rl.skipFunc != nil && rl.skipFunc(r) {
		return core.RateLimitResult{
			Allowed:   true,
			Limit:     rl.max,
			Remaining: rl.max,
			Reset:     rl.window,
		}
	}

	key := utils.GetClientIP(r)
	return rl.CheckKey(key)
}

// CheckKey checks rate limit for a specific key.
func (rl *RateLimiter) CheckKey(key string) core.RateLimitResult {
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
		return core.RateLimitResult{
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

	return core.RateLimitResult{
		Allowed:   entry.count <= rl.max,
		Limit:     rl.max,
		Remaining: remaining,
		Reset:     reset,
	}
}

func (rl *RateLimiter) checkKeyWithStore(key string) core.RateLimitResult {
	now := time.Now()

	entry := rl.customStore.Get(key)
	if entry == nil {
		resetTime := now.Add(rl.window)
		rl.customStore.Set(key, &core.RateLimitEntry{Count: 1, ResetTime: resetTime})
		return core.RateLimitResult{
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

	return core.RateLimitResult{
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
