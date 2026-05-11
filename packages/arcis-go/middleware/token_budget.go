package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Token-budget protection middleware. Caps per-key token spend over a
// sliding window — meant for routes that proxy LLM calls, where a tight
// 100-req/min rate limit isn't enough because a single 50KB prompt costs
// the same as 1000 small requests.
//
// Mirrors the Node + Python implementations.

// TokenBudgetOptions configures the middleware.
type TokenBudgetOptions struct {
	// MaxTokens caps how many tokens one key can spend per window.
	// Default: 100_000.
	MaxTokens int

	// Window is the sliding-window length. Default: 1 hour.
	Window time.Duration

	// MaxRequestTokens, when > 0, rejects any single request that would
	// consume more than this many tokens (with 413, before the budget is
	// charged). Default: 0 (no per-request cap).
	MaxRequestTokens int

	// KeyGenerator returns the budget key for a request. Default: client
	// IP, falling back to "unknown" when unresolvable.
	KeyGenerator func(*http.Request) string

	// EstimateTokens computes the token cost of a request. Default:
	// ceil((Content-Length) / 4) — close to OpenAI's "1 token ≈ 4 chars"
	// rule. Override for accurate counting (tiktoken / your tokenizer).
	EstimateTokens func(*http.Request) int

	// StatusCode returned when the window budget is exhausted. Default: 429.
	StatusCode int

	// StatusCodeOversize returned when MaxRequestTokens is exceeded.
	// Default: 413.
	StatusCodeOversize int

	// Message in the 429 response body. Default: "Token budget exceeded
	// for this window."
	Message string

	// MessageOversize in the 413 response body. Default: "Request exceeds
	// the per-request token limit."
	MessageOversize string

	// Skip lets specific requests bypass enforcement entirely.
	Skip func(*http.Request) bool
}

const (
	defaultTokenBudgetMax    = 100_000
	defaultTokenBudgetWindow = time.Hour
)

type tokenBudgetEntry struct {
	used      int
	resetTime time.Time
}

// TokenBudget is the live middleware instance. The Middleware() method
// returns an `http.Handler` decorator; Inspect() reads current usage; Close()
// releases the cleanup goroutine.
type TokenBudget struct {
	opts  TokenBudgetOptions
	store map[string]*tokenBudgetEntry
	mu    sync.Mutex
	stop  chan struct{}
}

// NewTokenBudget builds a TokenBudget from options, applying defaults. The
// returned value is safe for concurrent use.
func NewTokenBudget(opts TokenBudgetOptions) *TokenBudget {
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = defaultTokenBudgetMax
	}
	if opts.Window <= 0 {
		opts.Window = defaultTokenBudgetWindow
	}
	if opts.KeyGenerator == nil {
		opts.KeyGenerator = defaultTokenBudgetKey
	}
	if opts.EstimateTokens == nil {
		opts.EstimateTokens = defaultEstimateTokens
	}
	if opts.StatusCode == 0 {
		opts.StatusCode = http.StatusTooManyRequests
	}
	if opts.StatusCodeOversize == 0 {
		opts.StatusCodeOversize = http.StatusRequestEntityTooLarge
	}
	if opts.Message == "" {
		opts.Message = "Token budget exceeded for this window."
	}
	if opts.MessageOversize == "" {
		opts.MessageOversize = "Request exceeds the per-request token limit."
	}

	tb := &TokenBudget{
		opts:  opts,
		store: make(map[string]*tokenBudgetEntry),
		stop:  make(chan struct{}),
	}

	// Periodic sweep of expired buckets so a long-lived process doesn't
	// grow unbounded under high cardinality.
	go tb.sweep()
	return tb
}

func (tb *TokenBudget) sweep() {
	t := time.NewTicker(tb.opts.Window)
	defer t.Stop()
	for {
		select {
		case <-tb.stop:
			return
		case now := <-t.C:
			tb.mu.Lock()
			for k, e := range tb.store {
				if now.After(e.resetTime) {
					delete(tb.store, k)
				}
			}
			tb.mu.Unlock()
		}
	}
}

// Close stops the background cleanup. Safe to call multiple times.
func (tb *TokenBudget) Close() {
	select {
	case <-tb.stop:
		// already closed
	default:
		close(tb.stop)
	}
}

// Inspect returns the current usage for a key. Returns nil when the key has
// never been charged or its window has expired.
func (tb *TokenBudget) Inspect(key string) *struct {
	Used      int
	ResetTime time.Time
} {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	e, ok := tb.store[key]
	if !ok {
		return nil
	}
	return &struct {
		Used      int
		ResetTime time.Time
	}{Used: e.used, ResetTime: e.resetTime}
}

// Reset clears a single key's budget, or all keys if key is empty.
func (tb *TokenBudget) Reset(key string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if key == "" {
		tb.store = make(map[string]*tokenBudgetEntry)
		return
	}
	delete(tb.store, key)
}

// Middleware returns an http.Handler decorator that enforces the budget.
func (tb *TokenBudget) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tb.opts.Skip != nil && tb.opts.Skip(r) {
				next.ServeHTTP(w, r)
				return
			}

			estimated := safeEstimate(tb.opts.EstimateTokens, r)

			// Per-request cap (rejected before charging the budget).
			if tb.opts.MaxRequestTokens > 0 && estimated > tb.opts.MaxRequestTokens {
				w.Header().Set("X-Token-Budget-Limit", strconv.Itoa(tb.opts.MaxTokens))
				w.Header().Set("X-Token-Budget-Request-Cost", strconv.Itoa(estimated))
				writeJSONError(w, tb.opts.StatusCodeOversize, map[string]any{
					"error":            tb.opts.MessageOversize,
					"requestTokens":    estimated,
					"maxRequestTokens": tb.opts.MaxRequestTokens,
				})
				return
			}

			key := tb.opts.KeyGenerator(r)
			now := time.Now()

			tb.mu.Lock()
			entry, ok := tb.store[key]
			if !ok || now.After(entry.resetTime) {
				entry = &tokenBudgetEntry{used: 0, resetTime: now.Add(tb.opts.Window)}
				tb.store[key] = entry
			}
			projected := entry.used + estimated
			resetSec := int(entry.resetTime.Sub(now).Seconds() + 0.999)
			if resetSec < 0 {
				resetSec = 0
			}
			tb.mu.Unlock()

			w.Header().Set("X-Token-Budget-Limit", strconv.Itoa(tb.opts.MaxTokens))
			w.Header().Set("X-Token-Budget-Used", strconv.Itoa(entry.used))
			remaining := tb.opts.MaxTokens - entry.used
			if remaining < 0 {
				remaining = 0
			}
			w.Header().Set("X-Token-Budget-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-Token-Budget-Reset", strconv.Itoa(resetSec))
			w.Header().Set("X-Token-Budget-Request-Cost", strconv.Itoa(estimated))

			if projected > tb.opts.MaxTokens {
				w.Header().Set("Retry-After", strconv.Itoa(resetSec))
				writeJSONError(w, tb.opts.StatusCode, map[string]any{
					"error":      tb.opts.Message,
					"used":       entry.used,
					"maxTokens":  tb.opts.MaxTokens,
					"retryAfter": resetSec,
				})
				return
			}

			// Charge and continue.
			tb.mu.Lock()
			entry.used = projected
			tb.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

func defaultTokenBudgetKey(r *http.Request) string {
	// X-Forwarded-For (first hop) wins when present, then RemoteAddr.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// take first comma-separated value
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return trimSpaces(xff[:i])
			}
		}
		return trimSpaces(xff)
	}
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			return host
		}
		return r.RemoteAddr
	}
	return "unknown"
}

func defaultEstimateTokens(r *http.Request) int {
	if r.ContentLength <= 0 {
		return 0
	}
	// ceil(ContentLength / 4)
	bytes := int(r.ContentLength)
	return (bytes + 3) / 4
}

func safeEstimate(fn func(*http.Request) int, r *http.Request) int {
	defer func() { _ = recover() }()
	v := fn(r)
	if v < 0 {
		return 0
	}
	return v
}

func writeJSONError(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoded, err := json.Marshal(body)
	if err != nil {
		fmt.Fprintf(w, `{"error":"%s"}`, body["error"])
		return
	}
	_, _ = w.Write(encoded)
}

func trimSpaces(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
