/*
Package nethttp provides Arcis middleware adapters for plain net/http
servers (no third-party router required).

The implementation reuses the chi adapter (which is itself stdlib-only —
it never imports chi/v5 in code, only mentions it in its docstrings).
This package is a thin re-export so users who do not use chi can
discover the same middleware under an obvious import path.

Usage:

	import (
		"net/http"
		archttp "github.com/GagancM/arcis/nethttp"
	)

	func main() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", handler)

		// Full protection with defaults
		var h http.Handler = mux
		h = archttp.Middleware()(h)

		http.ListenAndServe(":8080", h)
	}

	// Or with custom config
	h = archttp.MiddlewareWithConfig(archttp.Config{
		RateLimitMax:    50,
		RateLimitWindow: time.Minute,
		CSP:             "default-src 'self'",
	})(h)

	// Granular rate-limit middleware with optional telemetry
	h = archttp.RateLimit(100, time.Minute, archttp.WithTelemetry(tc))(h)

# Resource Cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call
Cleanup() when your application shuts down to stop this goroutine and
release resources:

	import (
		"context"
		"net/http"
		"os/signal"
		"syscall"
		archttp "github.com/GagancM/arcis/nethttp"
	)

	func main() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", handler)

		var h http.Handler = mux
		h = archttp.Middleware()(h)

		srv := &http.Server{Addr: ":8080", Handler: h}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go srv.ListenAndServe()

		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
		archttp.Cleanup()
	}
*/
package nethttp

import (
	"net/http"
	"time"

	arcis "github.com/GagancM/arcis"
	arcischi "github.com/GagancM/arcis/chi"
	"github.com/GagancM/arcis/telemetry"
)

// Config holds Arcis middleware configuration. Aliased to the chi
// package so the two adapters share one source of truth.
type Config = arcischi.Config

// RateLimitOption configures a standalone rate-limit middleware. Use
// WithTelemetry to attach a telemetry client.
type RateLimitOption = arcischi.RateLimitOption

// DefaultConfig returns the default Arcis configuration.
func DefaultConfig() Config { return arcischi.DefaultConfig() }

// Cleanup closes all active Arcis middleware instances and releases
// resources. Stops background goroutines used by rate limiters for
// expired-entry cleanup. Call Cleanup() at application shutdown to
// prevent goroutine leaks.
//
// Cleanup is shared with the chi adapter — calling either flushes
// rate-limit instances created by either package.
func Cleanup() { arcischi.Cleanup() }

// WithTelemetry attaches a telemetry client to a standalone
// rate-limit middleware. On 429, one TelemetryEvent is emitted with
// vector="rate-limit", rule="rate-limit/exceeded", severity="medium".
//
// Standalone helpers emit only on deny. Allow events come from
// MiddlewareWithConfig; emitting them here would duplicate when
// composing RateLimit + Sanitizer + Validate with telemetry on each.
func WithTelemetry(tc *telemetry.Client) RateLimitOption {
	return arcischi.WithTelemetry(tc)
}

// Middleware returns the default Arcis middleware: rate limiting,
// security headers, server-fingerprint stripping. Composes with any
// router that accepts stdlib middleware (`func(http.Handler) http.Handler`).
func Middleware() func(http.Handler) http.Handler {
	return arcischi.Middleware()
}

// MiddlewareWithConfig returns Arcis middleware honoring the supplied
// config. When `Block` is true, scans the request body, query, and URL
// path for attack patterns and responds 403 instead of running the
// handler. When a Telemetry client is configured, emits one event per
// request (allow + deny) with the standard wire format.
func MiddlewareWithConfig(config Config) func(http.Handler) http.Handler {
	return arcischi.MiddlewareWithConfig(config)
}

// RateLimit returns a standalone rate-limit middleware. Optional
// WithTelemetry attaches a telemetry client that emits on 429.
func RateLimit(max int, window time.Duration, opts ...RateLimitOption) func(http.Handler) http.Handler {
	return arcischi.RateLimit(max, window, opts...)
}

// RateLimitWithStore returns a rate-limit middleware backed by an
// external store (Redis, etc.).
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore, opts ...RateLimitOption) func(http.Handler) http.Handler {
	return arcischi.RateLimitWithStore(max, window, store, opts...)
}

// RateLimitWithSkip returns a rate-limit middleware that skips
// counting requests for which `skip(r)` returns true (e.g. internal
// health checks).
func RateLimitWithSkip(max int, window time.Duration, skip func(*http.Request) bool, opts ...RateLimitOption) func(http.Handler) http.Handler {
	return arcischi.RateLimitWithSkip(max, window, skip, opts...)
}

// GetSanitizer retrieves the per-request Sanitizer that
// MiddlewareWithConfig stashes on the request context. Returns nil if
// the middleware was not in the chain or sanitization was disabled.
func GetSanitizer(r *http.Request) *arcis.Sanitizer {
	return arcischi.GetSanitizer(r)
}
