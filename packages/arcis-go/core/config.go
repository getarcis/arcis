package core

import (
	"fmt"
	"net/http"
	"time"
)

// Version is the current version of Arcis.
const Version = "1.1.0"

// MaxRecursionDepth is the maximum depth for recursive operations.
const MaxRecursionDepth = 10

// DefaultMaxInputSize is the default maximum input size in bytes (1MB).
const DefaultMaxInputSize = 1_000_000

// Config holds Arcis configuration options.
type Config struct {
	// Sanitizer options
	Sanitize      bool
	SanitizeXSS   bool
	SanitizeSQL   bool
	SanitizeNoSQL bool
	SanitizePath  bool
	SanitizeCmd   bool // Command injection protection
	MaxInputSize  int  // Maximum input size in bytes (default: 1MB)

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*http.Request) bool // Skip rate limiting for certain requests
	RateLimitStore  RateLimitStore           // Optional external store (e.g. Redis)

	// Security headers options
	Headers           bool
	CSP               string
	FrameOptions      string // DENY, SAMEORIGIN, or empty to disable
	HSTSMaxAge        int    // Max age in seconds, 0 to disable
	HSTSSubdomains    bool
	ReferrerPolicy    string
	PermissionsPolicy string
	CacheControl      bool   // Enable cache-control headers (default: true)
	CacheControlValue string // Custom Cache-Control value. Empty = use secure default.

	// Error handler options
	IsDev bool // Show error details in development mode
}

// DefaultConfig returns the default Arcis configuration.
// All protections are enabled with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Sanitize:          true,
		SanitizeXSS:       true,
		SanitizeSQL:       true,
		SanitizeNoSQL:     true,
		SanitizePath:      true,
		SanitizeCmd:       true,
		MaxInputSize:      DefaultMaxInputSize,
		RateLimit:         true,
		RateLimitMax:      100,
		RateLimitWindow:   time.Minute,
		Headers:           true,
		CSP:               "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
		FrameOptions:      "DENY",
		HSTSMaxAge:        31536000,
		HSTSSubdomains:    true,
		ReferrerPolicy:    "strict-origin-when-cross-origin",
		PermissionsPolicy: "geolocation=(), microphone=(), camera=()",
		CacheControl:      true,
		IsDev:             false,
	}
}

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

// InputTooLargeError is returned when input exceeds the maximum size.
type InputTooLargeError struct {
	Size    int
	MaxSize int
}

func (e *InputTooLargeError) Error() string {
	return fmt.Sprintf("input size %d exceeds maximum of %d bytes", e.Size, e.MaxSize)
}
