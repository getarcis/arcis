/*
Package arcis provides one-line security for Go web applications.

Arcis is a comprehensive security middleware that provides:
  - Input sanitization (XSS, SQL injection, NoSQL injection, path traversal, command injection)
  - HTTP header injection prevention
  - SSRF (Server-Side Request Forgery) prevention
  - Open redirect prevention
  - Rate limiting with configurable windows and limits
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Request validation with schema support
  - Safe logging with sensitive data redaction
  - Production-safe error handling

Usage with net/http:

	import "github.com/GagancM/arcis"

	// Full protection (recommended)
	http.Handle("/", arcis.Protect(myHandler))

	// Or with custom config
	s := arcis.NewWithConfig(arcis.Config{
		RateLimitMax: 50,
		CSP: "default-src 'none'",
	})
	http.Handle("/", s.Handler(myHandler))

Usage with Gin:

	import "github.com/GagancM/arcis/gin"

	r := gin.Default()
	r.Use(arcisgin.Middleware())

Usage with Echo:

	import "github.com/GagancM/arcis/echo"

	e := echo.New()
	e.Use(arcisecho.Middleware())
*/
package arcis

import (
	"encoding/json"
	"net/http"
	"strconv"
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

// Arcis is the main security middleware.
type Arcis struct {
	config       Config
	sanitizer    *Sanitizer
	rateLimiter  *RateLimiter
	headers      *SecurityHeaders
	errorHandler *ErrorHandler
}

// New creates a new Arcis instance with default configuration.
func New() *Arcis {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new Arcis instance with custom configuration.
func NewWithConfig(config Config) *Arcis {
	s := &Arcis{config: config}

	if config.Sanitize {
		s.sanitizer = NewSanitizer(config)
	}

	if config.RateLimit {
		if config.RateLimitStore != nil {
			s.rateLimiter = NewRateLimiterWithStore(config.RateLimitMax, config.RateLimitWindow, config.RateLimitStore)
		} else {
			s.rateLimiter = NewRateLimiter(config.RateLimitMax, config.RateLimitWindow)
		}
		if config.RateLimitSkip != nil {
			s.rateLimiter.SetSkipFunc(config.RateLimitSkip)
		}
	}

	if config.Headers {
		s.headers = NewSecurityHeaders(config)
	}

	s.errorHandler = NewErrorHandler(config.IsDev)

	return s
}

// Protect wraps an http.Handler with Arcis protection using default config.
func Protect(handler http.Handler) http.Handler {
	return New().Handler(handler)
}

// Handler returns an http.Handler middleware.
func (s *Arcis) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		if s.rateLimiter != nil {
			result := s.rateLimiter.Check(r)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}
		}

		// Security headers
		if s.headers != nil {
			for key, value := range s.headers.GetHeaders() {
				w.Header().Set(key, value)
			}
		}

		// Remove fingerprinting headers
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		next.ServeHTTP(w, r)
	})
}

// Close gracefully shuts down the Arcis instance, cleaning up resources.
func (s *Arcis) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// Sanitize sanitizes a string value.
func (s *Arcis) Sanitize(value string) string {
	if s.sanitizer == nil {
		return value
	}
	return s.sanitizer.SanitizeString(value)
}

// SanitizeMap sanitizes a map (like JSON body).
func (s *Arcis) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	if s.sanitizer == nil {
		return data
	}
	return s.sanitizer.SanitizeMap(data)
}

// SanitizeBody reads, sanitizes, and returns JSON body from request.
func (s *Arcis) SanitizeBody(r *http.Request) (map[string]interface{}, error) {
	if s.sanitizer == nil {
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			return nil, err
		}
		return data, nil
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return s.sanitizer.SanitizeMap(data), nil
}
