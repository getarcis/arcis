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

	"github.com/GagancM/arcis/core"
	"github.com/GagancM/arcis/logging"
	"github.com/GagancM/arcis/middleware"
	"github.com/GagancM/arcis/sanitizers"
	"github.com/GagancM/arcis/utils"
	"github.com/GagancM/arcis/validation"
)

// ─── Type aliases (backward compatibility) ──────────────────────────────────

// Core types
type Config = core.Config
type RateLimitResult = core.RateLimitResult
type RateLimitEntry = core.RateLimitEntry
type RateLimitStore = core.RateLimitStore
type InputTooLargeError = core.InputTooLargeError

// Sanitizer types
type Sanitizer = sanitizers.Sanitizer

// Middleware types
type RateLimiter = middleware.RateLimiter
type SecurityHeaders = middleware.SecurityHeaders
type ErrorHandler = middleware.ErrorHandler
type SafeCors = middleware.SafeCors
type CorsOptions = middleware.CorsOptions
type CorsOrigin = middleware.CorsOrigin
type CorsHeaders = middleware.CorsHeaders
type SecureCookieDefaults = middleware.SecureCookieDefaults
type SecureCookieOptions = middleware.SecureCookieOptions
type CsrfProtection = middleware.CsrfProtection
type CsrfOptions = middleware.CsrfOptions
type CsrfCookieOptions = middleware.CsrfCookieOptions

// Logging types
type SafeLogger = logging.SafeLogger

// Validation types
type FieldType = validation.FieldType
type FieldRule = validation.FieldRule
type ValidationSchema = validation.ValidationSchema
type ValidationError = validation.ValidationError
type Validator = validation.Validator

// URL/Redirect types
type ValidateURLOptions = utils.ValidateURLOptions
type ValidateURLResult = utils.ValidateURLResult
type ValidateRedirectOptions = utils.ValidateRedirectOptions
type ValidateRedirectResult = utils.ValidateRedirectResult

// ─── Constants (re-exported) ────────────────────────────────────────────────

const Version = core.Version
const MaxRecursionDepth = core.MaxRecursionDepth
const DefaultMaxInputSize = core.DefaultMaxInputSize

// Validation field type constants
const (
	TypeString  = validation.TypeString
	TypeNumber  = validation.TypeNumber
	TypeBoolean = validation.TypeBoolean
	TypeEmail   = validation.TypeEmail
	TypeURL     = validation.TypeURL
	TypeUUID    = validation.TypeUUID
	TypeArray   = validation.TypeArray
	TypeObject  = validation.TypeObject
)

// ─── Constructor re-exports ─────────────────────────────────────────────────

// DefaultConfig returns the default Arcis configuration.
var DefaultConfig = core.DefaultConfig

// NewSanitizer creates a new Sanitizer with the given configuration.
var NewSanitizer = sanitizers.NewSanitizer

// NewSanitizerWithOptions creates a sanitizer with explicit options.
var NewSanitizerWithOptions = sanitizers.NewSanitizerWithOptions

// NewRateLimiter creates a new RateLimiter with the given limit and window.
var NewRateLimiter = middleware.NewRateLimiter

// NewRateLimiterWithStore creates a new RateLimiter backed by the provided store.
var NewRateLimiterWithStore = middleware.NewRateLimiterWithStore

// NewSecurityHeaders creates a new SecurityHeaders with the given configuration.
var NewSecurityHeaders = middleware.NewSecurityHeaders

// NewErrorHandler creates a new ErrorHandler.
var NewErrorHandler = middleware.NewErrorHandler

// NewErrorHandlerWithLogger creates an ErrorHandler with a custom logger.
var NewErrorHandlerWithLogger = middleware.NewErrorHandlerWithLogger

// ContainsSensitiveInfo checks if an error message contains sensitive info.
var ContainsSensitiveInfo = middleware.ContainsSensitiveInfo

// NewSafeCors creates a SafeCors instance with the given options.
var NewSafeCors = middleware.NewSafeCors

// SafeCorsMiddleware creates a CORS http.Handler middleware from options.
var SafeCorsMiddleware = middleware.SafeCorsMiddleware

// NewSecureCookieDefaults creates a SecureCookieDefaults with the given options.
var NewSecureCookieDefaults = middleware.NewSecureCookieDefaults

// EnforceSecureCookie enforces secure defaults on a Set-Cookie header value.
var EnforceSecureCookie = middleware.EnforceSecureCookie

// SecureCookieMiddleware creates a secure cookie middleware from options.
var SecureCookieMiddleware = middleware.SecureCookieMiddleware

// NewCsrfProtection creates a CsrfProtection with the given options.
var NewCsrfProtection = middleware.NewCsrfProtection

// GenerateCsrfToken generates a cryptographically random CSRF token.
var GenerateCsrfToken = middleware.GenerateCsrfToken

// ValidateCsrfToken compares two CSRF tokens using constant-time comparison.
var ValidateCsrfToken = middleware.ValidateCsrfToken

// CsrfMiddleware creates a CSRF protection middleware from options.
var CsrfMiddleware = middleware.CsrfMiddleware

// NewSafeLogger creates a new SafeLogger with default settings.
var NewSafeLogger = logging.NewSafeLogger

// NewSafeLoggerWithKeys creates a SafeLogger with custom sensitive keys.
var NewSafeLoggerWithKeys = logging.NewSafeLoggerWithKeys

// NewSafeLoggerOnlyKeys creates a SafeLogger with ONLY the specified keys.
var NewSafeLoggerOnlyKeys = logging.NewSafeLoggerOnlyKeys

// NewValidator creates a new Validator with the given schema.
var NewValidator = validation.NewValidator

// ValidateHandler creates middleware that validates request body.
var ValidateHandler = validation.ValidateHandler

// GetValidatedBody retrieves the validated body from request context.
var GetValidatedBody = validation.GetValidatedBody

// Float is a helper for creating FieldRule with Min/Max.
var Float = validation.Float

// SanitizeHeaderValue strips CRLF/null bytes from a header value.
var SanitizeHeaderValue = sanitizers.SanitizeHeaderValue

// SanitizeHeaders sanitizes a map of HTTP header key-value pairs.
var SanitizeHeaders = sanitizers.SanitizeHeaders

// DetectHeaderInjection checks if a string contains header injection patterns.
var DetectHeaderInjection = sanitizers.DetectHeaderInjection

// ValidateURL checks a URL for SSRF safety.
var ValidateURL = utils.ValidateURL

// IsURLSafe is a convenience wrapper that returns true/false.
var IsURLSafe = utils.IsURLSafe

// ValidateRedirect checks a redirect URL for open redirect attacks.
var ValidateRedirect = utils.ValidateRedirect

// IsRedirectSafe is a convenience wrapper that returns true/false.
var IsRedirectSafe = utils.IsRedirectSafe

// GetClientIP extracts the client IP address from the request.
var GetClientIP = utils.GetClientIP

// ─── Arcis main struct ──────────────────────────────────────────────────────

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
