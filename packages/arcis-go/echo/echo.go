/*
Package echo provides Arcis middleware adapters for the Echo web framework.

Usage:

	import (
		"github.com/labstack/echo/v4"
		arcisecho "github.com/GagancM/arcis/echo"
	)

	func main() {
		e := echo.New()

		// Full protection with defaults
		e.Use(arcisecho.Middleware())

		// Or with custom config
		e.Use(arcisecho.MiddlewareWithConfig(arcisecho.Config{
			RateLimitMax:    50,
			RateLimitWindow: time.Minute,
			CSP:             "default-src 'self'",
		}))

		// Granular middleware
		e.Use(arcisecho.Headers())
		e.Use(arcisecho.RateLimit(100, time.Minute))
		e.Use(arcisecho.Sanitizer())

		e.GET("/", handler)
		e.Start(":8080")
	}

# Resource Cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call Cleanup()
when your application shuts down to stop this goroutine and release resources:

	import (
		"context"
		"os/signal"
		"syscall"
		arcisecho "github.com/GagancM/arcis/echo"
	)

	func main() {
		e := echo.New()
		e.Use(arcisecho.Middleware())

		// Graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go e.Start(":8080")

		<-ctx.Done()
		e.Shutdown(context.Background())
		arcisecho.Cleanup() // Stop rate limiter background goroutines
	}

Alternatively, register cleanup with a defer or shutdown hook:

	func main() {
		defer arcisecho.Cleanup()
		// ... rest of setup
	}
*/
package echo

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	arcis "github.com/GagancM/arcis"
)

// Config holds Arcis middleware configuration for Echo.
type Config struct {
	// Sanitizer options
	Sanitize      bool
	SanitizeXSS   bool
	SanitizeSQL   bool
	SanitizeNoSQL bool
	SanitizePath  bool
	SanitizeCmd   bool
	MaxInputSize  int

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(echo.Context) bool
	RateLimitStore  arcis.RateLimitStore // Optional external store (e.g. Redis)

	// Security headers options
	Headers           bool
	CSP               string
	FrameOptions      string
	HSTSMaxAge        int
	HSTSSubdomains    bool
	ReferrerPolicy    string
	PermissionsPolicy string
	CacheControl      bool
	CacheControlValue string // Custom Cache-Control value. Empty = use secure default.

	// Error handler options
	IsDev bool
}

// DefaultConfig returns the default Arcis configuration for Echo.
func DefaultConfig() Config {
	return Config{
		Sanitize:          true,
		SanitizeXSS:       true,
		SanitizeSQL:       true,
		SanitizeNoSQL:     true,
		SanitizePath:      true,
		SanitizeCmd:       true,
		MaxInputSize:      1000000,
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

// Context key for Arcis components
const (
	SanitizerKey     = "arcis_sanitizer"
	ValidatedBodyKey = "arcis_validated_body"
)

// arcisInstance holds the Arcis components for cleanup.
type arcisInstance struct {
	rateLimiter *arcis.RateLimiter
}

// Close cleans up Arcis resources, stopping the rate limiter's
// background cleanup goroutine.
func (s *arcisInstance) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// activeInstances tracks Arcis instances for cleanup.
var (
	activeInstances   []*arcisInstance
	activeInstancesMu sync.Mutex
)

// Cleanup closes all active Arcis middleware instances and releases resources.
// This stops the background goroutines used by rate limiters for automatic
// cleanup of expired entries.
//
// Call Cleanup() when your application shuts down to prevent goroutine leaks.
// This is especially important in long-running applications or when using
// hot-reloading during development.
//
// Example:
//
//	func main() {
//		defer arcisecho.Cleanup()
//		e := echo.New()
//		e.Use(arcisecho.Middleware())
//		e.Start(":8080")
//	}
//
// For graceful shutdown with signal handling:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	go e.Start(":8080")
//	<-ctx.Done()
//	e.Shutdown(context.Background())
//	arcisecho.Cleanup()
func Cleanup() {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	for _, instance := range activeInstances {
		instance.Close()
	}
	activeInstances = nil
}

// registerInstance safely adds an instance to the active instances list.
func registerInstance(instance *arcisInstance) {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	activeInstances = append(activeInstances, instance)
}

// Middleware returns an Echo middleware with default Arcis configuration.
func Middleware() echo.MiddlewareFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns an Echo middleware with custom configuration.
func MiddlewareWithConfig(config Config) echo.MiddlewareFunc {
	// Convert to core Arcis config
	arcisConfig := arcis.Config{
		Sanitize:          config.Sanitize,
		SanitizeXSS:       config.SanitizeXSS,
		SanitizeSQL:       config.SanitizeSQL,
		SanitizeNoSQL:     config.SanitizeNoSQL,
		SanitizePath:      config.SanitizePath,
		SanitizeCmd:       config.SanitizeCmd,
		MaxInputSize:      config.MaxInputSize,
		RateLimit:         config.RateLimit,
		RateLimitMax:      config.RateLimitMax,
		RateLimitWindow:   config.RateLimitWindow,
		Headers:           config.Headers,
		CSP:               config.CSP,
		FrameOptions:      config.FrameOptions,
		HSTSMaxAge:        config.HSTSMaxAge,
		HSTSSubdomains:    config.HSTSSubdomains,
		ReferrerPolicy:    config.ReferrerPolicy,
		PermissionsPolicy: config.PermissionsPolicy,
		CacheControl:      config.CacheControl,
		CacheControlValue: config.CacheControlValue,
		IsDev:             config.IsDev,
	}

	sanitizer := arcis.NewSanitizer(arcisConfig)
	instance := &arcisInstance{}

	var rateLimiter *arcis.RateLimiter
	if config.RateLimit {
		if config.RateLimitStore != nil {
			rateLimiter = arcis.NewRateLimiterWithStore(config.RateLimitMax, config.RateLimitWindow, config.RateLimitStore)
		} else {
			rateLimiter = arcis.NewRateLimiter(config.RateLimitMax, config.RateLimitWindow)
		}
		instance.rateLimiter = rateLimiter
	}

	var securityHeaders *arcis.SecurityHeaders
	if config.Headers {
		securityHeaders = arcis.NewSecurityHeaders(arcisConfig)
	}

	registerInstance(instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip function check for rate limiting
			skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

			if !skipRateLimit && rateLimiter != nil {
				result := rateLimiter.Check(c.Request())

				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

				if !result.Allowed {
					c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
					return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
						"error":      "Too many requests, please try again later.",
						"retryAfter": int(result.Reset.Seconds()),
					})
				}
			}

			// Security headers
			if securityHeaders != nil {
				for key, value := range securityHeaders.GetHeaders() {
					c.Response().Header().Set(key, value)
				}
			}

			// Store sanitizer in context for use in handlers
			c.Set(SanitizerKey, sanitizer)

			err := next(c)

			// Remove fingerprinting headers after handler runs
			c.Response().Header().Del("Server")
			c.Response().Header().Del("X-Powered-By")

			return err
		}
	}
}

// Headers returns a middleware that only sets security headers.
func Headers() echo.MiddlewareFunc {
	return HeadersWithConfig(DefaultConfig())
}

// HeadersWithConfig returns a headers middleware with custom configuration.
func HeadersWithConfig(config Config) echo.MiddlewareFunc {
	arcisConfig := arcis.Config{
		CSP:               config.CSP,
		FrameOptions:      config.FrameOptions,
		HSTSMaxAge:        config.HSTSMaxAge,
		HSTSSubdomains:    config.HSTSSubdomains,
		ReferrerPolicy:    config.ReferrerPolicy,
		PermissionsPolicy: config.PermissionsPolicy,
		CacheControl:      config.CacheControl,
		CacheControlValue: config.CacheControlValue,
	}

	headers := arcis.NewSecurityHeaders(arcisConfig)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			for key, value := range headers.GetHeaders() {
				c.Response().Header().Set(key, value)
			}
			err := next(c)
			c.Response().Header().Del("Server")
			c.Response().Header().Del("X-Powered-By")
			return err
		}
	}
}

// RateLimit returns a middleware for rate limiting with specified limits.
func RateLimit(max int, window time.Duration) echo.MiddlewareFunc {
	return RateLimitWithSkip(max, window, nil)
}

// RateLimitWithStore returns a rate limiting middleware backed by a custom store.
// Use this to plug in a distributed backend such as Redis.
//
// Example:
//
//	store := myredis.NewStore(redisClient)
//	e.Use(arcisecho.RateLimitWithStore(100, time.Minute, store))
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore) echo.MiddlewareFunc {
	limiter := arcis.NewRateLimiterWithStore(max, window, store)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			result := limiter.Check(c.Request())

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
			}

			return next(c)
		}
	}
}

// RateLimitWithSkip returns a rate limiting middleware with custom skip function.
func RateLimitWithSkip(max int, window time.Duration, skip func(echo.Context) bool) echo.MiddlewareFunc {
	limiter := arcis.NewRateLimiter(max, window)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skip != nil && skip(c) {
				return next(c)
			}

			result := limiter.Check(c.Request())

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
			}

			return next(c)
		}
	}
}

// Sanitizer returns a middleware that provides sanitization utilities.
func Sanitizer() echo.MiddlewareFunc {
	return SanitizerWithConfig(DefaultConfig())
}

// SanitizerWithConfig returns a sanitizer middleware with custom configuration.
func SanitizerWithConfig(config Config) echo.MiddlewareFunc {
	arcisConfig := arcis.Config{
		SanitizeXSS:   config.SanitizeXSS,
		SanitizeSQL:   config.SanitizeSQL,
		SanitizeNoSQL: config.SanitizeNoSQL,
		SanitizePath:  config.SanitizePath,
		SanitizeCmd:   config.SanitizeCmd,
		MaxInputSize:  config.MaxInputSize,
	}

	sanitizer := arcis.NewSanitizer(arcisConfig)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(SanitizerKey, sanitizer)
			return next(c)
		}
	}
}

// GetSanitizer retrieves the Arcis sanitizer from the Echo context.
func GetSanitizer(c echo.Context) *arcis.Sanitizer {
	if s := c.Get(SanitizerKey); s != nil {
		return s.(*arcis.Sanitizer)
	}
	return arcis.NewSanitizer(arcis.DefaultConfig())
}

// SanitizeJSON sanitizes JSON data using the sanitizer from context.
//
// Example:
//
//	func handler(c echo.Context) error {
//	    var data map[string]interface{}
//	    if err := c.Bind(&data); err != nil {
//	        return c.JSON(400, map[string]string{"error": err.Error()})
//	    }
//	    data = arcisecho.SanitizeJSON(c, data)
//	    // Use sanitized data...
//	}
func SanitizeJSON(c echo.Context, data map[string]interface{}) map[string]interface{} {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeMap(data)
}

// SanitizeString sanitizes a string value using the sanitizer from context.
func SanitizeString(c echo.Context, value string) string {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeString(value)
}

// Validate creates a validation middleware using Arcis's validator.
func Validate(schema arcis.ValidationSchema) echo.MiddlewareFunc {
	validator := arcis.NewValidator(schema)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var data map[string]interface{}
			if err := c.Bind(&data); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]interface{}{
					"errors": []string{"Invalid JSON"},
				})
			}

			validated, validationErr := validator.Validate(data)
			if validationErr != nil {
				return c.JSON(http.StatusBadRequest, map[string]interface{}{
					"errors": validationErr.Errors,
				})
			}

			c.Set(ValidatedBodyKey, validated)
			return next(c)
		}
	}
}

// GetValidatedBody retrieves the validated request body from the context.
func GetValidatedBody(c echo.Context) map[string]interface{} {
	if v := c.Get(ValidatedBodyKey); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

// ErrorHandler returns an Echo error handler function.
// Use with e.HTTPErrorHandler = arcisecho.ErrorHandler(isDev)
func ErrorHandler(isDev bool) echo.HTTPErrorHandler {
	handler := arcis.NewErrorHandler(isDev)

	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		statusCode := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			statusCode = he.Code
		}

		handler.Handle(c.Response().Writer, err, statusCode)
	}
}

// ErrorMiddleware returns middleware that catches errors and handles them safely.
func ErrorMiddleware(isDev bool) echo.MiddlewareFunc {
	handler := arcis.NewErrorHandler(isDev)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)
			if err != nil {
				statusCode := http.StatusInternalServerError
				if he, ok := err.(*echo.HTTPError); ok {
					statusCode = he.Code
				}
				handler.Handle(c.Response().Writer, err, statusCode)
				return nil // Error has been handled
			}
			return nil
		}
	}
}
