/*
Package gin provides Arcis middleware adapters for the Gin web framework.

Usage:

	import (
		"github.com/gin-gonic/gin"
		arcisgin "github.com/GagancM/arcis/gin"
	)

	func main() {
		r := gin.Default()

		// Full protection with defaults
		r.Use(arcisgin.Middleware())

		// Or with custom config
		r.Use(arcisgin.MiddlewareWithConfig(arcisgin.Config{
			RateLimitMax:    50,
			RateLimitWindow: time.Minute,
			CSP:             "default-src 'self'",
		}))

		// Granular middleware
		r.Use(arcisgin.Headers())
		r.Use(arcisgin.RateLimit(100, time.Minute))
		r.Use(arcisgin.Sanitizer())

		r.GET("/", handler)
		r.Run(":8080")
	}

# Resource Cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call Cleanup()
when your application shuts down to stop this goroutine and release resources:

	import (
		"context"
		"os/signal"
		"syscall"
		arcisgin "github.com/GagancM/arcis/gin"
	)

	func main() {
		r := gin.Default()
		r.Use(arcisgin.Middleware())

		// Graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go r.Run(":8080")

		<-ctx.Done()
		arcisgin.Cleanup() // Stop rate limiter background goroutines
	}

Alternatively, register cleanup with a defer or shutdown hook:

	func main() {
		defer arcisgin.Cleanup()
		// ... rest of setup
	}
*/
package gin

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	arcis "github.com/GagancM/arcis"
)

// Config holds Arcis middleware configuration for Gin.
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
	RateLimitSkip   func(*gin.Context) bool
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

// DefaultConfig returns the default Arcis configuration for Gin.
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
//		defer arcisgin.Cleanup()
//		r := gin.Default()
//		r.Use(arcisgin.Middleware())
//		r.Run(":8080")
//	}
//
// For graceful shutdown with signal handling:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	go r.Run(":8080")
//	<-ctx.Done()
//	arcisgin.Cleanup()
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

// Middleware returns a Gin middleware with default Arcis configuration.
func Middleware() gin.HandlerFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a Gin middleware with custom configuration.
func MiddlewareWithConfig(config Config) gin.HandlerFunc {
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

	return func(c *gin.Context) {
		// Skip function check for rate limiting
		skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

		if !skipRateLimit && rateLimiter != nil {
			result := rateLimiter.Check(c.Request)

			c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}
		}

		// Security headers
		if securityHeaders != nil {
			for key, value := range securityHeaders.GetHeaders() {
				c.Header(key, value)
			}
		}

		// Store sanitizer in context for use in handlers
		c.Set("arcis_sanitizer", sanitizer)

		c.Next()

		// Remove fingerprinting headers after handler runs
		c.Writer.Header().Del("Server")
		c.Writer.Header().Del("X-Powered-By")
	}
}

// Headers returns a middleware that only sets security headers.
func Headers() gin.HandlerFunc {
	return HeadersWithConfig(DefaultConfig())
}

// HeadersWithConfig returns a headers middleware with custom configuration.
func HeadersWithConfig(config Config) gin.HandlerFunc {
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

	return func(c *gin.Context) {
		for key, value := range headers.GetHeaders() {
			c.Header(key, value)
		}
		c.Next()
		c.Writer.Header().Del("Server")
		c.Writer.Header().Del("X-Powered-By")
	}
}

// RateLimit returns a middleware for rate limiting with specified limits.
func RateLimit(max int, window time.Duration) gin.HandlerFunc {
	return RateLimitWithSkip(max, window, nil)
}

// RateLimitWithStore returns a rate limiting middleware backed by a custom store.
// Use this to plug in a distributed backend such as Redis.
//
// Example:
//
//	store := myredis.NewStore(redisClient)
//	r.Use(arcisgin.RateLimitWithStore(100, time.Minute, store))
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore) gin.HandlerFunc {
	limiter := arcis.NewRateLimiterWithStore(max, window, store)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *gin.Context) {
		result := limiter.Check(c.Request)

		c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

		if !result.Allowed {
			c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
			return
		}

		c.Next()
	}
}

// RateLimitWithSkip returns a rate limiting middleware with custom skip function.
func RateLimitWithSkip(max int, window time.Duration, skip func(*gin.Context) bool) gin.HandlerFunc {
	limiter := arcis.NewRateLimiter(max, window)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *gin.Context) {
		if skip != nil && skip(c) {
			c.Next()
			return
		}

		result := limiter.Check(c.Request)

		c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

		if !result.Allowed {
			c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
			return
		}

		c.Next()
	}
}

// Sanitizer returns a middleware that provides sanitization utilities.
func Sanitizer() gin.HandlerFunc {
	return SanitizerWithConfig(DefaultConfig())
}

// SanitizerWithConfig returns a sanitizer middleware with custom configuration.
func SanitizerWithConfig(config Config) gin.HandlerFunc {
	arcisConfig := arcis.Config{
		SanitizeXSS:   config.SanitizeXSS,
		SanitizeSQL:   config.SanitizeSQL,
		SanitizeNoSQL: config.SanitizeNoSQL,
		SanitizePath:  config.SanitizePath,
		SanitizeCmd:   config.SanitizeCmd,
		MaxInputSize:  config.MaxInputSize,
	}

	sanitizer := arcis.NewSanitizer(arcisConfig)

	return func(c *gin.Context) {
		c.Set("arcis_sanitizer", sanitizer)
		c.Next()
	}
}

// GetSanitizer retrieves the Arcis sanitizer from the Gin context.
func GetSanitizer(c *gin.Context) *arcis.Sanitizer {
	if s, exists := c.Get("arcis_sanitizer"); exists {
		return s.(*arcis.Sanitizer)
	}
	return arcis.NewSanitizer(arcis.DefaultConfig())
}

// SanitizeJSON sanitizes JSON data using the sanitizer from context.
//
// Example:
//
//	func handler(c *gin.Context) {
//	    var data map[string]interface{}
//	    if err := c.ShouldBindJSON(&data); err != nil {
//	        c.JSON(400, gin.H{"error": err.Error()})
//	        return
//	    }
//	    data = arcisgin.SanitizeJSON(c, data)
//	    // Use sanitized data...
//	}
func SanitizeJSON(c *gin.Context, data map[string]interface{}) map[string]interface{} {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeMap(data)
}

// SanitizeString sanitizes a string value using the sanitizer from context.
func SanitizeString(c *gin.Context, value string) string {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeString(value)
}

// Validate creates a validation middleware using Arcis's validator.
func Validate(schema arcis.ValidationSchema) gin.HandlerFunc {
	validator := arcis.NewValidator(schema)

	return func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"errors": []string{"Invalid JSON"},
			})
			return
		}

		validated, validationErr := validator.Validate(data)
		if validationErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"errors": validationErr.Errors,
			})
			return
		}

		c.Set("validated_body", validated)
		c.Next()
	}
}

// GetValidatedBody retrieves the validated request body from the context.
func GetValidatedBody(c *gin.Context) map[string]interface{} {
	if v, exists := c.Get("validated_body"); exists {
		return v.(map[string]interface{})
	}
	return nil
}

// ErrorHandler returns a Gin error handler middleware.
func ErrorHandler(isDev bool) gin.HandlerFunc {
	handler := arcis.NewErrorHandler(isDev)

	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			statusCode := c.Writer.Status()
			if statusCode == 0 || statusCode == http.StatusOK {
				statusCode = http.StatusInternalServerError
			}
			handler.Handle(c.Writer, err, statusCode)
		}
	}
}
