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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	arcis "github.com/GagancM/arcis"
	"github.com/GagancM/arcis/telemetry"
)

// scanRequestForThreats is a shared helper for block-mode middleware that
// peeks at JSON or form body, query, and URL path. Always restores the
// body and Content-Length so handlers can re-bind regardless of whether
// a threat was found, the body parsed, or the body was empty.
func scanRequestForThreats(req *http.Request) *arcis.ThreatHit {
	ct := req.Header.Get("Content-Type")
	if req.Body != nil && (strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/x-www-form-urlencoded")) {
		raw, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(raw))
			req.ContentLength = int64(len(raw))

			if len(raw) > 0 && strings.HasPrefix(ct, "application/json") {
				var parsed interface{}
				if json.Unmarshal(raw, &parsed) == nil {
					if hit := arcis.ScanThreats(parsed); hit != nil {
						return hit
					}
				}
			} else if len(raw) > 0 && strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
				if values, err := url.ParseQuery(string(raw)); err == nil {
					form := make(map[string]interface{}, len(values))
					for k, vals := range values {
						if len(vals) == 1 {
							form[k] = vals[0]
						} else {
							arr := make([]interface{}, len(vals))
							for i, v := range vals {
								arr[i] = v
							}
							form[k] = arr
						}
					}
					if hit := arcis.ScanThreats(form); hit != nil {
						return hit
					}
				}
			}
		}
	}
	q := map[string]interface{}{}
	for k, vals := range req.URL.Query() {
		if len(vals) == 1 {
			q[k] = vals[0]
		} else {
			arr := make([]interface{}, len(vals))
			for i, v := range vals {
				arr[i] = v
			}
			q[k] = arr
		}
	}
	if len(q) > 0 {
		if hit := arcis.ScanThreats(q); hit != nil {
			return hit
		}
	}
	if hit := arcis.ScanThreats(req.URL.Path); hit != nil {
		return hit
	}
	return nil
}

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

	// Block: when true, scan request body / query / URL path for attack
	// patterns and return 403 instead of running the handler. Opt-in.
	Block bool

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

	// Telemetry, if non-nil, receives one Event per request after the
	// middleware decision. Nil = zero overhead (no defer registered, no
	// allocations) per spec/API_SPEC.md §9 Guarantees.
	Telemetry *telemetry.Client
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

// RateLimitOption configures a standalone rate-limit middleware
// (RateLimit, RateLimitWithStore, RateLimitWithSkip). Use WithTelemetry
// to attach a telemetry client.
type RateLimitOption func(*rateLimitOpts)

type rateLimitOpts struct {
	telemetry *telemetry.Client
}

// WithTelemetry returns a RateLimitOption that attaches a telemetry
// client to a standalone rate-limit middleware. On 429, one
// TelemetryEvent is emitted with vector="rate-limit",
// rule="rate-limit/exceeded", severity="medium" — matching the
// MiddlewareWithConfig wire format.
//
// Standalone helpers emit only on deny. Allow events come from
// MiddlewareWithConfig; emitting them here would duplicate when
// composing RateLimit + Sanitizer + Validate with telemetry on each.
func WithTelemetry(tc *telemetry.Client) RateLimitOption {
	return func(o *rateLimitOpts) { o.telemetry = tc }
}

// emitRateLimitDeny ships one TelemetryEvent for a 429 from a standalone
// rate-limit helper. Callers register a deferred call so the latency
// includes the JSON write, matching MiddlewareWithConfig's measurement.
func emitRateLimitDeny(tc *telemetry.Client, c echo.Context, start time.Time) {
	if tc == nil {
		return
	}
	latency := float64(time.Since(start)) / float64(time.Millisecond)
	if latency < 0 {
		latency = 0
	}
	tc.Send(telemetry.Event{
		Ts:        time.Now().UTC().Format(time.RFC3339),
		IP:        c.RealIP(),
		Method:    c.Request().Method,
		Path:      c.Request().URL.Path,
		Decision:  telemetry.DecisionDeny,
		Vector:    "rate-limit",
		Rule:      "rate-limit/exceeded",
		Severity:  telemetry.SeverityMedium,
		Reason:    "Rate limit exceeded",
		UserAgent: c.Request().Header.Get("User-Agent"),
		Status:    http.StatusTooManyRequests,
		LatencyMs: latency,
	})
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
			start := time.Now()
			// Per-request telemetry locals. Deny branches mutate these
			// before returning; the deferred emit (registered only when
			// Telemetry is configured) reads them on function exit.
			var (
				decision    = telemetry.DecisionAllow
				evtVector   string
				evtRule     string
				evtMatched  string
				evtReason   string
				evtSeverity telemetry.Severity
			)
			if config.Telemetry != nil {
				defer func() {
					status := c.Response().Status
					if status == 0 {
						status = http.StatusOK
					}
					latency := float64(time.Since(start)) / float64(time.Millisecond)
					if latency < 0 {
						latency = 0
					}
					config.Telemetry.Send(telemetry.Event{
						Ts:             time.Now().UTC().Format(time.RFC3339),
						IP:             c.RealIP(),
						Method:         c.Request().Method,
						Path:           c.Request().URL.Path,
						Decision:       decision,
						Vector:         evtVector,
						Rule:           evtRule,
						MatchedPattern: evtMatched,
						Reason:         evtReason,
						Severity:       evtSeverity,
						UserAgent:      c.Request().Header.Get("User-Agent"),
						Status:         status,
						LatencyMs:      latency,
					})
				}()
			}

			// Skip function check for rate limiting
			skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

			if !skipRateLimit && rateLimiter != nil {
				result := rateLimiter.Check(c.Request())

				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

				if !result.Allowed {
					decision = telemetry.DecisionDeny
					evtVector = "rate-limit"
					evtRule = "rate-limit/exceeded"
					evtSeverity = telemetry.SeverityMedium
					evtReason = "Rate limit exceeded"

					c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
					return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
						"error":      "Too many requests, please try again later.",
						"retryAfter": int(result.Reset.Seconds()),
					})
				}
			}

			// Block mode: scan body / query / path for attack patterns.
			if config.Block {
				if hit := scanRequestForThreats(c.Request()); hit != nil {
					decision = telemetry.DecisionDeny
					evtVector = hit.Vector
					evtRule = hit.Rule
					evtMatched = hit.MatchedPattern
					evtSeverity = telemetry.SeverityHigh
					evtReason = "Detected " + hit.Vector + " pattern"

					return c.JSON(http.StatusForbidden, map[string]interface{}{
						"error":  "Request blocked for security reasons",
						"code":   "SECURITY_THREAT",
						"vector": hit.Vector,
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
// Pass arcisecho.WithTelemetry(tc) to emit a TelemetryEvent on 429.
func RateLimit(max int, window time.Duration, opts ...RateLimitOption) echo.MiddlewareFunc {
	return RateLimitWithSkip(max, window, nil, opts...)
}

// RateLimitWithStore returns a rate limiting middleware backed by a custom store.
// Use this to plug in a distributed backend such as Redis. Pass
// arcisecho.WithTelemetry(tc) to emit a TelemetryEvent on 429.
//
// Example:
//
//	store := myredis.NewStore(redisClient)
//	e.Use(arcisecho.RateLimitWithStore(100, time.Minute, store))
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore, opts ...RateLimitOption) echo.MiddlewareFunc {
	var o rateLimitOpts
	for _, opt := range opts {
		opt(&o)
	}

	limiter := arcis.NewRateLimiterWithStore(max, window, store)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			var didDeny bool
			if o.telemetry != nil {
				defer func() {
					if didDeny {
						emitRateLimitDeny(o.telemetry, c, start)
					}
				}()
			}

			result := limiter.Check(c.Request())

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				didDeny = true
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
// Pass arcisecho.WithTelemetry(tc) to emit a TelemetryEvent on 429.
func RateLimitWithSkip(max int, window time.Duration, skip func(echo.Context) bool, opts ...RateLimitOption) echo.MiddlewareFunc {
	var o rateLimitOpts
	for _, opt := range opts {
		opt(&o)
	}

	limiter := arcis.NewRateLimiter(max, window)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			var didDeny bool
			if o.telemetry != nil {
				defer func() {
					if didDeny {
						emitRateLimitDeny(o.telemetry, c, start)
					}
				}()
			}

			if skip != nil && skip(c) {
				return next(c)
			}

			result := limiter.Check(c.Request())

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				didDeny = true
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

// CsrfProtection returns an Echo middleware for CSRF protection using double-submit cookie.
func CsrfProtection(opts arcis.CsrfOptions) echo.MiddlewareFunc {
	csrf := arcis.NewCsrfProtection(opts)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Use the Check method directly
			method := c.Request().Method

			// Check excluded paths
			if csrf.Check(method, c.Request().URL.Path, "", "") && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
				// Safe method — ensure cookie exists
				if cookie, err := c.Request().Cookie("_csrf"); err != nil || cookie.Value == "" {
					token, err := arcis.GenerateCsrfToken(32)
					if err == nil {
						c.Response().Header().Add("Set-Cookie", buildEchoCsrfCookie(opts, token))
					}
				}
				return next(c)
			}

			// Protected method — validate
			cookieToken := ""
			if cookie, err := c.Request().Cookie(csrfCookieName(opts)); err == nil {
				cookieToken = cookie.Value
			}

			headerName := opts.HeaderName
			if headerName == "" {
				headerName = "X-Csrf-Token"
			}
			requestToken := c.Request().Header.Get(headerName)
			if requestToken == "" {
				fieldName := opts.FieldName
				if fieldName == "" {
					fieldName = "_csrf"
				}
				requestToken = c.QueryParam(fieldName)
			}

			if !csrf.Check(method, c.Request().URL.Path, cookieToken, requestToken) {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error":   "CSRF token validation failed",
					"message": "Invalid or missing CSRF token. Include the token from the cookie in the X-CSRF-Token header.",
				})
			}

			return next(c)
		}
	}
}

func csrfCookieName(opts arcis.CsrfOptions) string {
	if opts.CookieName != "" {
		return opts.CookieName
	}
	return "_csrf"
}

func buildEchoCsrfCookie(opts arcis.CsrfOptions, token string) string {
	name := csrfCookieName(opts)
	path := opts.Cookie.Path
	if path == "" {
		path = "/"
	}
	sameSite := opts.Cookie.SameSite
	if sameSite == "" {
		sameSite = "Lax"
	}
	parts := []string{name + "=" + token, "Path=" + path}
	if opts.Cookie.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	secure := true
	if opts.Cookie.Secure != nil {
		secure = *opts.Cookie.Secure
	}
	if secure {
		parts = append(parts, "Secure")
	}
	parts = append(parts, "SameSite="+sameSite)
	if opts.Cookie.Domain != "" {
		parts = append(parts, "Domain="+opts.Cookie.Domain)
	}
	return strings.Join(parts, "; ")
}

// SecureCookies returns an Echo middleware that enforces secure cookie defaults.
func SecureCookies(opts arcis.SecureCookieOptions) echo.MiddlewareFunc {
	sc := arcis.NewSecureCookieDefaults(opts)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)

			// Enforce on all Set-Cookie headers after handler runs
			cookies := c.Response().Header().Values("Set-Cookie")
			if len(cookies) > 0 {
				c.Response().Header().Del("Set-Cookie")
				for _, cookie := range cookies {
					c.Response().Header().Add("Set-Cookie", sc.Enforce(cookie))
				}
			}

			return err
		}
	}
}

// Cors returns an Echo middleware for safe CORS handling.
func Cors(opts arcis.CorsOptions) echo.MiddlewareFunc {
	cors := arcis.NewSafeCors(opts)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			origin := c.Request().Header.Get("Origin")
			headers := cors.GetHeaders(origin, c.Request().Method)

			for key, value := range headers {
				c.Response().Header().Set(key, value)
			}

			// Handle preflight
			if c.Request().Method == http.MethodOptions && origin != "" {
				if _, ok := headers["Access-Control-Allow-Origin"]; ok {
					return c.NoContent(http.StatusNoContent)
				}
			}

			return next(c)
		}
	}
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
