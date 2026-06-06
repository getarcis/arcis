/*
Package fiber provides Arcis middleware adapters for the gofiber/fiber
v2 web framework (sdk-vectors.md G3 / P2 #27).

Fiber v2's middleware shape is `func(c *fiber.Ctx) error`. This package
ships a bundle middleware that runs the Arcis pipeline (rate limit +
block-mode threat scan + security headers + sanitizer in context) and
standalone RateLimit helpers + WithTelemetry option.

Surface available today: Middleware / MiddlewareWithConfig / RateLimit /
RateLimitWithStore / RateLimitWithSkip / GetSanitizer / WithTelemetry.
The granular Headers / Sanitizer / Validate / CsrfProtection /
SecureCookies / Cors / ErrorHandler helpers that gin / echo / chi expose
are NOT yet ported to the Fiber adapter — they land in v1.7. For
granular composition today, use chi (which is stdlib-compatible with
any router that accepts func(http.Handler) http.Handler).

Usage:

	import (
		"github.com/gofiber/fiber/v2"
		arcisfiber "github.com/getarcis/arcis/v2/fiber"
	)

	func main() {
		app := fiber.New()
		cfg := arcisfiber.DefaultConfig()
		cfg.Block = true
		app.Use(arcisfiber.MiddlewareWithConfig(cfg))
		app.Get("/", handler)
		app.Listen(":8080")
	}

# Resource cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call
Cleanup() at application shutdown to stop it:

	defer arcisfiber.Cleanup()
*/
package fiber

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	arcis "github.com/getarcis/arcis/v2"
	"github.com/getarcis/arcis/v2/telemetry"
)

// scanFiberCtxForThreats peeks at JSON body, query params, and URL path
// for the block-mode middleware. Returns the first hit or nil.
//
// Duplicates the gin / echo / chi `scanRequestForThreats` helpers.
// The owned-files boundary blocks consolidation here; a future janitor
// pass can extract this into `internal/scanutil/`.
func scanFiberCtxForThreats(c *fiber.Ctx) *arcis.ThreatHit {
	ct := c.Get(fiber.HeaderContentType)
	if strings.HasPrefix(ct, fiber.MIMEApplicationJSON) {
		raw := c.Body()
		if len(raw) > 0 {
			var parsed interface{}
			if json.Unmarshal(raw, &parsed) == nil {
				if hit := arcis.ScanThreats(parsed); hit != nil {
					return hit
				}
			}
		}
	} else if strings.HasPrefix(ct, fiber.MIMEApplicationForm) {
		raw := c.Body()
		if len(raw) > 0 {
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

	// Query string. Fiber surfaces this as a Queries() map of single
	// strings; convert to the interface{} shape ScanThreats expects.
	q := map[string]interface{}{}
	for k, v := range c.Queries() {
		q[k] = v
	}
	if len(q) > 0 {
		if hit := arcis.ScanThreats(q); hit != nil {
			return hit
		}
	}
	if hit := arcis.ScanThreats(c.Path()); hit != nil {
		return hit
	}
	return nil
}

// Config holds Arcis middleware configuration for Fiber.
//
// Mirrors the chi/gin/echo Config one-for-one so users can copy a known-
// good config across adapters without learning a new field set.
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
	// patterns and respond 403 instead of running the handler. Opt-in.
	Block bool

	// DryRun: when true (and Block is also true), run the block-mode
	// detection pipeline but do NOT respond 403. The threat is logged +
	// the OnSanitize callback fires + telemetry records the would-have-
	// blocked decision. Use for safe rollout.
	DryRun bool

	// OnSanitize fires when a threat is detected in block mode. Receives
	// a SanitizeEvent describing the vector + path. Must not panic; the
	// middleware swallows panics via defer/recover.
	OnSanitize func(SanitizeEvent)

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*fiber.Ctx) bool
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
	CacheControlValue string

	// Error handler options
	IsDev bool

	// Telemetry: optional client. When set, MiddlewareWithConfig emits
	// one TelemetryEvent per request (allow + deny). Standalone
	// RateLimit* helpers wire telemetry via WithTelemetry (deny-only).
	Telemetry *telemetry.Client
}

// DefaultConfig returns the default Arcis configuration for Fiber.
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

// SanitizeEvent is the payload passed to Config.OnSanitize when a
// block-mode scan matches a threat. DryRun indicates whether the request
// was actually denied or only logged.
type SanitizeEvent struct {
	Vector  string
	Rule    string
	Matched string
	Path    string
	DryRun  bool
}

// arcisInstance holds the Arcis components for cleanup.
type arcisInstance struct {
	rateLimiter *arcis.RateLimiter
}

func (s *arcisInstance) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

var (
	activeInstances   []*arcisInstance
	activeInstancesMu sync.Mutex
)

// Cleanup closes all active Arcis middleware instances and releases
// resources. Stops the rate limiter background goroutine. Safe to call
// multiple times.
func Cleanup() {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	for _, inst := range activeInstances {
		inst.Close()
	}
	activeInstances = nil
}

func registerInstance(inst *arcisInstance) {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	activeInstances = append(activeInstances, inst)
}

// RateLimitOption configures a standalone rate-limit middleware. Use
// WithTelemetry to attach a telemetry client.
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

func emitRateLimitDeny(tc *telemetry.Client, c *fiber.Ctx, start time.Time) {
	if tc == nil {
		return
	}
	latency := float64(time.Since(start)) / float64(time.Millisecond)
	if latency < 0 {
		latency = 0
	}
	tc.Send(telemetry.Event{
		Ts:        time.Now().UTC().Format(time.RFC3339),
		IP:        c.IP(),
		Method:    c.Method(),
		Path:      c.Path(),
		Decision:  telemetry.DecisionDeny,
		Vector:    "rate-limit",
		Rule:      "rate-limit/exceeded",
		Reason:    "Rate limit exceeded",
		Severity:  telemetry.SeverityMedium,
		UserAgent: c.Get(fiber.HeaderUserAgent),
		Status:    fiber.StatusTooManyRequests,
		LatencyMs: latency,
	})
}

// Middleware returns a Fiber middleware with default Arcis configuration.
func Middleware() fiber.Handler {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a Fiber middleware with custom config.
func MiddlewareWithConfig(config Config) fiber.Handler {
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

	return func(c *fiber.Ctx) error {
		start := time.Now()
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
				latency := float64(time.Since(start)) / float64(time.Millisecond)
				if latency < 0 {
					latency = 0
				}
				config.Telemetry.Send(telemetry.Event{
					Ts:             time.Now().UTC().Format(time.RFC3339),
					IP:             c.IP(),
					Method:         c.Method(),
					Path:           c.Path(),
					Decision:       decision,
					Vector:         evtVector,
					Rule:           evtRule,
					MatchedPattern: evtMatched,
					Reason:         evtReason,
					Severity:       evtSeverity,
					UserAgent:      c.Get(fiber.HeaderUserAgent),
					Status:         c.Response().StatusCode(),
					LatencyMs:      latency,
				})
			}()
		}

		// Skip function check for rate limiting
		skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

		if !skipRateLimit && rateLimiter != nil {
			// Use CheckKey directly with fiber's c.IP() so we don't
			// have to build a synthetic *http.Request just for the
			// IP read. c.IP() honours fiber's TrustedProxies config
			// when configured.
			result := rateLimiter.CheckKey(c.IP())

			c.Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				decision = telemetry.DecisionDeny
				evtVector = "rate-limit"
				evtRule = "rate-limit/exceeded"
				evtSeverity = telemetry.SeverityMedium
				evtReason = "Rate limit exceeded"

				c.Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
			}
		}

		if config.Block {
			if hit := scanFiberCtxForThreats(c); hit != nil {
				if config.DryRun {
					decision = telemetry.Decision("would_deny")
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = hit.Vector
				evtRule = hit.Rule
				evtMatched = hit.MatchedPattern
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Detected " + hit.Vector + " pattern"

				if config.OnSanitize != nil {
					func() {
						defer func() { _ = recover() }()
						config.OnSanitize(SanitizeEvent{
							Vector:  hit.Vector,
							Rule:    hit.Rule,
							Matched: hit.MatchedPattern,
							Path:    c.Path(),
							DryRun:  config.DryRun,
						})
					}()
				}

				if !config.DryRun {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":  "Request blocked for security reasons",
						"code":   "SECURITY_THREAT",
						"vector": hit.Vector,
					})
				}
			}
		}

		if securityHeaders != nil {
			for key, value := range securityHeaders.GetHeaders() {
				c.Set(key, value)
			}
		}

		// Stash the sanitizer in c.Locals so handlers can pull it back
		// via GetSanitizer(c).
		c.Locals(sanitizerLocalKey, sanitizer)

		if err := c.Next(); err != nil {
			return err
		}

		// Strip fingerprinting headers AFTER the handler ran.
		c.Response().Header.Del("Server")
		c.Response().Header.Del("X-Powered-By")
		return nil
	}
}

// sanitizerLocalKey is the c.Locals key for the per-request Sanitizer.
// Exported only as an unexported string to avoid collision with any
// user-set local; the GetSanitizer accessor is the public surface.
const sanitizerLocalKey = "arcis_sanitizer"

// GetSanitizer retrieves the per-request Sanitizer that
// MiddlewareWithConfig stashes on the request context. Returns a
// default sanitizer when the middleware was not in the chain (matches
// the gin / echo / chi GetSanitizer behavior — handlers stay
// panic-safe). The default config enables every vector.
func GetSanitizer(c *fiber.Ctx) *arcis.Sanitizer {
	v := c.Locals(sanitizerLocalKey)
	if v == nil {
		return arcis.NewSanitizer(arcis.DefaultConfig())
	}
	if s, ok := v.(*arcis.Sanitizer); ok {
		return s
	}
	return arcis.NewSanitizer(arcis.DefaultConfig())
}

// Standalone rate-limit middleware. Composes with the fiber pipeline
// for users who want fine-grained control: pair `RateLimit` with the
// granular `Headers` / `Sanitizer` helpers (or hand-rolled middleware)
// instead of the bundle `Middleware`.

// RateLimit returns a standalone rate-limit middleware. Optional
// WithTelemetry attaches a telemetry client that emits on 429.
func RateLimit(max int, window time.Duration, opts ...RateLimitOption) fiber.Handler {
	return rateLimitWithLimiter(arcis.NewRateLimiter(max, window), opts...)
}

// RateLimitWithStore returns a rate-limit middleware backed by an
// external store (Redis, etc.).
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore, opts ...RateLimitOption) fiber.Handler {
	return rateLimitWithLimiter(arcis.NewRateLimiterWithStore(max, window, store), opts...)
}

// RateLimitWithSkip returns a rate-limit middleware that skips counting
// requests for which `skip(c)` returns true (e.g., health checks).
func RateLimitWithSkip(max int, window time.Duration, skip func(*fiber.Ctx) bool, opts ...RateLimitOption) fiber.Handler {
	limiter := arcis.NewRateLimiter(max, window)
	options := &rateLimitOpts{}
	for _, opt := range opts {
		opt(options)
	}
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *fiber.Ctx) error {
		if skip != nil && skip(c) {
			return c.Next()
		}
		start := time.Now()
		result := limiter.CheckKey(c.IP())
		c.Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))
		if !result.Allowed {
			emitRateLimitDeny(options.telemetry, c, start)
			c.Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
		}
		return c.Next()
	}
}

// rateLimitWithLimiter is the shared body of RateLimit and
// RateLimitWithStore so option-parsing and telemetry hookup stay in
// one place.
func rateLimitWithLimiter(limiter *arcis.RateLimiter, opts ...RateLimitOption) fiber.Handler {
	options := &rateLimitOpts{}
	for _, opt := range opts {
		opt(options)
	}
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *fiber.Ctx) error {
		start := time.Now()
		result := limiter.CheckKey(c.IP())
		c.Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))
		if !result.Allowed {
			emitRateLimitDeny(options.telemetry, c, start)
			c.Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
		}
		return c.Next()
	}
}
