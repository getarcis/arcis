/*
Package chi provides Arcis middleware adapters for the go-chi router.

Chi middleware is a stdlib http.Handler decorator
(`func(next http.Handler) http.Handler`), so this package's surface uses
plain net/http types — `*http.Request`, `http.ResponseWriter`, and
`context.Context`. The result composes with any router that accepts
stdlib middleware, not just chi.

Usage:

	import (
		"github.com/go-chi/chi/v5"
		arcischi "github.com/GagancM/arcis/chi"
	)

	func main() {
		r := chi.NewRouter()

		// Full protection with defaults
		r.Use(arcischi.Middleware())

		// Or with custom config
		r.Use(arcischi.MiddlewareWithConfig(arcischi.Config{
			RateLimitMax:    50,
			RateLimitWindow: time.Minute,
			CSP:             "default-src 'self'",
		}))

		// Granular rate-limit middleware with optional telemetry
		r.Use(arcischi.RateLimit(100, time.Minute, arcischi.WithTelemetry(tc)))

		r.Get("/", handler)
		http.ListenAndServe(":8080", r)
	}

# Resource Cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call Cleanup()
when your application shuts down to stop this goroutine and release resources:

	import (
		"context"
		"net/http"
		"os/signal"
		"syscall"
		arcischi "github.com/GagancM/arcis/chi"
	)

	func main() {
		r := chi.NewRouter()
		r.Use(arcischi.Middleware())

		srv := &http.Server{Addr: ":8080", Handler: r}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go srv.ListenAndServe()

		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
		arcischi.Cleanup()
	}
*/
package chi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	arcis "github.com/GagancM/arcis"
	"github.com/GagancM/arcis/telemetry"
)

// scanRequestForThreats peeks at JSON or form body, query, and URL path
// for the block-mode middleware. Returns the first hit or nil. Restores
// the request body unconditionally so the handler can re-bind regardless
// of whether a threat was found, the body parsed, or the body was empty.
//
// Duplicated (byte-for-byte) from gin/gin.go and echo/echo.go. The owned-
// files boundary blocks consolidation here; a future janitor pass can
// extract this to packages/arcis-go/internal/scanutil/ in one cross-cutting
// commit that touches all three adapters together.
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

// clientIP returns the request's client IP. Honors X-Forwarded-For (first
// comma-separated value) then X-Real-IP, falling back to the host portion
// of RemoteAddr. Mirrors gin's ClientIP() and echo's RealIP() so the
// telemetry IP field stays consistent across adapters.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// statusWriter wraps http.ResponseWriter to capture the response status
// code for telemetry on the allow path (where the handler may write any
// status). Initial value http.StatusOK preserves stdlib semantics: if the
// handler calls Write without an explicit WriteHeader, net/http implicitly
// sends a 200 — so the telemetry event reports 200 too.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
		s.ResponseWriter.WriteHeader(code)
	}
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// Config holds Arcis middleware configuration for chi.
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

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*http.Request) bool
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

	// Telemetry: optional client. When set, MiddlewareWithConfig emits one
	// TelemetryEvent per request (allow + deny). Standalone RateLimit*
	// helpers wire telemetry via the WithTelemetry option (deny-only).
	Telemetry *telemetry.Client
}

// DefaultConfig returns the default Arcis configuration for chi.
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

// Cleanup closes all active Arcis middleware instances and releases
// resources. Stops background goroutines used by rate limiters for
// expired-entry cleanup.
//
// Call Cleanup() when your application shuts down to prevent goroutine
// leaks. Especially important in long-running applications or when using
// hot-reloading during development.
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
func emitRateLimitDeny(tc *telemetry.Client, r *http.Request, start time.Time) {
	if tc == nil {
		return
	}
	latency := float64(time.Since(start)) / float64(time.Millisecond)
	if latency < 0 {
		latency = 0
	}
	tc.Send(telemetry.Event{
		Ts:        time.Now().UTC().Format(time.RFC3339),
		IP:        clientIP(r),
		Method:    r.Method,
		Path:      r.URL.Path,
		Decision:  telemetry.DecisionDeny,
		Vector:    "rate-limit",
		Rule:      "rate-limit/exceeded",
		Severity:  telemetry.SeverityMedium,
		Reason:    "Rate limit exceeded",
		UserAgent: r.Header.Get("User-Agent"),
		Status:    http.StatusTooManyRequests,
		LatencyMs: latency,
	})
}

// writeJSON writes a JSON body with the supplied status. Errors from the
// encoder are intentionally ignored — the response is already committed
// at the wire level by the time encoding fails.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Middleware returns a chi-compatible middleware with default Arcis configuration.
func Middleware() func(http.Handler) http.Handler {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a chi-compatible middleware with custom configuration.
func MiddlewareWithConfig(config Config) func(http.Handler) http.Handler {
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
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
					status := sw.status
					if status == 0 {
						status = http.StatusOK
					}
					latency := float64(time.Since(start)) / float64(time.Millisecond)
					if latency < 0 {
						latency = 0
					}
					config.Telemetry.Send(telemetry.Event{
						Ts:             time.Now().UTC().Format(time.RFC3339),
						IP:             clientIP(r),
						Method:         r.Method,
						Path:           r.URL.Path,
						Decision:       decision,
						Vector:         evtVector,
						Rule:           evtRule,
						MatchedPattern: evtMatched,
						Reason:         evtReason,
						Severity:       evtSeverity,
						UserAgent:      r.Header.Get("User-Agent"),
						Status:         status,
						LatencyMs:      latency,
					})
				}()
			}

			skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(r)

			if !skipRateLimit && rateLimiter != nil {
				result := rateLimiter.Check(r)

				sw.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				sw.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				sw.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

				if !result.Allowed {
					decision = telemetry.DecisionDeny
					evtVector = "rate-limit"
					evtRule = "rate-limit/exceeded"
					evtSeverity = telemetry.SeverityMedium
					evtReason = "Rate limit exceeded"

					sw.Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
					writeJSON(sw, http.StatusTooManyRequests, map[string]interface{}{
						"error":      "Too many requests, please try again later.",
						"retryAfter": int(result.Reset.Seconds()),
					})
					return
				}
			}

			if config.Block {
				if hit := scanRequestForThreats(r); hit != nil {
					decision = telemetry.DecisionDeny
					evtVector = hit.Vector
					evtRule = hit.Rule
					evtMatched = hit.MatchedPattern
					evtSeverity = telemetry.SeverityHigh
					evtReason = "Detected " + hit.Vector + " pattern"

					writeJSON(sw, http.StatusForbidden, map[string]interface{}{
						"error":  "Request blocked for security reasons",
						"code":   "SECURITY_THREAT",
						"vector": hit.Vector,
					})
					return
				}
			}

			if securityHeaders != nil {
				for key, value := range securityHeaders.GetHeaders() {
					sw.Header().Set(key, value)
				}
			}

			// Stash sanitizer in request context so handlers can fetch it
			// via GetSanitizer(r). Stdlib equivalent of gin's c.Set / echo's
			// c.Set.
			ctx := context.WithValue(r.Context(), sanitizerCtxKey, sanitizer)
			next.ServeHTTP(sw, r.WithContext(ctx))

			// Strip fingerprinting headers. After the handler has written
			// the response these deletes only mutate the Header map (the
			// wire bytes are already sent), but match gin/echo behavior so
			// handlers that defer the write still get the strip.
			sw.Header().Del("Server")
			sw.Header().Del("X-Powered-By")
		})
	}
}

// RateLimit returns a chi-compatible rate-limit middleware. Pass
// WithTelemetry(tc) to emit a TelemetryEvent on 429 (deny-only).
func RateLimit(max int, window time.Duration, opts ...RateLimitOption) func(http.Handler) http.Handler {
	return RateLimitWithSkip(max, window, nil, opts...)
}

// RateLimitWithStore returns a rate-limit middleware backed by a custom
// store. Use this to plug in a distributed backend such as Redis. Pass
// WithTelemetry(tc) to emit on 429.
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore, opts ...RateLimitOption) func(http.Handler) http.Handler {
	var o rateLimitOpts
	for _, opt := range opts {
		opt(&o)
	}

	limiter := arcis.NewRateLimiterWithStore(max, window, store)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			var didDeny bool
			if o.telemetry != nil {
				defer func() {
					if didDeny {
						emitRateLimitDeny(o.telemetry, r, start)
					}
				}()
			}

			result := limiter.Check(r)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				didDeny = true
				w.Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitWithSkip returns a rate-limit middleware with a custom skip
// predicate. Pass WithTelemetry(tc) to emit on 429.
func RateLimitWithSkip(max int, window time.Duration, skip func(*http.Request) bool, opts ...RateLimitOption) func(http.Handler) http.Handler {
	var o rateLimitOpts
	for _, opt := range opts {
		opt(&o)
	}

	limiter := arcis.NewRateLimiter(max, window)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			var didDeny bool
			if o.telemetry != nil {
				defer func() {
					if didDeny {
						emitRateLimitDeny(o.telemetry, r, start)
					}
				}()
			}

			if skip != nil && skip(r) {
				next.ServeHTTP(w, r)
				return
			}

			result := limiter.Check(r)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				didDeny = true
				w.Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ctxKey is an unexported type used for context.WithValue keys to avoid
// collisions with other packages.
type ctxKey int

const sanitizerCtxKey ctxKey = iota

// GetSanitizer retrieves the Arcis sanitizer stashed in the request
// context by MiddlewareWithConfig. Returns a default sanitizer when no
// middleware ran upstream — handlers stay panic-safe and never see nil.
func GetSanitizer(r *http.Request) *arcis.Sanitizer {
	if v := r.Context().Value(sanitizerCtxKey); v != nil {
		if s, ok := v.(*arcis.Sanitizer); ok {
			return s
		}
	}
	return arcis.NewSanitizer(arcis.DefaultConfig())
}
