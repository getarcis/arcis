package middleware

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Default CORS configuration values.
var (
	DefaultCorsMethods = []string{"GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"}
	DefaultCorsHeaders = []string{"Content-Type", "Authorization"}
	DefaultCorsMaxAge  = 600 // 10 minutes
)

// CorsOrigin represents the allowed origin configuration.
// It can be a string, []string, *regexp.Regexp, func(string) bool, or bool (true = reflect).
type CorsOrigin interface{}

// CorsOptions configures the Safe CORS middleware.
type CorsOptions struct {
	// Origin defines which origins are allowed. Required.
	// Accepts: string, []string, *regexp.Regexp, func(string) bool, or true (reflect request origin).
	Origin CorsOrigin

	// Methods defines the allowed HTTP methods for preflight.
	// Default: GET, HEAD, PUT, PATCH, POST, DELETE
	Methods []string

	// AllowedHeaders defines the allowed request headers for preflight.
	// Default: Content-Type, Authorization
	AllowedHeaders []string

	// ExposedHeaders defines which response headers the browser can access.
	// Default: empty
	ExposedHeaders []string

	// Credentials indicates whether cookies/auth headers are allowed.
	// Default: false
	Credentials bool

	// MaxAge defines how long preflight results can be cached (seconds).
	// Default: 600 (10 minutes)
	MaxAge int
}

// CorsHeaders holds the computed CORS response headers.
type CorsHeaders map[string]string

// SafeCors provides safe CORS header management.
type SafeCors struct {
	origin         CorsOrigin
	methods        []string
	allowedHeaders []string
	exposedHeaders []string
	credentials    bool
	maxAge         int
}

// NewSafeCors creates a SafeCors instance with the given options.
func NewSafeCors(opts CorsOptions) *SafeCors {
	methods := opts.Methods
	if len(methods) == 0 {
		methods = DefaultCorsMethods
	}

	allowedHeaders := opts.AllowedHeaders
	if len(allowedHeaders) == 0 {
		allowedHeaders = DefaultCorsHeaders
	}

	exposedHeaders := opts.ExposedHeaders
	if exposedHeaders == nil {
		exposedHeaders = []string{}
	}

	maxAge := opts.MaxAge
	if maxAge == 0 {
		maxAge = DefaultCorsMaxAge
	}

	return &SafeCors{
		origin:         opts.Origin,
		methods:        methods,
		allowedHeaders: allowedHeaders,
		exposedHeaders: exposedHeaders,
		credentials:    opts.Credentials,
		maxAge:         maxAge,
	}
}

// isOriginAllowed checks if a request origin is permitted.
func isOriginAllowed(requestOrigin string, allowed CorsOrigin) bool {
	// Always block "null" origin (sandboxed iframes, data: URIs)
	if strings.EqualFold(requestOrigin, "null") {
		return false
	}

	switch v := allowed.(type) {
	case bool:
		return v
	case string:
		return requestOrigin == v
	case []string:
		for _, o := range v {
			if requestOrigin == o {
				return true
			}
		}
		return false
	case *regexp.Regexp:
		// SECURITY: Go's regexp package uses RE2 (linear time, no catastrophic
		// backtracking) so user-provided regex cannot cause ReDoS. We still cap
		// input length defensively — an Origin header longer than 2048 chars is
		// malformed or an abuse attempt.
		if len(requestOrigin) > 2048 {
			return false
		}
		return v.MatchString(requestOrigin)
	case func(string) bool:
		return v(requestOrigin)
	default:
		return false
	}
}

// GetHeaders computes the CORS headers for a given request origin and method.
func (sc *SafeCors) GetHeaders(requestOrigin string, method string) CorsHeaders {
	headers := CorsHeaders{
		"Vary": "Origin",
	}

	// No origin header → same-origin request, only Vary needed
	if requestOrigin == "" {
		return headers
	}

	if !isOriginAllowed(requestOrigin, sc.origin) {
		return headers
	}

	// Origin is allowed — set CORS headers
	headers["Access-Control-Allow-Origin"] = requestOrigin

	if sc.credentials {
		headers["Access-Control-Allow-Credentials"] = "true"
	}

	if len(sc.exposedHeaders) > 0 {
		headers["Access-Control-Expose-Headers"] = strings.Join(sc.exposedHeaders, ", ")
	}

	// Preflight-specific headers
	if strings.EqualFold(method, "OPTIONS") {
		headers["Access-Control-Allow-Methods"] = strings.Join(sc.methods, ", ")
		headers["Access-Control-Allow-Headers"] = strings.Join(sc.allowedHeaders, ", ")
		headers["Access-Control-Max-Age"] = strconv.Itoa(sc.maxAge)
	}

	return headers
}

// Handler returns an http.Handler middleware that applies CORS headers.
func (sc *SafeCors) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		corsHeaders := sc.GetHeaders(origin, r.Method)

		for key, value := range corsHeaders {
			w.Header().Set(key, value)
		}

		// Handle preflight
		if r.Method == http.MethodOptions && origin != "" && isOriginAllowed(origin, sc.origin) {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SafeCorsMiddleware creates a CORS http.Handler middleware from options.
func SafeCorsMiddleware(opts CorsOptions) func(http.Handler) http.Handler {
	cors := NewSafeCors(opts)
	return func(next http.Handler) http.Handler {
		return cors.Handler(next)
	}
}
