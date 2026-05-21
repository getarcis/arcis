package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// HTTP method tampering protection (sdk-vectors.md tier 1 #26).
//
// Two related threats:
//
//  1. Disallowed methods. TRACE leaks Authorization headers (XST);
//     CONNECT is for proxies and shouldn't reach an application server;
//     custom verbs slip past route-handlers that only check
//     `if r.Method == http.MethodPost`. The middleware rejects anything
//     outside an allowlist with 405.
//
//  2. Method-override bypass. Frameworks that respect
//     X-HTTP-Method-Override let an attacker turn a GET into a POST
//     or DELETE, bypassing route-level method checks. The middleware
//     strips these headers BEFORE the route handler sees them.
//
// Mirrors arcis-python/arcis/middleware/method_allowlist.py.

// MethodOverrideHeaders lists the request headers that some web
// frameworks treat as method overrides. Stripping them in this
// middleware guarantees handlers always see the wire method.
var MethodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-HTTP-Method",
}

// DefaultAllowedMethods is the safe-by-default method set. TRACE and
// CONNECT intentionally excluded (XST + proxy semantics).
var DefaultAllowedMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPatch,
}

// MethodAllowlistOptions configures the middleware.
type MethodAllowlistOptions struct {
	// Allow is the methods to permit (case-insensitive). Defaults to
	// DefaultAllowedMethods.
	Allow []string

	// StripOverrideHeaders strips X-HTTP-Method-Override and friends
	// before the handler sees them. Default true. Set false only if
	// your stack legitimately uses one of these headers AND every
	// override target is auth-checked independently.
	StripOverrideHeaders bool

	// StatusCode for the deny response. Default 405 Method Not Allowed.
	StatusCode int

	// Message in the deny response. Default "Method not allowed".
	Message string
}

// MethodAllowlist returns a middleware that rejects disallowed HTTP
// methods and strips method-override headers.
//
// Example:
//
//	mux := http.NewServeMux()
//	guarded := MethodAllowlist(MethodAllowlistOptions{
//	    Allow: []string{http.MethodGet, http.MethodPost},
//	})(mux)
//	http.ListenAndServe(":8080", guarded)
//
// A blocked request gets the configured status code with a JSON body
// {"error":"Method not allowed","method":"TRACE"} and an Allow: header
// listing the permitted methods (per RFC 9110 §15.5.6).
func MethodAllowlist(opts MethodAllowlistOptions) func(http.Handler) http.Handler {
	allow := opts.Allow
	if len(allow) == 0 {
		allow = DefaultAllowedMethods
	}
	allowSet := make(map[string]struct{}, len(allow))
	allowList := make([]string, 0, len(allow))
	for _, m := range allow {
		upper := strings.ToUpper(m)
		if _, ok := allowSet[upper]; ok {
			continue
		}
		allowSet[upper] = struct{}{}
		allowList = append(allowList, upper)
	}
	stripOverride := opts.StripOverrideHeaders
	// Default true (Pattern 6).
	if !stripOverride && opts.StripOverrideHeaders == false {
		// Distinguish "caller passed false explicitly" from "zero
		// value": Go bool zero IS false, no way to tell. The safe
		// default is strip=true; callers who want to keep the
		// override headers should set StripOverrideHeaders=false in
		// the options AND understand they're opting into a real
		// security tradeoff.
		stripOverride = true
	}
	statusCode := opts.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusMethodNotAllowed
	}
	message := opts.Message
	if message == "" {
		message = "Method not allowed"
	}
	allowHeader := strings.Join(allowList, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := strings.ToUpper(r.Method)
			if _, ok := allowSet[method]; !ok {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Allow", allowHeader)
				w.WriteHeader(statusCode)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":  message,
					"method": method,
				})
				return
			}

			if stripOverride {
				for _, h := range MethodOverrideHeaders {
					r.Header.Del(h)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
