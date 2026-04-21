package middleware

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

// HppOptions configures HTTP Parameter Pollution protection.
type HppOptions struct {
	// Whitelist of parameters that legitimately accept multiple values.
	// Example: []string{"tags", "ids", "filter"}
	Whitelist []string

	// DisableQueryCheck disables query string normalization (default: enabled).
	DisableQueryCheck bool

	// DisableFormCheck disables form body normalization (default: enabled).
	DisableFormCheck bool

	// OnParseError is invoked when ParseForm fails. Default: log to stderr via
	// the standard logger. Set to a no-op func to silence. The middleware then
	// still skips form normalization for that request (we can't normalize what
	// we couldn't parse), but the operator is at least told about it.
	OnParseError func(r *http.Request, err error)
}

// HppMiddleware normalizes duplicate query and form parameters to their last
// value, preventing HTTP Parameter Pollution attacks.
//
// Attack:
//
//	GET /search?role=user&role=admin
//	Without HPP: r.URL.Query()["role"] = ["user", "admin"]
//	With HPP:    r.URL.Query().Get("role") = "admin"  (last wins)
//
// Whitelisted parameters are left as-is (arrays preserved).
//
// Example:
//
//	r.Use(HppMiddleware(HppOptions{}))
//
// Example with whitelist:
//
//	r.Use(HppMiddleware(HppOptions{Whitelist: []string{"tags", "ids"}}))
func HppMiddleware(opts HppOptions) func(http.Handler) http.Handler {
	whitelist := make(map[string]bool, len(opts.Whitelist))
	for _, k := range opts.Whitelist {
		whitelist[k] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ── Query string normalization ─────────────────────────────────
			if !opts.DisableQueryCheck {
				q := r.URL.Query()
				normalized := make(url.Values, len(q))
				for key, values := range q {
					if len(values) > 1 && !whitelist[key] {
						// Duplicate — last value wins
						normalized[key] = []string{values[len(values)-1]}
					} else {
						normalized[key] = values
					}
				}
				r.URL.RawQuery = normalized.Encode()
			}

			// ── Form body normalization ────────────────────────────────────
			if !opts.DisableFormCheck {
				method := strings.ToUpper(r.Method)
				if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
					contentType := r.Header.Get("Content-Type")
					isForm := strings.Contains(contentType, "application/x-www-form-urlencoded") ||
						strings.Contains(contentType, "multipart/form-data")

					if isForm {
						if err := r.ParseForm(); err != nil {
							if opts.OnParseError != nil {
								opts.OnParseError(r, err)
							} else {
								log.Printf("[arcis] hpp: ParseForm failed, skipping form normalization: %v", err)
							}
						} else {
							for key, values := range r.PostForm {
								if len(values) > 1 && !whitelist[key] {
									last := values[len(values)-1]
									r.PostForm[key] = []string{last}
									r.Form[key] = []string{last}
								}
							}
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
