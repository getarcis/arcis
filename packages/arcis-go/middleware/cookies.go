package middleware

import (
	"net/http"
	"regexp"
	"strings"
)

// SecureCookieOptions configures secure cookie enforcement.
type SecureCookieOptions struct {
	// HttpOnly prevents JavaScript access to cookies. Default: true
	HttpOnly *bool

	// Secure ensures cookies are only sent over HTTPS. Default: true
	Secure *bool

	// SameSite attribute for CSRF protection. "Strict", "Lax", "None", or "" to skip.
	// Default: "Lax"
	SameSite *string

	// Path overrides the Path attribute on all cookies. Empty = keep original.
	Path string
}

// SecureCookieDefaults enforces secure cookie attributes on Set-Cookie headers.
type SecureCookieDefaults struct {
	httpOnly bool
	secure   bool
	sameSite string // "Strict", "Lax", "None", or "" to skip
	path     string
}

// NewSecureCookieDefaults creates a SecureCookieDefaults with the given options.
func NewSecureCookieDefaults(opts SecureCookieOptions) *SecureCookieDefaults {
	httpOnly := true
	if opts.HttpOnly != nil {
		httpOnly = *opts.HttpOnly
	}

	secure := true
	if opts.Secure != nil {
		secure = *opts.Secure
	}

	sameSite := "Lax"
	if opts.SameSite != nil {
		sameSite = *opts.SameSite
	}

	return &SecureCookieDefaults{
		httpOnly: httpOnly,
		secure:   secure,
		sameSite: sameSite,
		path:     opts.Path,
	}
}

var pathRegexp = regexp.MustCompile(`(?i);\s*path=[^;]*`)

// EnforceSecureCookie enforces secure defaults on a single Set-Cookie header value.
func EnforceSecureCookie(cookieStr string, httpOnly, secure bool, sameSite, path string) string {
	lower := strings.ToLower(cookieStr)
	result := cookieStr

	// HttpOnly — prevent JavaScript access
	if httpOnly && !strings.Contains(lower, "httponly") {
		result += "; HttpOnly"
	}

	// Secure — HTTPS only
	if secure && !strings.Contains(lower, "; secure") {
		result += "; Secure"
	}

	// SameSite — CSRF protection
	if sameSite != "" && !strings.Contains(lower, "samesite") {
		result += "; SameSite=" + sameSite
		// SameSite=None requires Secure
		if sameSite == "None" && !strings.Contains(strings.ToLower(result), "; secure") {
			result += "; Secure"
		}
	}

	// Override path if specified
	if path != "" {
		if strings.Contains(lower, "path=") {
			result = pathRegexp.ReplaceAllString(result, "; Path="+path)
		} else {
			result += "; Path=" + path
		}
	}

	return result
}

// Enforce applies secure defaults to a Set-Cookie header value.
func (sc *SecureCookieDefaults) Enforce(cookieStr string) string {
	return EnforceSecureCookie(cookieStr, sc.httpOnly, sc.secure, sc.sameSite, sc.path)
}

// Handler returns an http.Handler middleware that enforces secure cookie defaults.
// It wraps the ResponseWriter to intercept Set-Cookie headers.
func (sc *SecureCookieDefaults) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &secureCookieWriter{ResponseWriter: w, enforcer: sc}
		next.ServeHTTP(wrapped, r)
	})
}

// secureCookieWriter wraps http.ResponseWriter to intercept Set-Cookie headers.
type secureCookieWriter struct {
	http.ResponseWriter
	enforcer *SecureCookieDefaults
}

func (w *secureCookieWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *secureCookieWriter) WriteHeader(statusCode int) {
	// Enforce secure defaults on all Set-Cookie headers before writing
	cookies := w.ResponseWriter.Header().Values("Set-Cookie")
	if len(cookies) > 0 {
		w.ResponseWriter.Header().Del("Set-Cookie")
		for _, cookie := range cookies {
			w.ResponseWriter.Header().Add("Set-Cookie", w.enforcer.Enforce(cookie))
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *secureCookieWriter) Write(data []byte) (int, error) {
	// Enforce before first write (implicit 200)
	cookies := w.ResponseWriter.Header().Values("Set-Cookie")
	if len(cookies) > 0 {
		w.ResponseWriter.Header().Del("Set-Cookie")
		for _, cookie := range cookies {
			w.ResponseWriter.Header().Add("Set-Cookie", w.enforcer.Enforce(cookie))
		}
	}
	return w.ResponseWriter.Write(data)
}

// SecureCookieMiddleware creates a secure cookie http.Handler middleware from options.
func SecureCookieMiddleware(opts SecureCookieOptions) func(http.Handler) http.Handler {
	sc := NewSecureCookieDefaults(opts)
	return func(next http.Handler) http.Handler {
		return sc.Handler(next)
	}
}
