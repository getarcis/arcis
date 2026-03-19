package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Default CSRF configuration values.
const (
	DefaultCsrfCookieName = "_csrf"
	DefaultCsrfHeaderName = "X-Csrf-Token"
	DefaultCsrfFieldName  = "_csrf"
	DefaultTokenLength    = 32
)

// DefaultProtectedMethods are the HTTP methods that require CSRF validation.
var DefaultProtectedMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

// CsrfCookieOptions configures the CSRF token cookie.
type CsrfCookieOptions struct {
	// Path for the cookie. Default: "/"
	Path string
	// HttpOnly — set false so client JS can read it for headers. Default: false
	HttpOnly bool
	// Secure flag (HTTPS only). Default: true
	Secure *bool
	// SameSite attribute. Default: "Lax"
	SameSite string
	// Domain for the cookie
	Domain string
}

// CsrfOptions configures CSRF protection.
type CsrfOptions struct {
	// CookieName for the CSRF token. Default: "_csrf"
	CookieName string
	// HeaderName to check for the token. Default: "X-Csrf-Token"
	HeaderName string
	// FieldName to check in form/JSON body. Default: "_csrf"
	FieldName string
	// TokenLength in bytes (hex-encoded = 2x chars). Default: 32
	TokenLength int
	// ProtectedMethods that require CSRF validation. Default: POST, PUT, PATCH, DELETE
	ProtectedMethods []string
	// ExcludePaths excluded from CSRF checks (e.g., webhook endpoints)
	ExcludePaths []string
	// Cookie options for the CSRF token
	Cookie CsrfCookieOptions
	// OnError custom handler when CSRF validation fails. If nil, returns 403 JSON.
	OnError func(w http.ResponseWriter, r *http.Request)
}

// CsrfProtection provides CSRF protection using double-submit cookie pattern.
type CsrfProtection struct {
	cookieName       string
	headerName       string
	fieldName        string
	tokenLength      int
	protectedMethods map[string]bool
	excludePaths     []string
	cookie           CsrfCookieOptions
	onError          func(w http.ResponseWriter, r *http.Request)
}

// GenerateCsrfToken generates a cryptographically random CSRF token.
func GenerateCsrfToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateCsrfToken compares two CSRF tokens using constant-time comparison.
func ValidateCsrfToken(cookieToken, requestToken string) bool {
	if cookieToken == "" || requestToken == "" {
		return false
	}
	if len(cookieToken) != len(requestToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(requestToken)) == 1
}

// NewCsrfProtection creates a CsrfProtection with the given options.
func NewCsrfProtection(opts CsrfOptions) *CsrfProtection {
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = DefaultCsrfCookieName
	}

	headerName := opts.HeaderName
	if headerName == "" {
		headerName = DefaultCsrfHeaderName
	}

	fieldName := opts.FieldName
	if fieldName == "" {
		fieldName = DefaultCsrfFieldName
	}

	tokenLength := opts.TokenLength
	if tokenLength == 0 {
		tokenLength = DefaultTokenLength
	}

	methods := opts.ProtectedMethods
	if len(methods) == 0 {
		methods = DefaultProtectedMethods
	}
	protectedSet := make(map[string]bool, len(methods))
	for _, m := range methods {
		protectedSet[strings.ToUpper(m)] = true
	}

	excludePaths := opts.ExcludePaths
	if excludePaths == nil {
		excludePaths = []string{}
	}

	cookie := opts.Cookie
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	if cookie.SameSite == "" {
		cookie.SameSite = "Lax"
	}
	if cookie.Secure == nil {
		t := true
		cookie.Secure = &t
	}

	return &CsrfProtection{
		cookieName:       cookieName,
		headerName:       headerName,
		fieldName:        fieldName,
		tokenLength:      tokenLength,
		protectedMethods: protectedSet,
		excludePaths:     excludePaths,
		cookie:           cookie,
		onError:          opts.OnError,
	}
}

// isExcluded checks if a path is excluded from CSRF protection.
func (cp *CsrfProtection) isExcluded(path string) bool {
	for _, excluded := range cp.excludePaths {
		if path == excluded || strings.HasPrefix(path, excluded+"/") {
			return true
		}
	}
	return false
}

// buildCookieHeader builds a Set-Cookie header value for the CSRF token.
func (cp *CsrfProtection) buildCookieHeader(token string) string {
	parts := []string{fmt.Sprintf("%s=%s", cp.cookieName, token)}
	parts = append(parts, "Path="+cp.cookie.Path)
	if cp.cookie.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	if cp.cookie.Secure != nil && *cp.cookie.Secure {
		parts = append(parts, "Secure")
	}
	parts = append(parts, "SameSite="+cp.cookie.SameSite)
	if cp.cookie.Domain != "" {
		parts = append(parts, "Domain="+cp.cookie.Domain)
	}
	return strings.Join(parts, "; ")
}

// getCookieToken reads the CSRF token from the request cookie.
func (cp *CsrfProtection) getCookieToken(r *http.Request) string {
	cookie, err := r.Cookie(cp.cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// getRequestToken extracts the CSRF token from the request (header, then body, then query).
func (cp *CsrfProtection) getRequestToken(r *http.Request) string {
	// 1. Check header (most common for SPAs)
	headerToken := r.Header.Get(cp.headerName)
	if headerToken != "" {
		return headerToken
	}

	// 2. Check form field
	if r.Form != nil {
		formToken := r.FormValue(cp.fieldName)
		if formToken != "" {
			return formToken
		}
	}

	// 3. Check query string
	queryToken := r.URL.Query().Get(cp.fieldName)
	if queryToken != "" {
		return queryToken
	}

	return ""
}

// sendError sends the CSRF error response.
func (cp *CsrfProtection) sendError(w http.ResponseWriter, r *http.Request) {
	if cp.onError != nil {
		cp.onError(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "CSRF token validation failed",
		"message": "Invalid or missing CSRF token. Include the token from the cookie in the X-CSRF-Token header.",
	})
}

// Check performs framework-agnostic CSRF validation.
// Returns true if the request is valid (safe method, excluded path, or valid token).
func (cp *CsrfProtection) Check(method, path, cookieToken, requestToken string) bool {
	if cp.isExcluded(path) {
		return true
	}
	if !cp.protectedMethods[strings.ToUpper(method)] {
		return true
	}
	if cookieToken == "" || requestToken == "" {
		return false
	}
	return ValidateCsrfToken(cookieToken, requestToken)
}

// GenerateToken generates a new CSRF token.
func (cp *CsrfProtection) GenerateToken() (string, error) {
	return GenerateCsrfToken(cp.tokenLength)
}

// Handler returns an http.Handler middleware for CSRF protection.
func (cp *CsrfProtection) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := strings.ToUpper(r.Method)

		// Check if path is excluded
		if cp.isExcluded(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// For safe methods — ensure a CSRF cookie exists
		if !cp.protectedMethods[method] {
			existing := cp.getCookieToken(r)
			if existing == "" {
				token, err := GenerateCsrfToken(cp.tokenLength)
				if err == nil {
					w.Header().Add("Set-Cookie", cp.buildCookieHeader(token))
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		// For protected methods — validate the token
		cookieToken := cp.getCookieToken(r)
		if cookieToken == "" {
			cp.sendError(w, r)
			return
		}

		requestToken := cp.getRequestToken(r)
		if requestToken == "" {
			cp.sendError(w, r)
			return
		}

		if !ValidateCsrfToken(cookieToken, requestToken) {
			cp.sendError(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CsrfMiddleware creates a CSRF protection http.Handler middleware from options.
func CsrfMiddleware(opts CsrfOptions) func(http.Handler) http.Handler {
	csrf := NewCsrfProtection(opts)
	return func(next http.Handler) http.Handler {
		return csrf.Handler(next)
	}
}
