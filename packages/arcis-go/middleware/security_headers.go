package middleware

import (
	"fmt"

	"github.com/GagancM/arcis/core"
)

// SecurityHeaders handles security header configuration and application.
type SecurityHeaders struct {
	headers map[string]string
}

// NewSecurityHeaders creates a new SecurityHeaders with the given configuration.
func NewSecurityHeaders(config core.Config) *SecurityHeaders {
	headers := make(map[string]string)

	if config.CSP != "" {
		headers["Content-Security-Policy"] = config.CSP
	}

	headers["X-Content-Type-Options"] = "nosniff"

	if config.FrameOptions != "" {
		headers["X-Frame-Options"] = config.FrameOptions
	}

	headers["X-XSS-Protection"] = "1; mode=block"

	if config.HSTSMaxAge > 0 {
		hsts := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
		if config.HSTSSubdomains {
			hsts += "; includeSubDomains"
		}
		headers["Strict-Transport-Security"] = hsts
	}

	if config.ReferrerPolicy != "" {
		headers["Referrer-Policy"] = config.ReferrerPolicy
	}

	if config.PermissionsPolicy != "" {
		headers["Permissions-Policy"] = config.PermissionsPolicy
	}

	headers["X-Permitted-Cross-Domain-Policies"] = "none"

	if config.CacheControl {
		cacheControlValue := config.CacheControlValue
		if cacheControlValue == "" {
			cacheControlValue = "no-store, no-cache, must-revalidate, proxy-revalidate"
		}
		headers["Cache-Control"] = cacheControlValue
		headers["Pragma"] = "no-cache"
		headers["Expires"] = "0"
	}

	return &SecurityHeaders{headers: headers}
}

// GetHeaders returns all security headers as a map.
func (sh *SecurityHeaders) GetHeaders() map[string]string {
	return sh.headers
}

// SetHeader sets or overrides a specific header.
func (sh *SecurityHeaders) SetHeader(key, value string) {
	sh.headers[key] = value
}

// RemoveHeader removes a specific header.
func (sh *SecurityHeaders) RemoveHeader(key string) {
	delete(sh.headers, key)
}
