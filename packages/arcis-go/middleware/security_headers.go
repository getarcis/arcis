package middleware

import (
	"fmt"

	"github.com/getarcis/arcis/core"
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

	// X-XSS-Protection: 0 disables the legacy XSS auditor which was itself
	// an attack vector (could be abused to selectively block legitimate scripts)
	headers["X-XSS-Protection"] = "0"

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

	// Cross-origin isolation headers (Spectre mitigation)
	if config.CrossOriginOpenerPolicy != "" {
		headers["Cross-Origin-Opener-Policy"] = config.CrossOriginOpenerPolicy
	}

	if config.CrossOriginResourcePolicy != "" {
		headers["Cross-Origin-Resource-Policy"] = config.CrossOriginResourcePolicy
	}

	if config.CrossOriginEmbedderPolicy != "" {
		headers["Cross-Origin-Embedder-Policy"] = config.CrossOriginEmbedderPolicy
	}

	// Request origin-keyed process isolation
	if config.OriginAgentCluster {
		headers["Origin-Agent-Cluster"] = "?1"
	}

	// Prevent DNS prefetching (privacy leak vector)
	if config.DNSPrefetchControl {
		headers["X-DNS-Prefetch-Control"] = "off"
	}

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
