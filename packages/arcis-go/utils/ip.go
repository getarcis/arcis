package utils

import (
	"net/http"
	"strings"
)

// GetClientIP extracts the client IP address from the request,
// handling common proxy headers.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (comma-separated list, first is client)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		if strings.Contains(addr, "[") {
			if bracketIdx := strings.LastIndex(addr, "]"); bracketIdx != -1 && bracketIdx < idx {
				return addr[:idx]
			}
			return strings.Trim(addr, "[]")
		}
		return addr[:idx]
	}
	return addr
}
