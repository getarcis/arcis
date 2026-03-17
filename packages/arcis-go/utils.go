package arcis

import (
	"fmt"
	"net/http"
	"strings"
)

// InputTooLargeError is returned when input exceeds the maximum size.
type InputTooLargeError struct {
	Size    int
	MaxSize int
}

func (e *InputTooLargeError) Error() string {
	return fmt.Sprintf("input size %d exceeds maximum of %d bytes", e.Size, e.MaxSize)
}

// getClientIP extracts the client IP address from the request,
// handling common proxy headers.
func getClientIP(r *http.Request) string {
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
