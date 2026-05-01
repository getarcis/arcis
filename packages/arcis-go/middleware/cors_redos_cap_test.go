package middleware

import (
	"regexp"
	"strings"
	"testing"
)

// M6 — Regexp origin check caps input length defensively.
// Go's RE2 engine is linear-time so there's no real ReDoS, but
// oversized Origin headers must still be rejected fast.
func TestAuditM6_RegexpOriginLengthCap(t *testing.T) {
	re := regexp.MustCompile(`^https://.*\.example\.com$`)

	overlong := "https://" + strings.Repeat("a", 4000) + ".example.com"
	if isOriginAllowed(overlong, re) {
		t.Errorf("expected overlong origin (>2048) to be rejected, got allowed")
	}

	normal := "https://api.example.com"
	if !isOriginAllowed(normal, re) {
		t.Errorf("expected normal origin to be allowed")
	}
}
