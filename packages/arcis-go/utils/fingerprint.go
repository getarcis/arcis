package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// FingerprintOptions configures which components are included in request fingerprinting.
type FingerprintOptions struct {
	IP               bool              // Include client IP (default: true)
	UserAgent        bool              // Include User-Agent header (default: true)
	Accept           bool              // Include Accept header (default: true)
	AcceptLanguage   bool              // Include Accept-Language header (default: true)
	AcceptEncoding   bool              // Include Accept-Encoding header (default: true)
	Custom           []string          // Additional custom components
	IPOptions        *DetectIPOptions  // Options for IP detection
}

// DefaultFingerprintOptions returns fingerprint options with all defaults enabled.
func DefaultFingerprintOptions() FingerprintOptions {
	return FingerprintOptions{
		IP:             true,
		UserAgent:      true,
		Accept:         true,
		AcceptLanguage: true,
		AcceptEncoding: true,
	}
}

// Fingerprint generates a SHA-256 hash fingerprint of the request based on
// selected components (IP, headers, custom values). Returns a 64-char hex string.
func Fingerprint(r *http.Request, opts *FingerprintOptions) string {
	o := DefaultFingerprintOptions()
	if opts != nil {
		o = *opts
	}

	var components []string

	if o.IP {
		ip := DetectClientIP(r, o.IPOptions)
		components = append(components, fmt.Sprintf("ip:%s", ip))
	}

	if o.UserAgent {
		components = append(components, fmt.Sprintf("ua:%s", r.Header.Get("User-Agent")))
	}

	if o.Accept {
		components = append(components, fmt.Sprintf("accept:%s", r.Header.Get("Accept")))
	}

	if o.AcceptLanguage {
		components = append(components, fmt.Sprintf("lang:%s", r.Header.Get("Accept-Language")))
	}

	if o.AcceptEncoding {
		components = append(components, fmt.Sprintf("enc:%s", r.Header.Get("Accept-Encoding")))
	}

	for _, c := range o.Custom {
		components = append(components, fmt.Sprintf("custom:%s", c))
	}

	// Sort for deterministic output
	sort.Strings(components)

	joined := strings.Join(components, "|")

	hash := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(hash[:])
}
