package arcis

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ValidateURLOptions configures SSRF URL validation.
type ValidateURLOptions struct {
	AllowedProtocols []string
	BlockedHosts     []string
	AllowedHosts     []string
	AllowLocalhost   bool
	AllowPrivate     bool
}

// ValidateURLResult is the result of URL validation.
type ValidateURLResult struct {
	Safe   bool
	Reason string
}

// Pre-compiled patterns for SSRF IP checks
var (
	reLoopback   = regexp.MustCompile(`^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	re10         = regexp.MustCompile(`^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	re172        = regexp.MustCompile(`^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$`)
	re192        = regexp.MustCompile(`^192\.168\.\d{1,3}\.\d{1,3}$`)
	reLinkLocal  = regexp.MustCompile(`^169\.254\.\d{1,3}\.\d{1,3}$`)
	reCurrentNet = regexp.MustCompile(`^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

// ValidateURL checks a URL for SSRF safety.
//
// Blocks:
//   - Private IPs (10.x, 172.16-31.x, 192.168.x)
//   - Loopback (127.x.x.x, ::1, localhost)
//   - Link-local / cloud metadata (169.254.x.x)
//   - Dangerous protocols (file:, ftp:, gopher:, etc.)
//   - URLs with embedded credentials (user:pass@host)
func ValidateURL(rawURL string, opts *ValidateURLOptions) ValidateURLResult {
	if opts == nil {
		opts = &ValidateURLOptions{}
	}

	allowedProtocols := opts.AllowedProtocols
	if len(allowedProtocols) == 0 {
		allowedProtocols = []string{"http", "https"}
	}

	if strings.TrimSpace(rawURL) == "" {
		return ValidateURLResult{Safe: false, Reason: "invalid URL: empty or not a string"}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return ValidateURLResult{Safe: false, Reason: "invalid URL: failed to parse"}
	}

	// Check protocol first (before host check, since file:// URLs have empty host)
	protoAllowed := false
	for _, p := range allowedProtocols {
		if parsed.Scheme == p {
			protoAllowed = true
			break
		}
	}
	if !protoAllowed {
		return ValidateURLResult{Safe: false, Reason: "disallowed protocol: " + parsed.Scheme + ":"}
	}

	// Require a host for allowed protocols
	if parsed.Host == "" {
		return ValidateURLResult{Safe: false, Reason: "invalid URL: failed to parse"}
	}

	// Check for credentials
	if parsed.User != nil {
		return ValidateURLResult{Safe: false, Reason: "URL contains credentials"}
	}

	hostname := strings.ToLower(parsed.Hostname())

	// Check explicit allowlist (bypasses IP checks)
	for _, h := range opts.AllowedHosts {
		if hostname == strings.ToLower(h) {
			return ValidateURLResult{Safe: true}
		}
	}

	// Check explicit blocklist
	for _, h := range opts.BlockedHosts {
		if hostname == strings.ToLower(h) {
			return ValidateURLResult{Safe: false, Reason: "blocked host: " + hostname}
		}
	}

	// Check localhost/loopback
	if !opts.AllowLocalhost {
		if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" ||
			hostname == "0.0.0.0" || strings.HasSuffix(hostname, ".localhost") {
			return ValidateURLResult{Safe: false, Reason: "loopback address"}
		}
		if reLoopback.MatchString(hostname) {
			return ValidateURLResult{Safe: false, Reason: "loopback address"}
		}
	}

	// Check private IPs
	if !opts.AllowPrivate {
		if reason := checkPrivateIP(hostname); reason != "" {
			return ValidateURLResult{Safe: false, Reason: reason}
		}
	}

	return ValidateURLResult{Safe: true}
}

// IsURLSafe is a convenience wrapper that returns true/false.
func IsURLSafe(rawURL string, opts *ValidateURLOptions) bool {
	return ValidateURL(rawURL, opts).Safe
}

func checkPrivateIP(hostname string) string {
	if re10.MatchString(hostname) {
		return "private address (10.0.0.0/8)"
	}

	if m := re172.FindStringSubmatch(hostname); m != nil {
		second, _ := strconv.Atoi(m[1])
		if second >= 16 && second <= 31 {
			return "private address (172.16.0.0/12)"
		}
	}

	if re192.MatchString(hostname) {
		return "private address (192.168.0.0/16)"
	}

	if reLinkLocal.MatchString(hostname) {
		return "link-local address (169.254.0.0/16)"
	}

	if reCurrentNet.MatchString(hostname) {
		return "current network address (0.0.0.0/8)"
	}

	if hostname == "metadata.google.internal" || hostname == "metadata.internal" {
		return "cloud metadata endpoint"
	}

	// IPv6 private ranges
	ipv6 := strings.Trim(hostname, "[]")
	if ipv6 == "::1" || ipv6 == "::" {
		return "private IPv6 address"
	}
	if strings.HasPrefix(ipv6, "fc") || strings.HasPrefix(ipv6, "fd") || strings.HasPrefix(ipv6, "fe80") {
		return "private IPv6 address"
	}

	return ""
}
