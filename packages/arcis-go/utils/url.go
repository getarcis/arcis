package utils

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

	// Check decimal IP encoding (e.g., 2130706433 = 127.0.0.1)
	if !opts.AllowLocalhost || !opts.AllowPrivate {
		if reason := checkDecimalIP(hostname, opts.AllowLocalhost, opts.AllowPrivate); reason != "" {
			return ValidateURLResult{Safe: false, Reason: reason}
		}
	}

	// Check octal/hex IP encoding (e.g., 0177.0.0.1 = 127.0.0.1, 0x7f.0.0.1 = 127.0.0.1)
	if !opts.AllowLocalhost || !opts.AllowPrivate {
		if reason := checkOctalHexIP(hostname, opts.AllowLocalhost, opts.AllowPrivate); reason != "" {
			return ValidateURLResult{Safe: false, Reason: reason}
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

// checkDecimalIP detects decimal-encoded IPs (e.g., 2130706433 = 127.0.0.1).
func checkDecimalIP(hostname string, allowLocalhost, allowPrivate bool) string {
	// Must be all digits
	if len(hostname) == 0 {
		return ""
	}
	for _, c := range hostname {
		if c < '0' || c > '9' {
			return ""
		}
	}

	num, err := strconv.ParseUint(hostname, 10, 64)
	if err != nil || num > 0xFFFFFFFF {
		return ""
	}

	a := byte(num >> 24)
	b := byte(num >> 16)
	c := byte(num >> 8)
	d := byte(num)
	dotted := strconv.Itoa(int(a)) + "." + strconv.Itoa(int(b)) + "." + strconv.Itoa(int(c)) + "." + strconv.Itoa(int(d))

	if !allowLocalhost && a == 127 {
		return "loopback address (decimal IP: " + dotted + ")"
	}
	if !allowPrivate {
		if reason := checkPrivateIP(dotted); reason != "" {
			return reason + " (decimal IP: " + dotted + ")"
		}
	}
	return ""
}

// checkOctalHexIP detects octal/hex-encoded IPs (e.g., 0177.0.0.1, 0x7f.0.0.1 = 127.0.0.1).
func checkOctalHexIP(hostname string, allowLocalhost, allowPrivate bool) string {
	parts := strings.Split(hostname, ".")
	if len(parts) != 4 {
		return ""
	}

	// Check if any part uses octal (leading 0) or hex (0x) notation
	hasAlternate := false
	for _, p := range parts {
		if len(p) > 1 && p[0] == '0' {
			if len(p) > 2 && (p[1] == 'x' || p[1] == 'X') {
				hasAlternate = true // hex
			} else if p[1] >= '0' && p[1] <= '7' {
				hasAlternate = true // octal
			}
		}
	}
	if !hasAlternate {
		return ""
	}

	octets := make([]int, 4)
	for i, part := range parts {
		var val int64
		var err error
		if len(part) > 2 && (part[:2] == "0x" || part[:2] == "0X") {
			val, err = strconv.ParseInt(part[2:], 16, 64)
		} else if len(part) > 1 && part[0] == '0' {
			val, err = strconv.ParseInt(part, 8, 64)
		} else {
			val, err = strconv.ParseInt(part, 10, 64)
		}
		if err != nil || val < 0 || val > 255 {
			return ""
		}
		octets[i] = int(val)
	}

	dotted := strconv.Itoa(octets[0]) + "." + strconv.Itoa(octets[1]) + "." + strconv.Itoa(octets[2]) + "." + strconv.Itoa(octets[3])

	if !allowLocalhost && octets[0] == 127 {
		return "loopback address (octal/hex IP: " + dotted + ")"
	}
	if !allowPrivate {
		if reason := checkPrivateIP(dotted); reason != "" {
			return reason + " (octal/hex IP: " + dotted + ")"
		}
	}
	return ""
}
