package arcis

import (
	"net/url"
	"regexp"
	"strings"
)

// ValidateRedirectOptions configures redirect validation.
type ValidateRedirectOptions struct {
	AllowedHosts          []string
	AllowProtocolRelative bool
	AllowedProtocols      []string
}

// ValidateRedirectResult is the result of redirect validation.
type ValidateRedirectResult struct {
	Safe   bool
	Reason string
}

// Patterns for redirect validation
var (
	dangerousProtocols = regexp.MustCompile(`(?i)^(javascript|data|vbscript|blob):`)
	controlChars       = regexp.MustCompile(`[\t\n\r]`)
	protoRelativeHost  = regexp.MustCompile(`^//([^/:?#]+)`)
)

// ValidateRedirect checks a redirect URL for open redirect attacks.
//
// Safe:
//   - Relative paths: /dashboard, /users?page=2
//   - Absolute URLs to allowed hosts
//
// Blocked:
//   - Absolute URLs to unknown hosts
//   - Protocol-relative URLs (//evil.com)
//   - javascript:, data:, vbscript:, blob: protocols
//   - Backslash-prefixed paths (\\evil.com)
//   - URLs with control characters
func ValidateRedirect(rawURL string, opts *ValidateRedirectOptions) ValidateRedirectResult {
	if opts == nil {
		opts = &ValidateRedirectOptions{}
	}

	allowedProtocols := opts.AllowedProtocols
	if len(allowedProtocols) == 0 {
		allowedProtocols = []string{"http", "https"}
	}

	if strings.TrimSpace(rawURL) == "" {
		return ValidateRedirectResult{Safe: false, Reason: "invalid redirect: empty or not a string"}
	}

	// Strip control characters
	cleaned := controlChars.ReplaceAllString(rawURL, "")

	// Block dangerous protocols
	if m := dangerousProtocols.FindString(cleaned); m != "" {
		return ValidateRedirectResult{Safe: false, Reason: "dangerous protocol: " + m}
	}

	// Block backslash-prefixed paths
	if strings.HasPrefix(cleaned, `\`) {
		return ValidateRedirectResult{Safe: false, Reason: "backslash-prefixed URL (browser treats as protocol-relative)"}
	}

	// Check protocol-relative URLs
	if strings.HasPrefix(cleaned, "//") {
		host := ""
		if m := protoRelativeHost.FindStringSubmatch(cleaned); m != nil {
			host = strings.ToLower(m[1])
		}

		if !opts.AllowProtocolRelative {
			if host != "" {
				for _, h := range opts.AllowedHosts {
					if host == strings.ToLower(h) {
						return ValidateRedirectResult{Safe: true}
					}
				}
			}
			return ValidateRedirectResult{Safe: false, Reason: "protocol-relative URL not in allowed hosts"}
		}

		if host != "" && len(opts.AllowedHosts) > 0 {
			found := false
			for _, h := range opts.AllowedHosts {
				if host == strings.ToLower(h) {
					found = true
					break
				}
			}
			if !found {
				return ValidateRedirectResult{Safe: false, Reason: "protocol-relative URL not in allowed hosts"}
			}
		}
		return ValidateRedirectResult{Safe: true}
	}

	// Try parsing as absolute URL
	parsed, err := url.Parse(cleaned)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		// Not a valid absolute URL — relative path (safe)
		return ValidateRedirectResult{Safe: true}
	}

	// Check protocol
	protoAllowed := false
	for _, p := range allowedProtocols {
		if parsed.Scheme == p {
			protoAllowed = true
			break
		}
	}
	if !protoAllowed {
		return ValidateRedirectResult{Safe: false, Reason: "disallowed protocol: " + parsed.Scheme + ":"}
	}

	// Check if host is in allowed list
	hostname := strings.ToLower(parsed.Hostname())
	if len(opts.AllowedHosts) == 0 {
		return ValidateRedirectResult{Safe: false, Reason: "absolute URL not in allowed hosts"}
	}

	for _, h := range opts.AllowedHosts {
		if hostname == strings.ToLower(h) {
			return ValidateRedirectResult{Safe: true}
		}
	}

	return ValidateRedirectResult{Safe: false, Reason: "host not allowed: " + hostname}
}

// IsRedirectSafe is a convenience wrapper that returns true/false.
func IsRedirectSafe(rawURL string, opts *ValidateRedirectOptions) bool {
	return ValidateRedirect(rawURL, opts).Safe
}
