package utils

import (
	"context"
	"net"
	"net/url"
	"strings"
)

// ValidateURLContext is the context-aware SSRF check that resolves the
// hostname and validates every returned IP. Closes the DNS-rebinding
// TOCTOU window that ValidateURL leaves open.
//
// ValidateURL validates the literal hostname only. That's NOT enough
// against DNS rebinding: an attacker controls `7f000001.rebind.it`,
// whose first resolve returns a public IP (passes the literal-hostname
// check) and whose second resolve at fetch time returns 127.0.0.1.
// Validating the hostname at request time and then fetching at handler
// time opens a TOCTOU window.
//
// This function closes the window by resolving the hostname upfront
// and rejecting the URL if ANY returned address is private / loopback
// / link-local / cloud-metadata. Callers should pin the resolved IP
// (build a custom net.Resolver / Dialer in their HTTP client) so the
// actual fetch hits the same address that was validated.
//
// The ctx parameter caps DNS wall-clock — pass context.WithTimeout
// when the caller has a budget; otherwise resolution is bounded only
// by the platform default. Cancellation via ctx is honored.
//
// Mirrors arcis-python/arcis/validation/url.py::validate_url_async.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
//	defer cancel()
//	res := ValidateURLContext(ctx, userURL, nil)
//	if !res.Safe {
//	    http.Error(w, res.Reason, http.StatusBadRequest)
//	    return
//	}
//	// Safe to fetch userURL.
func ValidateURLContext(ctx context.Context, rawURL string, opts *ValidateURLOptions) ValidateURLResult {
	if opts == nil {
		opts = &ValidateURLOptions{}
	}

	// Sync literal-hostname check first. If that says no, no DNS work.
	syncResult := ValidateURL(rawURL, opts)
	if !syncResult.Safe {
		return syncResult
	}

	// Re-parse for hostname extraction.
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ValidateURLResult{Safe: false, Reason: "invalid URL: failed to parse"}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return ValidateURLResult{Safe: false, Reason: "invalid URL: no hostname"}
	}

	// Allowlisted host? Skip resolution entirely. The user explicitly
	// opted into trusting this name even if it resolves elsewhere later.
	for _, h := range opts.AllowedHosts {
		if hostname == strings.ToLower(h) {
			return ValidateURLResult{Safe: true}
		}
	}

	// If the hostname is already an IP, sync check already covered it.
	if net.ParseIP(strings.Trim(hostname, "[]")) != nil {
		return ValidateURLResult{Safe: true}
	}

	// Resolve via Go's default resolver, respecting the caller's context.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		// Distinguish ctx.Err() (timeout / cancel) from real DNS error
		// in the message so operators can tell them apart in logs.
		if ctx.Err() != nil {
			return ValidateURLResult{
				Safe:   false,
				Reason: "DNS resolution cancelled: " + ctx.Err().Error(),
			}
		}
		return ValidateURLResult{
			Safe:   false,
			Reason: "DNS resolution failed: " + err.Error(),
		}
	}

	if len(ips) == 0 {
		return ValidateURLResult{
			Safe:   false,
			Reason: "DNS resolution returned no addresses",
		}
	}

	// Validate each resolved IP. Fail-closed on ANY private hit.
	for _, addr := range ips {
		ipStr := addr.IP.String()

		if !opts.AllowLocalhost {
			if addr.IP.IsLoopback() {
				return ValidateURLResult{
					Safe:   false,
					Reason: "resolved to loopback address (" + ipStr + ")",
				}
			}
			if ipStr == "0.0.0.0" {
				return ValidateURLResult{
					Safe:   false,
					Reason: "resolved to 0.0.0.0",
				}
			}
		}
		if !opts.AllowPrivate {
			if reason := checkResolvedIPPrivate(ipStr); reason != "" {
				return ValidateURLResult{
					Safe:   false,
					Reason: "resolved to " + reason + " (" + ipStr + ")",
				}
			}
		}
	}

	return ValidateURLResult{Safe: true}
}

// IsURLSafeContext is the context-aware boolean convenience wrapper.
func IsURLSafeContext(ctx context.Context, rawURL string, opts *ValidateURLOptions) bool {
	return ValidateURLContext(ctx, rawURL, opts).Safe
}

// checkResolvedIPPrivate reuses the existing checkPrivateIP rules.
// Wraps it so the call site is named for clarity at the resolved-IP
// validation step (vs the literal-hostname step).
func checkResolvedIPPrivate(ipStr string) string {
	return checkPrivateIP(ipStr)
}
