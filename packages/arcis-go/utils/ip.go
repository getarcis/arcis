package utils

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"unicode"
)

// Platform represents the hosting platform for platform-aware IP detection.
type Platform string

const (
	PlatformAuto       Platform = "auto"
	PlatformGeneric    Platform = "generic"
	PlatformCloudflare Platform = "cloudflare"
	PlatformVercel     Platform = "vercel"
	PlatformFlyio      Platform = "flyio"
	PlatformRender     Platform = "render"
	PlatformFirebase   Platform = "firebase"
	PlatformAWSALB     Platform = "aws-alb"
)

// DetectIPOptions configures platform-aware IP detection.
type DetectIPOptions struct {
	Platform          Platform
	TrustedProxyCount int // Default: 1
}

// maxIPLength is the maximum length for an IP string (IPv6 max).
const maxIPLength = 45

var (
	detectedPlatform Platform
	platformOnce     sync.Once
)

// GetClientIP extracts the client IP address from the request,
// handling common proxy headers. This is the simple/legacy version.
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
	return extractIP(r.RemoteAddr)
}

// DetectClientIP extracts the client IP using platform-aware header detection.
// It reads from the right side of X-Forwarded-For to prevent client spoofing.
func DetectClientIP(r *http.Request, opts *DetectIPOptions) string {
	platform := PlatformAuto
	trustedProxyCount := 1

	if opts != nil {
		if opts.Platform != "" {
			platform = opts.Platform
		}
		if opts.TrustedProxyCount > 0 {
			trustedProxyCount = opts.TrustedProxyCount
		}
	}

	if platform == PlatformAuto {
		platform = autoDetectPlatform()
	}

	// 1. Try platform-specific header
	if platform != PlatformGeneric {
		ip := getPlatformIP(r, platform, trustedProxyCount)
		if ip != "" {
			return ip
		}
	}

	// 2. X-Forwarded-For (right-to-left parsing)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ip := parseXFFRightToLeft(xff, trustedProxyCount)
		if ip != "" {
			return ip
		}
	}

	// 3. X-Real-IP
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return sanitizeIP(xri)
	}

	// 4. RemoteAddr
	ip := extractIP(r.RemoteAddr)
	if ip != "" {
		return ip
	}

	return "unknown"
}

// IsPrivateIP checks if an IP address is in a private/reserved range.
func IsPrivateIP(ip string) bool {
	// Strip IPv4-mapped IPv6 prefix
	cleaned := ip
	if strings.HasPrefix(strings.ToLower(cleaned), "::ffff:") {
		cleaned = cleaned[7:]
	}

	// IPv4 checks
	if strings.Contains(cleaned, ".") && !strings.Contains(cleaned, ":") {
		parts := strings.Split(cleaned, ".")
		if len(parts) != 4 {
			return false
		}

		first := parts[0]
		second := parts[1]

		// 127.x.x.x (loopback)
		if first == "127" {
			return true
		}
		// 10.x.x.x (Class A private)
		if first == "10" {
			return true
		}
		// 192.168.x.x (Class C private)
		if first == "192" && second == "168" {
			return true
		}
		// 172.16-31.x.x (Class B private)
		if first == "172" {
			s := 0
			for _, c := range second {
				s = s*10 + int(c-'0')
			}
			if s >= 16 && s <= 31 {
				return true
			}
		}
		// 169.254.x.x (link-local)
		if first == "169" && second == "254" {
			return true
		}
		// 0.x.x.x (current network)
		if first == "0" {
			return true
		}

		return false
	}

	// IPv6 checks
	lower := strings.ToLower(cleaned)

	// ::1 (loopback)
	if lower == "::1" {
		return true
	}
	// fe80:: (link-local)
	if strings.HasPrefix(lower, "fe80:") || strings.HasPrefix(lower, "fe80%") {
		return true
	}
	// fc00::/7 (unique local) — fc00:: and fd::
	if strings.HasPrefix(lower, "fc") || strings.HasPrefix(lower, "fd") {
		return true
	}

	return false
}

// ResetPlatformCache resets the auto-detected platform cache. For testing only.
func ResetPlatformCache() {
	platformOnce = sync.Once{}
	detectedPlatform = ""
}

func autoDetectPlatform() Platform {
	platformOnce.Do(func() {
		if os.Getenv("CF_PAGES") != "" || os.Getenv("CF_WORKERS") != "" {
			detectedPlatform = PlatformCloudflare
		} else if os.Getenv("VERCEL") != "" {
			detectedPlatform = PlatformVercel
		} else if os.Getenv("FLY_APP_NAME") != "" {
			detectedPlatform = PlatformFlyio
		} else if os.Getenv("RENDER") != "" {
			detectedPlatform = PlatformRender
		} else if os.Getenv("FIREBASE_CONFIG") != "" || os.Getenv("GCLOUD_PROJECT") != "" {
			detectedPlatform = PlatformFirebase
		} else if os.Getenv("AWS_EXECUTION_ENV") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
			detectedPlatform = PlatformAWSALB
		} else {
			detectedPlatform = PlatformGeneric
		}
	})
	return detectedPlatform
}

func getPlatformIP(r *http.Request, platform Platform, trustedProxyCount int) string {
	var header string
	switch platform {
	case PlatformCloudflare:
		header = "Cf-Connecting-Ip"
	case PlatformVercel:
		header = "X-Real-Ip"
	case PlatformFlyio:
		header = "Fly-Client-Ip"
	case PlatformRender:
		header = "X-Render-Client-Ip"
	case PlatformFirebase:
		header = "X-Appengine-User-Ip"
	case PlatformAWSALB:
		// AWS ALB uses X-Forwarded-For, parsed right-to-left
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			return parseXFFRightToLeft(xff, trustedProxyCount)
		}
		return ""
	default:
		return ""
	}

	val := r.Header.Get(header)
	if val == "" {
		return ""
	}
	return sanitizeIP(val)
}

func parseXFFRightToLeft(xff string, trustedProxyCount int) string {
	parts := strings.Split(xff, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	// Remove empty entries
	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			ips = append(ips, p)
		}
	}

	if len(ips) == 0 {
		return ""
	}

	// Read from right: clientIndex = max(0, len - trustedProxyCount)
	idx := len(ips) - trustedProxyCount
	if idx < 0 {
		idx = 0
	}

	return sanitizeIP(ips[idx])
}

func sanitizeIP(ip string) string {
	// Trim whitespace
	ip = strings.TrimSpace(ip)

	// Strip control characters
	ip = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, ip)

	// Truncate to max IP length
	if len(ip) > maxIPLength {
		ip = ip[:maxIPLength]
	}

	return ip
}

func extractIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	// Handle [IPv6]:port format
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		if strings.Contains(remoteAddr, "[") {
			if bracketIdx := strings.LastIndex(remoteAddr, "]"); bracketIdx != -1 && bracketIdx < idx {
				return remoteAddr[:idx]
			}
			return strings.Trim(remoteAddr, "[]")
		}
		return remoteAddr[:idx]
	}
	return remoteAddr
}
