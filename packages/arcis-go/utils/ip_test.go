package utils

import (
	"net/http/httptest"
	"os"
	"testing"
)

// ─── Legacy GetClientIP tests ────────────────────────────────────────────────

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		{"uses RemoteAddr", "192.168.1.1:12345", "", "", "192.168.1.1"},
		{"prefers X-Forwarded-For", "127.0.0.1:12345", "10.0.0.1, 192.168.1.1", "", "10.0.0.1"},
		{"uses X-Real-IP", "127.0.0.1:12345", "", "10.0.0.2", "10.0.0.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			result := GetClientIP(req)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ─── DetectClientIP tests ────────────────────────────────────────────────────

func TestDetectClientIP_Cloudflare(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.50")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformCloudflare})
	if result != "203.0.113.50" {
		t.Errorf("Expected 203.0.113.50, got %q", result)
	}
}

func TestDetectClientIP_Vercel(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-Ip", "198.51.100.1")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformVercel})
	if result != "198.51.100.1" {
		t.Errorf("Expected 198.51.100.1, got %q", result)
	}
}

func TestDetectClientIP_Flyio(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Fly-Client-Ip", "10.20.30.40")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformFlyio})
	if result != "10.20.30.40" {
		t.Errorf("Expected 10.20.30.40, got %q", result)
	}
}

func TestDetectClientIP_Render(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Render-Client-Ip", "172.16.0.1")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformRender})
	if result != "172.16.0.1" {
		t.Errorf("Expected 172.16.0.1, got %q", result)
	}
}

func TestDetectClientIP_Firebase(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Appengine-User-Ip", "8.8.8.8")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformFirebase})
	if result != "8.8.8.8" {
		t.Errorf("Expected 8.8.8.8, got %q", result)
	}
}

func TestDetectClientIP_AWSALB_XFF(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")
	req.RemoteAddr = "127.0.0.1:1234"

	// With 1 trusted proxy, pick from right: index = max(0, 3-1) = 2 → 3.3.3.3
	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformAWSALB, TrustedProxyCount: 1})
	if result != "3.3.3.3" {
		t.Errorf("Expected 3.3.3.3, got %q", result)
	}
}

func TestDetectClientIP_AWSALB_TwoProxies(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")
	req.RemoteAddr = "127.0.0.1:1234"

	// 2 trusted proxies: index = max(0, 3-2) = 1 → 2.2.2.2
	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformAWSALB, TrustedProxyCount: 2})
	if result != "2.2.2.2" {
		t.Errorf("Expected 2.2.2.2, got %q", result)
	}
}

func TestDetectClientIP_GenericXFF_RightToLeft(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "spoofed, real-client, proxy")
	req.RemoteAddr = "127.0.0.1:1234"

	// 1 trusted proxy: index = max(0, 3-1) = 2 → proxy
	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformGeneric, TrustedProxyCount: 1})
	if result != "proxy" {
		t.Errorf("Expected 'proxy', got %q", result)
	}
}

func TestDetectClientIP_GenericXFF_HighProxyCount(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	req.RemoteAddr = "127.0.0.1:1234"

	// 10 trusted proxies but only 2 IPs: index = max(0, 2-10) = 0 → 1.1.1.1
	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformGeneric, TrustedProxyCount: 10})
	if result != "1.1.1.1" {
		t.Errorf("Expected 1.1.1.1, got %q", result)
	}
}

func TestDetectClientIP_FallbackXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-Ip", "99.99.99.99")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformGeneric})
	if result != "99.99.99.99" {
		t.Errorf("Expected 99.99.99.99, got %q", result)
	}
}

func TestDetectClientIP_FallbackRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "5.5.5.5:9999"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformGeneric})
	if result != "5.5.5.5" {
		t.Errorf("Expected 5.5.5.5, got %q", result)
	}
}

func TestDetectClientIP_Unknown(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformGeneric})
	if result != "unknown" {
		t.Errorf("Expected 'unknown', got %q", result)
	}
}

func TestDetectClientIP_DefaultOptions(t *testing.T) {
	ResetPlatformCache()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "4.4.4.4:1234"

	result := DetectClientIP(req, nil)
	if result != "4.4.4.4" {
		t.Errorf("Expected 4.4.4.4, got %q", result)
	}
}

func TestDetectClientIP_SanitizesWhitespace(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Connecting-Ip", "  203.0.113.50  ")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformCloudflare})
	if result != "203.0.113.50" {
		t.Errorf("Expected 203.0.113.50, got %q", result)
	}
}

func TestDetectClientIP_TruncatesLongIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	longIP := "aaaa:bbbb:cccc:dddd:eeee:ffff:1111:2222:3333:4444:5555:6666"
	req.Header.Set("Cf-Connecting-Ip", longIP)
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformCloudflare})
	if len(result) > maxIPLength {
		t.Errorf("Expected max length %d, got %d", maxIPLength, len(result))
	}
}

func TestDetectClientIP_PlatformFallsBackToXFF(t *testing.T) {
	// Platform header missing, should fall through to XFF
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.RemoteAddr = "127.0.0.1:1234"

	result := DetectClientIP(req, &DetectIPOptions{Platform: PlatformCloudflare})
	if result != "9.9.9.9" {
		t.Errorf("Expected 9.9.9.9, got %q", result)
	}
}

// ─── Auto-detection tests ────────────────────────────────────────────────────

func TestAutoDetect_Cloudflare(t *testing.T) {
	ResetPlatformCache()
	os.Setenv("CF_PAGES", "1")
	defer os.Unsetenv("CF_PAGES")

	p := autoDetectPlatform()
	if p != PlatformCloudflare {
		t.Errorf("Expected cloudflare, got %s", p)
	}
	ResetPlatformCache()
}

func TestAutoDetect_Vercel(t *testing.T) {
	ResetPlatformCache()
	os.Setenv("VERCEL", "1")
	defer os.Unsetenv("VERCEL")

	p := autoDetectPlatform()
	if p != PlatformVercel {
		t.Errorf("Expected vercel, got %s", p)
	}
	ResetPlatformCache()
}

func TestAutoDetect_Flyio(t *testing.T) {
	ResetPlatformCache()
	os.Setenv("FLY_APP_NAME", "myapp")
	defer os.Unsetenv("FLY_APP_NAME")

	p := autoDetectPlatform()
	if p != PlatformFlyio {
		t.Errorf("Expected flyio, got %s", p)
	}
	ResetPlatformCache()
}

func TestAutoDetect_Generic(t *testing.T) {
	ResetPlatformCache()
	p := autoDetectPlatform()
	if p != PlatformGeneric {
		t.Errorf("Expected generic, got %s", p)
	}
	ResetPlatformCache()
}

// ─── IsPrivateIP tests ──────────────────────────────────────────────────────

func TestIsPrivateIP_IPv4(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		// Loopback
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		// Class A
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		// Class B
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		// Class C
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// Link-local
		{"169.254.0.1", true},
		{"169.254.255.255", true},
		// Current network
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.50", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"::1", true},
		{"fe80::1", true},
		{"fe80::abc:def", true},
		{"fc00::1", true},
		{"fd12::1", true},
		{"2001:db8::1", false},
		{"2607:f8b0:4004:800::200e", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP_IPv4Mapped(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
