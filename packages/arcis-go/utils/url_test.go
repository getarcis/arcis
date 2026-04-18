package utils

import (
	"strings"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		opts   *ValidateURLOptions
		safe   bool
		reason string
	}{
		{"allows safe URL", "https://api.example.com/data", nil, true, ""},
		{"allows http", "http://example.com", nil, true, ""},
		{"blocks empty", "", nil, false, "invalid URL: empty or not a string"},
		{"blocks no scheme", "example.com", nil, false, "invalid URL: failed to parse"},
		{"blocks file protocol", "file:///etc/passwd", nil, false, "disallowed protocol: file:"},
		{"blocks ftp protocol", "ftp://evil.com/file", nil, false, "disallowed protocol: ftp:"},
		{"blocks localhost", "http://localhost/secret", nil, false, "loopback address"},
		{"blocks 127.0.0.1", "http://127.0.0.1/admin", nil, false, "loopback address"},
		{"blocks 127.x.x.x", "http://127.0.0.2/admin", nil, false, "loopback address"},
		{"blocks 0.0.0.0", "http://0.0.0.0/admin", nil, false, "loopback address"},
		{"blocks .localhost", "http://app.localhost/admin", nil, false, "loopback address"},
		{"blocks 10.x private", "http://10.0.0.1/admin", nil, false, "private address (10.0.0.0/8)"},
		{"blocks 172.16.x private", "http://172.16.0.1/admin", nil, false, "private address (172.16.0.0/12)"},
		{"blocks 192.168.x private", "http://192.168.1.1/admin", nil, false, "private address (192.168.0.0/16)"},
		{"blocks link-local", "http://169.254.169.254/latest/meta-data/", nil, false, "link-local address (169.254.0.0/16)"},
		{"blocks cloud metadata", "http://metadata.google.internal/", nil, false, "cloud metadata endpoint"},
		{"blocks credentials", "http://user:pass@example.com", nil, false, "URL contains credentials"},
		{
			"allows with AllowLocalhost",
			"http://localhost/api",
			&ValidateURLOptions{AllowLocalhost: true},
			true, "",
		},
		{
			"allows with AllowPrivate",
			"http://10.0.0.1/api",
			&ValidateURLOptions{AllowPrivate: true},
			true, "",
		},
		{
			"allows with AllowedHosts",
			"http://10.0.0.1/api",
			&ValidateURLOptions{AllowedHosts: []string{"10.0.0.1"}},
			true, "",
		},
		{
			"blocks with BlockedHosts",
			"http://evil.internal/api",
			&ValidateURLOptions{BlockedHosts: []string{"evil.internal"}},
			false, "blocked host: evil.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateURL(tt.url, tt.opts)
			if result.Safe != tt.safe {
				t.Errorf("ValidateURL(%q).Safe = %v, want %v (reason: %s)", tt.url, result.Safe, tt.safe, result.Reason)
			}
			if tt.reason != "" && result.Reason != tt.reason {
				t.Errorf("ValidateURL(%q).Reason = %q, want %q", tt.url, result.Reason, tt.reason)
			}
		})
	}
}

func TestValidateURL_DecimalIP(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		safe       bool
		reasonHas  string
	}{
		{"blocks decimal 127.0.0.1 (2130706433)", "http://2130706433/", false, "loopback"},
		{"blocks decimal 10.0.0.1 (167772161)", "http://167772161/", false, "private"},
		{"blocks decimal 192.168.1.1 (3232235777)", "http://3232235777/", false, "private"},
		{"blocks decimal 169.254.169.254 (2852039166)", "http://2852039166/", false, "link-local"},
		{"allows safe decimal 8.8.8.8 (134744072)", "http://134744072/", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateURL(tt.url, nil)
			if result.Safe != tt.safe {
				t.Errorf("ValidateURL(%q).Safe = %v, want %v (reason: %s)", tt.url, result.Safe, tt.safe, result.Reason)
			}
			if tt.reasonHas != "" && !strings.Contains(strings.ToLower(result.Reason), tt.reasonHas) {
				t.Errorf("ValidateURL(%q).Reason = %q, want it to contain %q", tt.url, result.Reason, tt.reasonHas)
			}
		})
	}
}

func TestValidateURL_OctalHexIP(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		safe       bool
		reasonHas  string
	}{
		{"blocks octal 127.0.0.1 (0177.0.0.1)", "http://0177.0.0.1/", false, "loopback"},
		{"blocks octal 10.0.0.1 (012.0.0.1)", "http://012.0.0.1/", false, "private"},
		{"blocks hex 127.0.0.1 (0x7f.0.0.1)", "http://0x7f.0.0.1/", false, "loopback"},
		{"blocks hex 10.0.0.1 (0x0a.0.0.1)", "http://0x0a.0.0.1/", false, "private"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateURL(tt.url, nil)
			if result.Safe != tt.safe {
				t.Errorf("ValidateURL(%q).Safe = %v, want %v (reason: %s)", tt.url, result.Safe, tt.safe, result.Reason)
			}
			if tt.reasonHas != "" && !strings.Contains(strings.ToLower(result.Reason), tt.reasonHas) {
				t.Errorf("ValidateURL(%q).Reason = %q, want it to contain %q", tt.url, result.Reason, tt.reasonHas)
			}
		})
	}
}

func TestIsURLSafe(t *testing.T) {
	if IsURLSafe("https://example.com", nil) != true {
		t.Error("Expected safe URL")
	}
	if IsURLSafe("http://localhost", nil) != false {
		t.Error("Expected unsafe URL")
	}
}
