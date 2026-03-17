package arcis

import "testing"

func TestValidateRedirect(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		opts   *ValidateRedirectOptions
		safe   bool
		reason string
	}{
		{"allows relative path", "/dashboard", nil, true, ""},
		{"allows relative with query", "/users?page=2", nil, true, ""},
		{"allows relative with dots", "../settings", nil, true, ""},
		{"blocks absolute URL no allowlist", "http://evil.com", nil, false, "absolute URL not in allowed hosts"},
		{"blocks protocol-relative", "//evil.com/path", nil, false, "protocol-relative URL not in allowed hosts"},
		{"blocks javascript:", "javascript:alert(1)", nil, false, "dangerous protocol: javascript:"},
		{"blocks data:", "data:text/html,<script>alert(1)</script>", nil, false, "dangerous protocol: data:"},
		{"blocks vbscript:", "vbscript:msgbox", nil, false, "dangerous protocol: vbscript:"},
		{"blocks backslash", `\evil.com`, nil, false, "backslash-prefixed URL (browser treats as protocol-relative)"},
		{"blocks empty", "", nil, false, "invalid redirect: empty or not a string"},
		{
			"allows absolute with allowed host",
			"https://myapp.com/home",
			&ValidateRedirectOptions{AllowedHosts: []string{"myapp.com"}},
			true, "",
		},
		{
			"blocks absolute with wrong host",
			"https://evil.com/home",
			&ValidateRedirectOptions{AllowedHosts: []string{"myapp.com"}},
			false, "host not allowed: evil.com",
		},
		{
			"allows protocol-relative with allowed host",
			"//myapp.com/path",
			&ValidateRedirectOptions{AllowedHosts: []string{"myapp.com"}},
			true, "",
		},
		{
			"strips control chars before checking",
			"java\tscript:alert(1)",
			nil,
			false, "dangerous protocol: javascript:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRedirect(tt.url, tt.opts)
			if result.Safe != tt.safe {
				t.Errorf("ValidateRedirect(%q).Safe = %v, want %v (reason: %s)", tt.url, result.Safe, tt.safe, result.Reason)
			}
			if tt.reason != "" && result.Reason != tt.reason {
				t.Errorf("ValidateRedirect(%q).Reason = %q, want %q", tt.url, result.Reason, tt.reason)
			}
		})
	}
}

func TestIsRedirectSafe(t *testing.T) {
	if IsRedirectSafe("/dashboard", nil) != true {
		t.Error("Expected safe redirect")
	}
	if IsRedirectSafe("http://evil.com", nil) != false {
		t.Error("Expected unsafe redirect")
	}
}
