package sanitizers

import (
	"strings"
	"testing"
)

func TestSanitizeLdapFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
		notContains []string
	}{
		{
			name:        "escapes wildcard",
			input:       "admin*",
			contains:    []string{`\2a`},
			notContains: []string{"*"},
		},
		{
			name:        "escapes open paren",
			input:       "(admin",
			contains:    []string{`\28`},
			notContains: []string{"("},
		},
		{
			name:        "escapes close paren",
			input:       "admin)",
			contains:    []string{`\29`},
			notContains: []string{")"},
		},
		{
			name:        "escapes backslash",
			input:       `ad\min`,
			contains:    []string{`\5c`},
		},
		{
			name:        "escapes NUL byte",
			input:       "ad\x00min",
			contains:    []string{`\00`},
		},
		{
			name:        "OR bypass payload neutralized",
			input:       "*)(uid=*))(|(uid=*",
			notContains: []string{"*", "(", ")"},
		},
		{
			name:     "safe input unchanged",
			input:    "johndoe",
			contains: []string{"johndoe"},
		},
		{
			name:     "empty string",
			input:    "",
			contains: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeLdapFilter(tt.input)
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("expected result to contain %q, got %q", s, result)
				}
			}
			for _, s := range tt.notContains {
				if strings.Contains(result, s) {
					t.Errorf("expected result NOT to contain %q, got %q", s, result)
				}
			}
		})
	}
}

func TestSanitizeLdapFilterIdempotent(t *testing.T) {
	input := "user*(admin)"
	once := SanitizeLdapFilter(input)
	twice := SanitizeLdapFilter(once)
	if once != twice {
		t.Errorf("sanitizeLdapFilter is not idempotent: %q vs %q", once, twice)
	}
}

func TestSanitizeLdapDn(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
	}{
		{"escapes comma", "cn=admin,dc=example", []string{`\2c`}},
		{"escapes equals", "cn=admin", []string{`\3d`}},
		{"escapes plus", "a+b", []string{`\2b`}},
		{"escapes semicolon", "a;b", []string{`\3b`}},
		{"escapes less than", "<admin>", []string{`\3c`}},
		{"escapes greater than", "<admin>", []string{`\3e`}},
		{"safe input unchanged", "johndoe", []string{"johndoe"}},
		{"empty string", "", []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeLdapDn(tt.input)
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("expected result to contain %q, got %q", s, result)
				}
			}
		})
	}
}

func TestDetectLdapInjection(t *testing.T) {
	threats := []string{
		"*",
		"*)(uid=*))(|(uid=*",
		"admin)(&(password=*)",
		`ad\min`,
		"ad\x00min",
	}
	for _, input := range threats {
		t.Run("detects: "+input, func(t *testing.T) {
			if !DetectLdapInjection(input) {
				t.Errorf("expected DetectLdapInjection(%q) = true", input)
			}
		})
	}

	safe := []string{"johndoe", "john.doe@example.com", "John Doe", ""}
	for _, input := range safe {
		t.Run("safe: "+input, func(t *testing.T) {
			if DetectLdapInjection(input) {
				t.Errorf("expected DetectLdapInjection(%q) = false", input)
			}
		})
	}
}
