package sanitizers

import (
	"strings"
	"testing"
)

// M1 — SSTI operator-free dunder patterns.
func TestAuditM1_SSTIDunderPatterns(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{"jinja dunder dict", "hello ${self.__dict__} world", "__dict__"},
		{"pug dunder class", "#{obj.__class__}", "__class__"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := SanitizeSSTI(tt.input)
			if strings.Contains(out, tt.notContains) {
				t.Errorf("expected %q to be removed from %q, got %q", tt.notContains, tt.input, out)
			}
		})
	}
}

// M2 — XSS <style> tag removal.
func TestAuditM2_XSSStyleTagRemoval(t *testing.T) {
	tests := []string{
		"<style>body { x: expression(alert(1)) }</style>",
		`<style type="text/css">`,
	}
	for _, in := range tests {
		out := strings.ToLower(SanitizeXSS(in))
		if strings.Contains(out, "<style") {
			t.Errorf("expected <style to be stripped from %q, got %q", in, out)
		}
	}
}

// M10 — Null byte injection patterns in path sanitization.
func TestAuditM10_NullByteInPath(t *testing.T) {
	tests := []string{
		"../etc/passwd%00.jpg",
		"file.txt\x00.png",
	}
	for _, in := range tests {
		out := SanitizePath(in)
		if strings.Contains(strings.ToLower(out), "%00") {
			t.Errorf("expected %%00 stripped from %q, got %q", in, out)
		}
		if strings.Contains(out, "\x00") {
			t.Errorf("expected literal NUL stripped from %q, got %q", in, out)
		}
	}
}
