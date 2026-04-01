package sanitizers

import (
	"strings"
	"testing"
)

func TestEncodeForHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"script tags", "<script>", "&lt;script&gt;"},
		{"double quotes", `"quotes"`, "&quot;quotes&quot;"},
		{"single quotes", "it's", "it&#x27;s"},
		{"ampersand", "a & b", "a &amp; b"},
		{"full XSS", "<script>alert('xss')</script>", "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"},
		{"safe text", "safe text 123", "safe text 123"},
		{"empty", "", ""},
		{"mixed", `"quotes" & <tags>`, "&quot;quotes&quot; &amp; &lt;tags&gt;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeForHTML(tt.input)
			if got != tt.expected {
				t.Errorf("EncodeForHTML(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEncodeForAttribute(t *testing.T) {
	t.Run("encodes non-alphanumeric", func(t *testing.T) {
		result := EncodeForAttribute("onclick=alert(1)")
		if strings.Contains(result, "=") || strings.Contains(result, "(") || strings.Contains(result, ")") {
			t.Errorf("should encode special chars, got %q", result)
		}
		if !strings.Contains(result, "&#x") {
			t.Errorf("should contain hex entities, got %q", result)
		}
	})

	t.Run("alphanumeric unchanged", func(t *testing.T) {
		if got := EncodeForAttribute("safe"); got != "safe" {
			t.Errorf("got %q, want %q", got, "safe")
		}
		if got := EncodeForAttribute("ABC123"); got != "ABC123" {
			t.Errorf("got %q, want %q", got, "ABC123")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		if got := EncodeForAttribute(""); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("encodes spaces", func(t *testing.T) {
		if got := EncodeForAttribute("a b"); got != "a&#x20;b" {
			t.Errorf("got %q, want %q", got, "a&#x20;b")
		}
	})

	t.Run("encodes quotes", func(t *testing.T) {
		result := EncodeForAttribute(`"hello"`)
		if strings.Contains(result, `"`) {
			t.Errorf("should not contain raw quotes, got %q", result)
		}
	})
}

func TestEncodeForJS(t *testing.T) {
	t.Run("escapes non-alphanumeric", func(t *testing.T) {
		result := EncodeForJS("alert('xss')")
		if strings.Contains(result, "'") || strings.Contains(result, "(") {
			t.Errorf("should escape specials, got %q", result)
		}
		if !strings.Contains(result, "\\x") {
			t.Errorf("should contain hex escapes, got %q", result)
		}
	})

	t.Run("escapes script close", func(t *testing.T) {
		result := EncodeForJS("</script>")
		if strings.Contains(result, "<") || strings.Contains(result, "/") || strings.Contains(result, ">") {
			t.Errorf("should escape < / >, got %q", result)
		}
	})

	t.Run("alphanumeric unchanged", func(t *testing.T) {
		if got := EncodeForJS("safe123"); got != "safe123" {
			t.Errorf("got %q, want %q", got, "safe123")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		if got := EncodeForJS(""); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("unicode escaped", func(t *testing.T) {
		result := EncodeForJS("hello\u2028world")
		if !strings.Contains(result, "\\u2028") {
			t.Errorf("should contain \\u2028, got %q", result)
		}
	})

	t.Run("backslash escaped", func(t *testing.T) {
		result := EncodeForJS("a\\b")
		if !strings.Contains(result, "\\x5C") {
			t.Errorf("should contain \\x5C, got %q", result)
		}
	})
}

func TestEncodeForURL(t *testing.T) {
	t.Run("encodes spaces and specials", func(t *testing.T) {
		result := EncodeForURL("hello world&foo=bar")
		// Go's url.QueryEscape uses + for spaces
		if strings.Contains(result, "&") || strings.Contains(result, "=") {
			t.Errorf("should encode & and =, got %q", result)
		}
	})

	t.Run("alphanumeric unchanged", func(t *testing.T) {
		if got := EncodeForURL("safe123"); got != "safe123" {
			t.Errorf("got %q, want %q", got, "safe123")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		if got := EncodeForURL(""); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("encodes slashes and hashes", func(t *testing.T) {
		result := EncodeForURL("a/b?c=d#e")
		if strings.Contains(result, "/") || strings.Contains(result, "?") || strings.Contains(result, "#") {
			t.Errorf("should encode / ? #, got %q", result)
		}
	})
}

func TestEncodeForCSS(t *testing.T) {
	t.Run("escapes non-alphanumeric", func(t *testing.T) {
		result := EncodeForCSS("expression(alert(1))")
		if strings.Contains(result, "(") || strings.Contains(result, ")") {
			t.Errorf("should escape parens, got %q", result)
		}
		if !strings.Contains(result, "\\") {
			t.Errorf("should contain backslash escapes, got %q", result)
		}
	})

	t.Run("alphanumeric unchanged", func(t *testing.T) {
		if got := EncodeForCSS("red"); got != "red" {
			t.Errorf("got %q, want %q", got, "red")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		if got := EncodeForCSS(""); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("trailing space per CSS spec", func(t *testing.T) {
		result := EncodeForCSS(";")
		if !strings.HasSuffix(result, " ") {
			t.Errorf("should end with trailing space, got %q", result)
		}
		if !strings.Contains(result, "\\") {
			t.Errorf("should contain backslash, got %q", result)
		}
	})

	t.Run("prevents CSS injection", func(t *testing.T) {
		result := EncodeForCSS("red; background: url(evil)")
		if strings.Contains(result, ";") || strings.Contains(result, ":") || strings.Contains(result, "(") {
			t.Errorf("should escape ; : (, got %q", result)
		}
	})
}
