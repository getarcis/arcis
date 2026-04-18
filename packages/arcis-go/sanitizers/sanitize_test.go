package sanitizers

import (
	"strings"
	"testing"
)

func TestSanitizeString_XSS(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{"removes script tags", "<script>alert('xss')</script>", "<script>"},
		{"removes onerror handler", `<img onerror="alert(1)" src="x">`, "onerror"},
		{"removes javascript protocol", "javascript:alert(1)", "javascript:"},
		{"removes iframe tags", `<iframe src="evil.com">`, "<iframe"},
		{"removes data protocol", "data:text/html,<script>alert(1)</script>", "data:"},
		{"removes vbscript protocol", "vbscript:msgbox(1)", "vbscript:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToLower(result), strings.ToLower(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_XSS_EncodesHTML(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)
	result := sanitizer.SanitizeString("Hello <b>World</b>")

	if !strings.Contains(result, "&lt;") || !strings.Contains(result, "&gt;") {
		t.Errorf("Expected HTML entities, got: %s", result)
	}
}

func TestSanitizeString_SQL(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, true, false, false, false)

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{"removes DROP TABLE", "'; DROP TABLE users; --", "DROP"},
		{"removes OR 1=1 pattern", "1 OR 1=1", "OR 1"},
		{"removes SELECT", "SELECT * FROM users", "SELECT"},
		{"removes DELETE", "1; DELETE FROM users", "DELETE"},
		{"removes SQL comments", "admin'--", "--"},
		{"removes UNION", "1 /* comment */ UNION SELECT", "UNION"},
		{"removes pg_sleep (PostgreSQL timing)", "1; SELECT pg_sleep(5)", "pg_sleep"},
		{"removes WAITFOR DELAY (MSSQL timing)", "1; WAITFOR DELAY '0:0:5'", "WAITFOR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToUpper(result), strings.ToUpper(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_CommandInjection(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, false, false, true)

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{"removes %0a (newline)", "file.txt%0aid", "%0a"},
		{"removes %0d (carriage return)", "file.txt%0dwhoami", "%0d"},
		{"removes %0B (vertical tab)", "file.txt%0Bwhoami", "%0B"},
		{"removes %0C (form feed)", "file.txt%0Cwhoami", "%0C"},
		{"removes %09 (tab)", "file.txt%09whoami", "%09"},
		{"removes %00 (null byte)", "file.txt%00whoami", "%00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToLower(result), strings.ToLower(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_PathTraversal(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, false, true, false)

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{"removes unix path traversal", "../../etc/passwd", "../"},
		{"removes windows path traversal", "..\\..\\windows\\system32", "..\\"},
		{"removes URL-encoded traversal", "%2e%2e%2f%2e%2e%2f", "%2e%2e"},
		{"removes fullwidth dot traversal (U+FF0E)", "\uFF0E\uFF0E/etc/passwd", "../"},
		{"removes fullwidth slash traversal (U+FF0F)", "..\uFF0Fetc", ".."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToLower(result), strings.ToLower(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_SafeInputUnchanged(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, false, true, false)
	input := "file.txt"
	result := sanitizer.SanitizeString(input)
	if result != input {
		t.Errorf("Safe input should be unchanged, got: %s", result)
	}
}

func TestSanitizeMap_PrototypePollution(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, true, true, true, true)

	tests := []struct {
		name        string
		input       map[string]interface{}
		blockedKey  string
		requiredKey string
	}{
		{"blocks __proto__", map[string]interface{}{"__proto__": map[string]interface{}{"admin": true}, "name": "test"}, "__proto__", "name"},
		{"blocks constructor", map[string]interface{}{"constructor": map[string]interface{}{}, "email": "test@test.com"}, "constructor", "email"},
		{"blocks prototype", map[string]interface{}{"prototype": map[string]interface{}{}, "value": 123}, "prototype", "value"},
		{"blocks __defineGetter__ (case-insensitive)", map[string]interface{}{"__defineGetter__": "x", "safe": "y"}, "__defineGetter__", "safe"},
		{"blocks __PROTO__ (case-insensitive)", map[string]interface{}{"__PROTO__": "x", "ok": "y"}, "__PROTO__", "ok"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeMap(tt.input)
			if _, exists := result[tt.blockedKey]; exists {
				t.Errorf("Result should not contain blocked key %q", tt.blockedKey)
			}
			if _, exists := result[tt.requiredKey]; !exists {
				t.Errorf("Result should contain required key %q", tt.requiredKey)
			}
		})
	}
}

func TestSanitizeMap_NoSQLInjection(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, true, false, false)

	tests := []struct {
		name        string
		input       map[string]interface{}
		blockedKeys []string
		requiredKey string
	}{
		{"blocks $gt", map[string]interface{}{"$gt": "", "name": "test"}, []string{"$gt"}, "name"},
		{"blocks $where", map[string]interface{}{"$where": "function(){ return true; }", "id": 1}, []string{"$where"}, "id"},
		{"blocks multiple", map[string]interface{}{"$ne": nil, "$or": []interface{}{}, "valid": true}, []string{"$ne", "$or"}, "valid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeMap(tt.input)
			for _, key := range tt.blockedKeys {
				if _, exists := result[key]; exists {
					t.Errorf("Result should not contain blocked key %q", key)
				}
			}
			if _, exists := result[tt.requiredKey]; !exists {
				t.Errorf("Result should contain required key %q", tt.requiredKey)
			}
		})
	}
}

func TestSanitizeMap_NestedObjects(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)

	t.Run("sanitizes nested strings", func(t *testing.T) {
		input := map[string]interface{}{
			"user": map[string]interface{}{"name": "<script>xss</script>"},
		}
		result := sanitizer.SanitizeMap(input)
		user := result["user"].(map[string]interface{})
		if strings.Contains(user["name"].(string), "<script>") {
			t.Error("Nested string should be sanitized")
		}
	})

	t.Run("sanitizes array items", func(t *testing.T) {
		input := map[string]interface{}{
			"items": []interface{}{"<script>alert(1)</script>", "normal"},
		}
		result := sanitizer.SanitizeMap(input)
		items := result["items"].([]interface{})
		if strings.Contains(items[0].(string), "<script>") {
			t.Error("Array items should be sanitized")
		}
	})
}

func BenchmarkSanitizeString_XSS(b *testing.B) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)
	input := "<script>alert('xss')</script>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizer.SanitizeString(input)
	}
}

func BenchmarkSanitizeMap_Nested(b *testing.B) {
	sanitizer := NewSanitizerWithOptions(true, true, true, true, true)
	input := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "<script>xss</script>",
			"email": "test@test.com",
			"items": []interface{}{"<script>1</script>", "normal"},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizer.SanitizeMap(input)
	}
}
