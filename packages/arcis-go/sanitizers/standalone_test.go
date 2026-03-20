package sanitizers

import (
	"strings"
	"testing"
)

// ─── SanitizeXSS tests ──────────────────────────────────────────────────────

func TestSanitizeXSS_RemovesScriptTags(t *testing.T) {
	result := SanitizeXSS(`hello <script>alert("xss")</script> world`)
	if strings.Contains(result, "<script") || strings.Contains(result, "alert") {
		t.Errorf("Expected script tags removed, got %q", result)
	}
}

func TestSanitizeXSS_RemovesEventHandlers(t *testing.T) {
	result := SanitizeXSS(`<img onerror=alert(1) src=x>`)
	if strings.Contains(result, "onerror") {
		t.Errorf("Expected event handler removed, got %q", result)
	}
}

func TestSanitizeXSS_EncodesHTMLEntities(t *testing.T) {
	result := SanitizeXSS(`<div>hello</div>`)
	if strings.Contains(result, "<div>") {
		t.Errorf("Expected HTML encoded, got %q", result)
	}
	if !strings.Contains(result, "&lt;") {
		t.Errorf("Expected &lt; in output, got %q", result)
	}
}

func TestSanitizeXSS_EmptyString(t *testing.T) {
	if SanitizeXSS("") != "" {
		t.Error("Empty string should return empty")
	}
}

func TestSanitizeXSS_SafeString(t *testing.T) {
	result := SanitizeXSS("hello world")
	if result != "hello world" {
		t.Errorf("Safe string should pass through, got %q", result)
	}
}

func TestSanitizeXSS_RemovesJavascriptProtocol(t *testing.T) {
	result := SanitizeXSS(`javascript:alert(1)`)
	if strings.Contains(result, "javascript:") {
		t.Errorf("Expected javascript: removed, got %q", result)
	}
}

// ─── SanitizeSQL tests ──────────────────────────────────────────────────────

func TestSanitizeSQL_BlocksSQLKeywords(t *testing.T) {
	tests := []string{
		"SELECT * FROM users",
		"DROP TABLE users",
		"1; DELETE FROM users",
		"1 OR 1=1",
		"UNION SELECT password FROM users",
	}
	for _, input := range tests {
		result := SanitizeSQL(input)
		if !strings.Contains(result, "[BLOCKED]") {
			t.Errorf("Expected [BLOCKED] for %q, got %q", input, result)
		}
	}
}

func TestSanitizeSQL_PassesSafeInput(t *testing.T) {
	result := SanitizeSQL("John Doe")
	if strings.Contains(result, "[BLOCKED]") {
		t.Errorf("Safe input should not be blocked, got %q", result)
	}
}

func TestSanitizeSQL_EmptyString(t *testing.T) {
	if SanitizeSQL("") != "" {
		t.Error("Empty string should return empty")
	}
}

func TestSanitizeSQL_BlocksSQLComments(t *testing.T) {
	result := SanitizeSQL("value -- comment")
	if !strings.Contains(result, "[BLOCKED]") {
		t.Errorf("Expected SQL comment blocked, got %q", result)
	}
}

// ─── SanitizePath tests ─────────────────────────────────────────────────────

func TestSanitizePath_RemovesDotDotSlash(t *testing.T) {
	result := SanitizePath("../../etc/passwd")
	if strings.Contains(result, "..") {
		t.Errorf("Expected path traversal removed, got %q", result)
	}
}

func TestSanitizePath_RemovesEncodedTraversal(t *testing.T) {
	result := SanitizePath("%2e%2e/etc/passwd")
	if strings.Contains(strings.ToLower(result), "%2e%2e") {
		t.Errorf("Expected encoded traversal removed, got %q", result)
	}
}

func TestSanitizePath_PassesSafeInput(t *testing.T) {
	result := SanitizePath("images/photo.jpg")
	if result != "images/photo.jpg" {
		t.Errorf("Safe path should pass through, got %q", result)
	}
}

func TestSanitizePath_EmptyString(t *testing.T) {
	if SanitizePath("") != "" {
		t.Error("Empty string should return empty")
	}
}

// ─── SanitizeCommand tests ──────────────────────────────────────────────────

func TestSanitizeCommand_BlocksShellChars(t *testing.T) {
	tests := []string{
		"foo; rm -rf /",
		"foo | cat /etc/passwd",
		"$(whoami)",
		"foo && ls",
	}
	for _, input := range tests {
		result := SanitizeCommand(input)
		if !strings.Contains(result, "[BLOCKED]") {
			t.Errorf("Expected [BLOCKED] for %q, got %q", input, result)
		}
	}
}

func TestSanitizeCommand_PassesSafeInput(t *testing.T) {
	result := SanitizeCommand("hello world")
	if strings.Contains(result, "[BLOCKED]") {
		t.Errorf("Safe input should not be blocked, got %q", result)
	}
}

func TestSanitizeCommand_EmptyString(t *testing.T) {
	if SanitizeCommand("") != "" {
		t.Error("Empty string should return empty")
	}
}

// ─── DetectXSS tests ────────────────────────────────────────────────────────

func TestDetectXSS_DetectsScriptTags(t *testing.T) {
	if !DetectXSS(`<script>alert("xss")</script>`) {
		t.Error("Should detect script tags")
	}
}

func TestDetectXSS_DetectsEventHandlers(t *testing.T) {
	if !DetectXSS(`<img onerror=alert(1)>`) {
		t.Error("Should detect event handlers")
	}
}

func TestDetectXSS_DetectsJavascriptProtocol(t *testing.T) {
	if !DetectXSS(`javascript:alert(1)`) {
		t.Error("Should detect javascript: protocol")
	}
}

func TestDetectXSS_DetectsIframe(t *testing.T) {
	if !DetectXSS(`<iframe src="evil.com">`) {
		t.Error("Should detect iframe")
	}
}

func TestDetectXSS_SafeInput(t *testing.T) {
	if DetectXSS("hello world") {
		t.Error("Should not detect XSS in safe input")
	}
}

func TestDetectXSS_EmptyString(t *testing.T) {
	if DetectXSS("") {
		t.Error("Empty string should return false")
	}
}

// ─── DetectSQL tests ────────────────────────────────────────────────────────

func TestDetectSQL_DetectsKeywords(t *testing.T) {
	attacks := []string{
		"SELECT * FROM users",
		"DROP TABLE users",
		"UNION SELECT 1",
		"1 OR 1=1",
		"SLEEP(5)",
	}
	for _, input := range attacks {
		if !DetectSQL(input) {
			t.Errorf("Should detect SQL injection: %q", input)
		}
	}
}

func TestDetectSQL_SafeInput(t *testing.T) {
	if DetectSQL("hello world") {
		t.Error("Should not detect SQL in safe input")
	}
}

func TestDetectSQL_EmptyString(t *testing.T) {
	if DetectSQL("") {
		t.Error("Empty string should return false")
	}
}

// ─── DetectPathTraversal tests ──────────────────────────────────────────────

func TestDetectPathTraversal_Detects(t *testing.T) {
	attacks := []string{
		"../../etc/passwd",
		"..\\windows\\system32",
		"%2e%2e/etc/passwd",
		"%252e%252e/",
	}
	for _, input := range attacks {
		if !DetectPathTraversal(input) {
			t.Errorf("Should detect path traversal: %q", input)
		}
	}
}

func TestDetectPathTraversal_SafeInput(t *testing.T) {
	if DetectPathTraversal("images/photo.jpg") {
		t.Error("Should not detect path traversal in safe input")
	}
}

func TestDetectPathTraversal_EmptyString(t *testing.T) {
	if DetectPathTraversal("") {
		t.Error("Empty string should return false")
	}
}

// ─── DetectCommandInjection tests ───────────────────────────────────────────

func TestDetectCommandInjection_Detects(t *testing.T) {
	attacks := []string{
		"foo; rm -rf /",
		"$(whoami)",
		"foo | cat",
		"foo && ls",
	}
	for _, input := range attacks {
		if !DetectCommandInjection(input) {
			t.Errorf("Should detect command injection: %q", input)
		}
	}
}

func TestDetectCommandInjection_SafeInput(t *testing.T) {
	if DetectCommandInjection("hello world") {
		t.Error("Should not detect command injection in safe input")
	}
}

func TestDetectCommandInjection_EmptyString(t *testing.T) {
	if DetectCommandInjection("") {
		t.Error("Empty string should return false")
	}
}

// ─── DetectNoSQLInjection tests ─────────────────────────────────────────────

func TestDetectNoSQLInjection_DetectsDangerousKeys(t *testing.T) {
	data := map[string]interface{}{
		"username": "admin",
		"$gt":      "",
	}
	if !DetectNoSQLInjection(data, 10) {
		t.Error("Should detect $gt operator")
	}
}

func TestDetectNoSQLInjection_DetectsNested(t *testing.T) {
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"password": map[string]interface{}{
				"$ne": "",
			},
		},
	}
	if !DetectNoSQLInjection(data, 10) {
		t.Error("Should detect nested $ne operator")
	}
}

func TestDetectNoSQLInjection_DetectsInArray(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{
				"$where": "1==1",
			},
		},
	}
	if !DetectNoSQLInjection(data, 10) {
		t.Error("Should detect $where in array")
	}
}

func TestDetectNoSQLInjection_CaseInsensitive(t *testing.T) {
	data := map[string]interface{}{
		"$GT": "value",
	}
	if !DetectNoSQLInjection(data, 10) {
		t.Error("Should detect case-insensitive $GT")
	}
}

func TestDetectNoSQLInjection_SafeData(t *testing.T) {
	data := map[string]interface{}{
		"username": "admin",
		"email":    "admin@test.com",
	}
	if DetectNoSQLInjection(data, 10) {
		t.Error("Should not detect NoSQL injection in safe data")
	}
}

func TestDetectNoSQLInjection_NilMap(t *testing.T) {
	if DetectNoSQLInjection(nil, 10) {
		t.Error("Nil map should return false")
	}
}

func TestDetectNoSQLInjection_RespectsDepthLimit(t *testing.T) {
	data := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"$gt": "1",
			},
		},
	}
	if DetectNoSQLInjection(data, 1) {
		t.Error("Should not detect beyond depth limit")
	}
}

// ─── DetectPrototypePollution tests ─────────────────────────────────────────

func TestDetectPrototypePollution_DetectsProto(t *testing.T) {
	data := map[string]interface{}{
		"__proto__": map[string]interface{}{
			"isAdmin": true,
		},
	}
	if !DetectPrototypePollution(data, 10) {
		t.Error("Should detect __proto__")
	}
}

func TestDetectPrototypePollution_DetectsConstructor(t *testing.T) {
	data := map[string]interface{}{
		"constructor": map[string]interface{}{
			"prototype": map[string]interface{}{},
		},
	}
	if !DetectPrototypePollution(data, 10) {
		t.Error("Should detect constructor")
	}
}

func TestDetectPrototypePollution_CaseInsensitive(t *testing.T) {
	data := map[string]interface{}{
		"__PROTO__": "value",
	}
	if !DetectPrototypePollution(data, 10) {
		t.Error("Should detect case-insensitive __PROTO__")
	}
}

func TestDetectPrototypePollution_DetectsNested(t *testing.T) {
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"__proto__": map[string]interface{}{},
		},
	}
	if !DetectPrototypePollution(data, 10) {
		t.Error("Should detect nested __proto__")
	}
}

func TestDetectPrototypePollution_SafeData(t *testing.T) {
	data := map[string]interface{}{
		"name":  "test",
		"value": 123,
	}
	if DetectPrototypePollution(data, 10) {
		t.Error("Should not detect prototype pollution in safe data")
	}
}

func TestDetectPrototypePollution_NilMap(t *testing.T) {
	if DetectPrototypePollution(nil, 10) {
		t.Error("Nil map should return false")
	}
}

func TestDetectPrototypePollution_DetectsDefineGetter(t *testing.T) {
	data := map[string]interface{}{
		"__defineGetter__": "value",
	}
	if !DetectPrototypePollution(data, 10) {
		t.Error("Should detect __defineGetter__")
	}
}

// ─── IsDangerousNoSQLKey tests ──────────────────────────────────────────────

func TestIsDangerousNoSQLKey_Dangerous(t *testing.T) {
	keys := []string{"$gt", "$gte", "$lt", "$lte", "$ne", "$eq", "$in", "$nin", "$and", "$or", "$not", "$exists", "$where", "$regex", "$type", "$expr"}
	for _, key := range keys {
		if !IsDangerousNoSQLKey(key) {
			t.Errorf("Expected %q to be dangerous", key)
		}
	}
}

func TestIsDangerousNoSQLKey_CaseInsensitive(t *testing.T) {
	if !IsDangerousNoSQLKey("$GT") {
		t.Error("Should be case insensitive")
	}
}

func TestIsDangerousNoSQLKey_Safe(t *testing.T) {
	if IsDangerousNoSQLKey("username") {
		t.Error("Normal key should not be dangerous")
	}
}

// ─── IsDangerousProtoKey tests ──────────────────────────────────────────────

func TestIsDangerousProtoKey_Dangerous(t *testing.T) {
	keys := []string{"__proto__", "constructor", "prototype", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"}
	for _, key := range keys {
		if !IsDangerousProtoKey(key) {
			t.Errorf("Expected %q to be dangerous", key)
		}
	}
}

func TestIsDangerousProtoKey_CaseInsensitive(t *testing.T) {
	if !IsDangerousProtoKey("__PROTO__") {
		t.Error("Should be case insensitive")
	}
	if !IsDangerousProtoKey("CONSTRUCTOR") {
		t.Error("Should be case insensitive")
	}
}

func TestIsDangerousProtoKey_Safe(t *testing.T) {
	if IsDangerousProtoKey("name") {
		t.Error("Normal key should not be dangerous")
	}
}

// ─── GetDangerousOperators tests ────────────────────────────────────────────

func TestGetDangerousOperators_ReturnsAll(t *testing.T) {
	ops := GetDangerousOperators()
	if len(ops) != len(nosqlDangerousKeys) {
		t.Errorf("Expected %d operators, got %d", len(nosqlDangerousKeys), len(ops))
	}
	// Verify all are $-prefixed
	for _, op := range ops {
		if !strings.HasPrefix(op, "$") {
			t.Errorf("Expected $-prefixed operator, got %q", op)
		}
	}
}

// ─── GetDangerousProtoKeys tests ────────────────────────────────────────────

func TestGetDangerousProtoKeys_ReturnsAll(t *testing.T) {
	keys := GetDangerousProtoKeys()
	if len(keys) != len(protoPollutionKeys) {
		t.Errorf("Expected %d keys, got %d", len(protoPollutionKeys), len(keys))
	}
}

// ─── EncodeHTMLEntities tests ───────────────────────────────────────────────

func TestEncodeHTMLEntities_EncodesAll(t *testing.T) {
	result := EncodeHTMLEntities(`<div class="test">&'hello'</div>`)
	if strings.Contains(result, "<") || strings.Contains(result, ">") {
		t.Errorf("Expected all HTML chars encoded, got %q", result)
	}
	if !strings.Contains(result, "&lt;") {
		t.Errorf("Expected &lt; in output, got %q", result)
	}
	if !strings.Contains(result, "&gt;") {
		t.Errorf("Expected &gt; in output, got %q", result)
	}
	if !strings.Contains(result, "&quot;") {
		t.Errorf("Expected &quot; in output, got %q", result)
	}
	if !strings.Contains(result, "&amp;") {
		t.Errorf("Expected &amp; in output, got %q", result)
	}
	if !strings.Contains(result, "&#x27;") {
		t.Errorf("Expected &#x27; in output, got %q", result)
	}
}

func TestEncodeHTMLEntities_SafeString(t *testing.T) {
	result := EncodeHTMLEntities("hello world")
	if result != "hello world" {
		t.Errorf("Safe string should pass through, got %q", result)
	}
}

func TestEncodeHTMLEntities_EmptyString(t *testing.T) {
	result := EncodeHTMLEntities("")
	if result != "" {
		t.Error("Empty string should return empty")
	}
}
