package sanitizers

import (
	"strings"

	"github.com/GagancM/arcis/core"
)

// ─── Standalone Sanitize Functions ───────────────────────────────────────────

// SanitizeXSS removes XSS patterns from input and HTML-encodes dangerous characters.
func SanitizeXSS(input string) string {
	if input == "" {
		return input
	}
	if len(input) > core.DefaultMaxInputSize {
		input = input[:core.DefaultMaxInputSize]
	}
	result := input
	for _, pattern := range xssPatterns {
		result = pattern.ReplaceAllString(result, "")
	}
	return encodeHTML(result)
}

// SanitizeSQL removes SQL injection patterns from input.
func SanitizeSQL(input string) string {
	if input == "" {
		return input
	}
	if len(input) > core.DefaultMaxInputSize {
		input = input[:core.DefaultMaxInputSize]
	}
	result := input
	for _, pattern := range sqlPatterns {
		result = pattern.ReplaceAllString(result, "[BLOCKED]")
	}
	return result
}

// SanitizePath removes path traversal patterns from input.
func SanitizePath(input string) string {
	if input == "" {
		return input
	}
	if len(input) > core.DefaultMaxInputSize {
		input = input[:core.DefaultMaxInputSize]
	}
	result := input
	for _, pattern := range pathPatterns {
		result = pattern.ReplaceAllString(result, "")
	}
	return result
}

// SanitizeCommand removes command injection patterns from input.
func SanitizeCommand(input string) string {
	if input == "" {
		return input
	}
	if len(input) > core.DefaultMaxInputSize {
		input = input[:core.DefaultMaxInputSize]
	}
	result := input
	for _, pattern := range commandPatterns {
		result = pattern.ReplaceAllString(result, "[BLOCKED]")
	}
	return result
}

// ─── Detect Functions ────────────────────────────────────────────────────────

// DetectXSS checks if a string contains XSS patterns.
func DetectXSS(input string) bool {
	if input == "" {
		return false
	}
	for _, pattern := range xssPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// DetectSQL checks if a string contains SQL injection patterns.
func DetectSQL(input string) bool {
	if input == "" {
		return false
	}
	for _, pattern := range sqlPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// DetectPathTraversal checks if a string contains path traversal patterns.
func DetectPathTraversal(input string) bool {
	if input == "" {
		return false
	}
	for _, pattern := range pathPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// DetectCommandInjection checks if a string contains command injection patterns.
func DetectCommandInjection(input string) bool {
	if input == "" {
		return false
	}
	for _, pattern := range commandPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// SanitizeSSTI removes SSTI patterns from input.
func SanitizeSSTI(input string) string {
	result := input
	for _, pattern := range sstiRemovePatterns {
		result = pattern.ReplaceAllString(result, "")
	}
	return result
}

// SanitizeXXE removes XXE patterns from input.
func SanitizeXXE(input string) string {
	result := input
	for _, pattern := range xxeRemovePatterns {
		result = pattern.ReplaceAllString(result, "")
	}
	return result
}

// DetectSSTI checks if input contains SSTI patterns.
func DetectSSTI(input string) bool {
	if input == "" {
		return false
	}
	for _, pattern := range sstiDetectPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// DetectXXE checks if input contains XXE patterns.
func DetectXXE(input string) bool {
	if input == "" {
		return false
	}
	for _, pattern := range xxeDetectPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// DetectNoSQLInjection checks if a map contains NoSQL injection operators.
// It recursively walks the map up to maxDepth levels deep.
func DetectNoSQLInjection(data map[string]interface{}, maxDepth int) bool {
	if maxDepth <= 0 {
		maxDepth = 10
	}
	return detectNoSQLDepth(data, 0, maxDepth)
}

func detectNoSQLDepth(data map[string]interface{}, depth, maxDepth int) bool {
	if depth > maxDepth || data == nil {
		return false
	}
	for key, value := range data {
		if nosqlDangerousKeys[strings.ToLower(key)] {
			return true
		}
		if nested, ok := value.(map[string]interface{}); ok {
			if detectNoSQLDepth(nested, depth+1, maxDepth) {
				return true
			}
		}
		if arr, ok := value.([]interface{}); ok {
			for _, item := range arr {
				if nested, ok := item.(map[string]interface{}); ok {
					if detectNoSQLDepth(nested, depth+1, maxDepth) {
						return true
					}
				}
			}
		}
	}
	return false
}

// DetectPrototypePollution checks if a map contains prototype pollution keys.
// It recursively walks the map up to maxDepth levels deep.
func DetectPrototypePollution(data map[string]interface{}, maxDepth int) bool {
	if maxDepth <= 0 {
		maxDepth = 10
	}
	return detectProtoDepth(data, 0, maxDepth)
}

func detectProtoDepth(data map[string]interface{}, depth, maxDepth int) bool {
	if depth > maxDepth || data == nil {
		return false
	}
	for key, value := range data {
		if protoPollutionKeys[strings.ToLower(key)] {
			return true
		}
		if nested, ok := value.(map[string]interface{}); ok {
			if detectProtoDepth(nested, depth+1, maxDepth) {
				return true
			}
		}
		if arr, ok := value.([]interface{}); ok {
			for _, item := range arr {
				if nested, ok := item.(map[string]interface{}); ok {
					if detectProtoDepth(nested, depth+1, maxDepth) {
						return true
					}
				}
			}
		}
	}
	return false
}

// ─── Threat Scanner (block-mode helper) ──────────────────────────────────────

// ThreatHit describes the first attack pattern found while scanning a request.
type ThreatHit struct {
	Vector         string // xss | sql | nosql | path | command | prototype
	Rule           string // e.g. "xss/match"
	MatchedPattern string // truncated sample of the matched value
}

// ScanThreats walks data (string, []interface{}, or map[string]interface{}) and
// returns the first threat hit found. Returns nil if no threat detected.
//
// Vector ordering matches Node + Python SDKs for cross-SDK parity (Pattern 7):
//
//	xss → ssti → xxe → email-header → ldap → sql → xpath → path → command
//
// Plus prototype/nosql key checks at any nesting (before string vectors).
//
// LDAP-strict + email-header fire BEFORE command because their attack
// shapes don't overlap with command/SQL syntax; XPath fires AFTER SQL
// because `1' OR '1'='1` matches both patterns and SQL is the canonical
// attribution.
//
// Broad LDAP filter rule `[*()\\x00]` deliberately stays out (every
// parenthesised string trips it). Generic header CRLF stays out for the
// same reason. Use DetectLdapInjection / DetectHeaderInjection at the
// LDAP / response-header call sites directly when needed.
func ScanThreats(data interface{}) *ThreatHit {
	return scanThreatsDepth(data, 0, 10)
}

func scanThreatsDepth(data interface{}, depth, maxDepth int) *ThreatHit {
	if depth > maxDepth {
		return nil
	}
	switch v := data.(type) {
	case map[string]interface{}:
		for k, val := range v {
			lower := strings.ToLower(k)
			if protoPollutionKeys[lower] {
				return &ThreatHit{Vector: "prototype", Rule: "prototype/match", MatchedPattern: k}
			}
			if nosqlDangerousKeys[lower] {
				return &ThreatHit{Vector: "nosql", Rule: "nosql/match", MatchedPattern: k}
			}
			if hit := scanThreatsDepth(val, depth+1, maxDepth); hit != nil {
				return hit
			}
		}
		return nil
	case []interface{}:
		for _, item := range v {
			if hit := scanThreatsDepth(item, depth+1, maxDepth); hit != nil {
				return hit
			}
		}
		return nil
	case string:
		sample := v
		if len(sample) > 80 {
			sample = sample[:80]
		}
		if DetectXSS(v) {
			return &ThreatHit{Vector: "xss", Rule: "xss/match", MatchedPattern: sample}
		}
		if DetectSSTI(v) {
			return &ThreatHit{Vector: "ssti", Rule: "ssti/match", MatchedPattern: sample}
		}
		if DetectXXE(v) {
			return &ThreatHit{Vector: "xxe", Rule: "xxe/match", MatchedPattern: sample}
		}
		// Email-header CRLF + SMTP keyword: very specific.
		if DetectEmailHeaderInjection(v) {
			return &ThreatHit{Vector: "email-header", Rule: "email-header/match", MatchedPattern: sample}
		}
		// LDAP-strict: before command so LDAP doesn't misclass as
		// command on the `*` chars (Raghav's Responza pilot 2026-05-20
		// regression — closed by this ordering in Python; mirrored here).
		if DetectLdapInjectionStrict(v) {
			return &ThreatHit{Vector: "ldap", Rule: "ldap/match", MatchedPattern: sample}
		}
		// SQL before XPath: `1' OR '1'='1` matches both, SQL wins as
		// canonical attribution.
		if DetectSQL(v) {
			return &ThreatHit{Vector: "sql", Rule: "sql/match", MatchedPattern: sample}
		}
		if DetectXPathInjection(v) {
			return &ThreatHit{Vector: "xpath", Rule: "xpath/match", MatchedPattern: sample}
		}
		if DetectPathTraversal(v) {
			return &ThreatHit{Vector: "path", Rule: "path/match", MatchedPattern: sample}
		}
		if DetectCommandInjection(v) {
			return &ThreatHit{Vector: "command", Rule: "command/match", MatchedPattern: sample}
		}
		return nil
	}
	return nil
}

// ─── Helper Functions ────────────────────────────────────────────────────────

// IsDangerousNoSQLKey checks if a key is a dangerous NoSQL operator (case-insensitive).
func IsDangerousNoSQLKey(key string) bool {
	return nosqlDangerousKeys[strings.ToLower(key)]
}

// IsDangerousProtoKey checks if a key is a dangerous prototype pollution key (case-insensitive).
func IsDangerousProtoKey(key string) bool {
	return protoPollutionKeys[strings.ToLower(key)]
}

// GetDangerousOperators returns a list of all blocked NoSQL operators.
func GetDangerousOperators() []string {
	keys := make([]string, 0, len(nosqlDangerousKeys))
	for k := range nosqlDangerousKeys {
		keys = append(keys, k)
	}
	return keys
}

// GetDangerousProtoKeys returns a list of all blocked prototype pollution keys.
func GetDangerousProtoKeys() []string {
	keys := make([]string, 0, len(protoPollutionKeys))
	for k := range protoPollutionKeys {
		keys = append(keys, k)
	}
	return keys
}

// EncodeHTMLEntities encodes HTML special characters in a string.
func EncodeHTMLEntities(input string) string {
	return encodeHTML(input)
}

func encodeHTML(input string) string {
	var sb strings.Builder
	sb.Grow(len(input) * 2)
	for _, r := range input {
		if enc, ok := htmlEncoding[r]; ok {
			sb.WriteString(enc)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
