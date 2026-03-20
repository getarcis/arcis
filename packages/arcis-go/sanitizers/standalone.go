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
	for _, pattern := range cmdPatterns {
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
	for _, pattern := range cmdPatterns {
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
