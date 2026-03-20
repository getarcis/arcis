package logging

import (
	"strings"

	"github.com/GagancM/arcis/core"
)

// SafeLogger provides safe logging with automatic redaction of sensitive data.
type SafeLogger struct {
	sensitiveKeys map[string]bool
	maxLength     int
}

// Default sensitive keys to redact
var defaultSensitiveKeys = []string{
	"password", "passwd", "pwd", "secret", "token", "apikey",
	"api_key", "authorization", "auth", "credit_card", "creditcard",
	"cc", "ssn", "social_security", "private_key", "access_token",
	"refresh_token", "bearer", "jwt", "session", "cookie",
}

// NewSafeLogger creates a new SafeLogger with default settings.
func NewSafeLogger() *SafeLogger {
	keys := make(map[string]bool, len(defaultSensitiveKeys))
	for _, k := range defaultSensitiveKeys {
		keys[strings.ToLower(k)] = true
	}
	return &SafeLogger{
		sensitiveKeys: keys,
		maxLength:     10000,
	}
}

// NewSafeLoggerWithKeys creates a SafeLogger with custom sensitive keys.
// Custom keys are merged with the defaults to ensure base protection.
func NewSafeLoggerWithKeys(keys []string, maxLength int) *SafeLogger {
	keyMap := make(map[string]bool, len(defaultSensitiveKeys)+len(keys))
	for _, k := range defaultSensitiveKeys {
		keyMap[strings.ToLower(k)] = true
	}
	for _, k := range keys {
		keyMap[strings.ToLower(k)] = true
	}
	return &SafeLogger{
		sensitiveKeys: keyMap,
		maxLength:     maxLength,
	}
}

// NewSafeLoggerOnlyKeys creates a SafeLogger with ONLY the specified keys,
// completely replacing the defaults. Use with caution.
func NewSafeLoggerOnlyKeys(keys []string, maxLength int) *SafeLogger {
	keyMap := make(map[string]bool, len(keys))
	for _, k := range keys {
		keyMap[strings.ToLower(k)] = true
	}
	return &SafeLogger{
		sensitiveKeys: keyMap,
		maxLength:     maxLength,
	}
}

// Redact redacts sensitive information from a map.
func (l *SafeLogger) Redact(data map[string]interface{}) map[string]interface{} {
	return l.redactDepth(data, 0)
}

func (l *SafeLogger) redactDepth(data map[string]interface{}, depth int) map[string]interface{} {
	if depth > core.MaxRecursionDepth || data == nil {
		return data
	}

	result := make(map[string]interface{}, len(data))

	for key, value := range data {
		lowKey := strings.ToLower(key)
		if l.sensitiveKeys[lowKey] {
			result[key] = "[REDACTED]"
			continue
		}

		switch v := value.(type) {
		case string:
			result[key] = l.redactString(v)
		case map[string]interface{}:
			result[key] = l.redactDepth(v, depth+1)
		case []interface{}:
			result[key] = l.redactSlice(v, depth+1)
		default:
			result[key] = value
		}
	}

	return result
}

func (l *SafeLogger) redactSlice(data []interface{}, depth int) []interface{} {
	if depth > core.MaxRecursionDepth || data == nil {
		return data
	}

	result := make([]interface{}, len(data))
	for i, item := range data {
		switch v := item.(type) {
		case string:
			result[i] = l.redactString(v)
		case map[string]interface{}:
			result[i] = l.redactDepth(v, depth+1)
		case []interface{}:
			result[i] = l.redactSlice(v, depth+1)
		default:
			result[i] = item
		}
	}
	return result
}

func (l *SafeLogger) redactString(value string) string {
	// Remove control characters (prevent log injection)
	result := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)

	if len(result) > l.maxLength {
		return result[:l.maxLength] + "...[TRUNCATED]"
	}

	return result
}

// RedactString sanitizes a single string for safe logging.
func (l *SafeLogger) RedactString(value string) string {
	return l.redactString(value)
}
