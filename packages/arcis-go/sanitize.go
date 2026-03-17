package arcis

import (
	"regexp"
	"strings"
)

// Pre-compiled XSS patterns for performance (ReDoS-safe)
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
	regexp.MustCompile(`(?i)<iframe`),
	regexp.MustCompile(`(?i)<object`),
	regexp.MustCompile(`(?i)<embed`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=])data:`),
	regexp.MustCompile(`(?i)%3Cscript`),
	regexp.MustCompile(`(?i)<svg[^>]*onload`),
}

// Pre-compiled SQL injection patterns
var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b`),
	regexp.MustCompile(`(--|/\*|\*/)`),
	regexp.MustCompile(`(;|\|\||&&)`),
	regexp.MustCompile(`(?i)\bOR\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)\bOR\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]`),
	regexp.MustCompile(`(?i)\bAND\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)\bAND\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]`),
	regexp.MustCompile(`(?i)\bSLEEP\s*\(\s*\d+\s*\)`),
	regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`),
}

// Pre-compiled path traversal patterns
var pathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\.\/`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`(?i)%2e%2e`),
	regexp.MustCompile(`(?i)%252e`),
}

// Pre-compiled command injection patterns
var cmdPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|` + "`" + `$()]`),
	regexp.MustCompile(`(?i)\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b`),
}

// NoSQL dangerous keys that could be used for injection
var nosqlDangerousKeys = map[string]bool{
	"$gt": true, "$gte": true, "$lt": true, "$lte": true,
	"$ne": true, "$eq": true, "$in": true, "$nin": true,
	"$and": true, "$or": true, "$not": true, "$exists": true,
	"$type": true, "$regex": true, "$where": true, "$expr": true,
}

// Prototype pollution dangerous keys (for JS interop).
// Case-insensitive matching is done in sanitizeMapDepth.
var protoPollutionKeys = map[string]bool{
	"__proto__":        true,
	"constructor":      true,
	"prototype":        true,
	"__definegetter__": true,
	"__definesetter__": true,
	"__lookupgetter__": true,
	"__lookupsetter__": true,
}

// HTML encoding map for XSS prevention
var htmlEncoding = map[rune]string{
	'&':  "&amp;",
	'<':  "&lt;",
	'>':  "&gt;",
	'"':  "&quot;",
	'\'': "&#x27;",
}

// Sanitizer handles input sanitization.
type Sanitizer struct {
	xss          bool
	sql          bool
	nosql        bool
	path         bool
	cmd          bool
	maxInputSize int
}

// NewSanitizer creates a new Sanitizer with the given configuration.
func NewSanitizer(config Config) *Sanitizer {
	maxSize := config.MaxInputSize
	if maxSize <= 0 {
		maxSize = DefaultMaxInputSize
	}
	return &Sanitizer{
		xss:          config.SanitizeXSS,
		sql:          config.SanitizeSQL,
		nosql:        config.SanitizeNoSQL,
		path:         config.SanitizePath,
		cmd:          config.SanitizeCmd,
		maxInputSize: maxSize,
	}
}

// NewSanitizerWithOptions creates a sanitizer with explicit options.
func NewSanitizerWithOptions(xss, sql, nosql, path, cmd bool) *Sanitizer {
	return &Sanitizer{
		xss:          xss,
		sql:          sql,
		nosql:        nosql,
		path:         path,
		cmd:          cmd,
		maxInputSize: DefaultMaxInputSize,
	}
}

// SanitizeString sanitizes a string value, removing potentially dangerous content.
func (s *Sanitizer) SanitizeString(value string) string {
	if value == "" {
		return value
	}

	// Input size limit to prevent DoS
	if len(value) > s.maxInputSize {
		value = value[:s.maxInputSize]
	}

	result := value

	// XSS prevention - remove patterns FIRST (while detectable), then encode
	if s.xss {
		for _, pattern := range xssPatterns {
			result = pattern.ReplaceAllString(result, "")
		}

		var sb strings.Builder
		sb.Grow(len(result) * 2)
		for _, r := range result {
			if enc, ok := htmlEncoding[r]; ok {
				sb.WriteString(enc)
			} else {
				sb.WriteRune(r)
			}
		}
		result = sb.String()
	}

	// SQL injection prevention
	if s.sql {
		for _, pattern := range sqlPatterns {
			result = pattern.ReplaceAllString(result, "[BLOCKED]")
		}
	}

	// Path traversal prevention
	if s.path {
		for _, pattern := range pathPatterns {
			result = pattern.ReplaceAllString(result, "")
		}
	}

	// Command injection prevention
	if s.cmd {
		for _, pattern := range cmdPatterns {
			result = pattern.ReplaceAllString(result, "[BLOCKED]")
		}
	}

	return result
}

// SanitizeMap sanitizes a map recursively.
func (s *Sanitizer) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	return s.sanitizeMapDepth(data, 0)
}

func (s *Sanitizer) sanitizeMapDepth(data map[string]interface{}, depth int) map[string]interface{} {
	if depth > MaxRecursionDepth || data == nil {
		return data
	}

	result := make(map[string]interface{}, len(data))

	for key, value := range data {
		// Prototype pollution prevention - always block dangerous keys (case-insensitive)
		if protoPollutionKeys[strings.ToLower(key)] {
			continue
		}

		// NoSQL injection - skip dangerous keys like $gt, $where, etc. (case-insensitive)
		if s.nosql && nosqlDangerousKeys[strings.ToLower(key)] {
			continue
		}

		// Sanitize key
		sanitizedKey := s.SanitizeString(key)

		// Sanitize value based on type
		switch v := value.(type) {
		case string:
			result[sanitizedKey] = s.SanitizeString(v)
		case map[string]interface{}:
			result[sanitizedKey] = s.sanitizeMapDepth(v, depth+1)
		case []interface{}:
			result[sanitizedKey] = s.sanitizeSlice(v, depth+1)
		default:
			result[sanitizedKey] = value
		}
	}

	return result
}

func (s *Sanitizer) sanitizeSlice(data []interface{}, depth int) []interface{} {
	if depth > MaxRecursionDepth || data == nil {
		return data
	}

	result := make([]interface{}, len(data))

	for i, item := range data {
		switch v := item.(type) {
		case string:
			result[i] = s.SanitizeString(v)
		case map[string]interface{}:
			result[i] = s.sanitizeMapDepth(v, depth+1)
		case []interface{}:
			result[i] = s.sanitizeSlice(v, depth+1)
		default:
			result[i] = item
		}
	}

	return result
}
