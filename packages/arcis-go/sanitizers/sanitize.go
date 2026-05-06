package sanitizers

import (
	"regexp"
	"strings"

	"github.com/GagancM/arcis/core"
	"golang.org/x/text/unicode/norm"
)

// Pre-compiled XSS patterns for performance (ReDoS-safe)
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
	regexp.MustCompile(`(?i)<iframe`),
	regexp.MustCompile(`(?i)<style[\s>]`),
	regexp.MustCompile(`(?i)<object`),
	regexp.MustCompile(`(?i)<embed`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=])data:`),
	regexp.MustCompile(`(?i)%3Cscript`),
	regexp.MustCompile(`(?i)<svg[^>]*onload`),
	// HTML injection vectors — form/meta/base/link can be used for phishing,
	// CSP bypass, base-href hijack, and stylesheet injection
	regexp.MustCompile(`(?i)<form[\s>]`),
	regexp.MustCompile(`(?i)<meta[\s>]`),
	regexp.MustCompile(`(?i)<base[\s>]`),
	regexp.MustCompile(`(?i)<link[\s>]`),
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
	regexp.MustCompile(`(?i)\bpg_sleep\s*\(`),
	regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\b`),
}

// Pre-compiled path traversal patterns
var pathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\.\/`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`(?i)%2e%2e`),
	regexp.MustCompile(`(?i)%252e`),
	regexp.MustCompile(`(?i)%00`), // null byte injection — truncates file paths (file.txt%00.jpg)
	regexp.MustCompile(`\x00`),    // literal null byte
}

// Pre-compiled command injection patterns
var cmdPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|` + "`" + `]`),
	regexp.MustCompile(`\$\(`),
	regexp.MustCompile(`(?i)%0[0-9a-fA-F]`),
	regexp.MustCompile(`(>>|<<|[<>]\s+[/\w])`),
}

// Pre-compiled SSTI (Server-Side Template Injection) detection patterns.
// Matches Node.js/Python SSTI implementation for cross-SDK parity.
var sstiDetectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{.*?\}\}`),                                                        // Jinja2 / Twig / Nunjucks
	regexp.MustCompile(`\$\{.*?\}`),                                                          // Freemarker / Spring EL
	regexp.MustCompile(`<%[\s\S]*?%>`),                                                       // ERB / EJS
	regexp.MustCompile(`#\{.*?\}`),                                                           // Pug / Jade
	regexp.MustCompile(`(?i)__(?:class|mro|subclasses|globals|builtins|import)__`),           // Python dunder
	regexp.MustCompile(`(?i)\{\{\s*config[.\[]`),                                             // Jinja2 config leak
	regexp.MustCompile(`(?i)\{\{\s*(?:self|request|lipsum|cycler|joiner|namespace|range)\b`), // Jinja2 objects
}

// SSTI removal patterns — narrowed to avoid false positives on legitimate ${name}.
// Only strip ${...} and #{...} when operators are present inside the expression.
var sstiRemovePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{.*?\}\}`),                 // Jinja2 / Twig
	regexp.MustCompile(`\$\{[^}]*__\w+__[^}]*\}`),     // Freemarker with Python dunders
	regexp.MustCompile(`\$\{[^}]*[?!()*+\-/][^}]*\}`), // Freemarker with operators
	regexp.MustCompile(`<%[\s\S]*?%>`),                // ERB / EJS
	regexp.MustCompile(`#\{[^}]*__\w+__[^}]*\}`),      // Pug with Python dunders
	regexp.MustCompile(`#\{[^}]*[?!()*+\-/][^}]*\}`),  // Pug with operators
	regexp.MustCompile(`(?i)__(?:class|mro|subclasses|globals|builtins|import)__`),
}

// Pre-compiled XXE (XML External Entity) detection patterns.
var xxeDetectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<!DOCTYPE\b`),
	regexp.MustCompile(`(?i)<!ENTITY\b`),
	regexp.MustCompile(`(?i)\bSYSTEM\s+["']`),
	regexp.MustCompile(`(?i)\bPUBLIC\s+["']`),
	regexp.MustCompile(`%\s*\w+\s*;`), // Parameter entity
	regexp.MustCompile(`(?i)<!\[CDATA\[`),
}

// XXE removal patterns
var xxeRemovePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<!DOCTYPE\s[^[>]*(?:\[[^\]]*\]\s*)?>|<!DOCTYPE\s[^>]*>`),
	regexp.MustCompile(`(?i)<!ENTITY[^>]*>`),
	regexp.MustCompile(`(?i)<!\[CDATA\[[\s\S]*?\]\]>`),
}

// NoSQL dangerous keys that could be used for injection.
// Synced with packages/core/patterns.json dangerous_keys (35 operators).
var nosqlDangerousKeys = map[string]bool{
	// Comparison
	"$gt": true, "$gte": true, "$lt": true, "$lte": true,
	"$ne": true, "$eq": true, "$in": true, "$nin": true,
	// Logical
	"$and": true, "$or": true, "$not": true, "$nor": true,
	// Element
	"$exists": true, "$type": true,
	// Evaluation — high risk (JS execution, regex, schema)
	"$regex": true, "$where": true, "$expr": true, "$mod": true,
	"$text": true, "$jsonSchema": true,
	// JavaScript execution operators — critical
	"$function": true, "$accumulator": true,
	// Array
	"$elemMatch": true, "$all": true, "$size": true,
	// Aggregation pipeline operators
	"$lookup": true, "$match": true, "$project": true, "$group": true,
	"$sort": true, "$limit": true, "$skip": true, "$unwind": true,
	"$addFields": true, "$replaceRoot": true,
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
	ssti         bool
	xxe          bool
	maxInputSize int
}

// NewSanitizer creates a new Sanitizer with the given configuration.
func NewSanitizer(config core.Config) *Sanitizer {
	maxSize := config.MaxInputSize
	if maxSize <= 0 {
		maxSize = core.DefaultMaxInputSize
	}
	return &Sanitizer{
		xss:          config.SanitizeXSS,
		sql:          config.SanitizeSQL,
		nosql:        config.SanitizeNoSQL,
		path:         config.SanitizePath,
		cmd:          config.SanitizeCmd,
		ssti:         config.SanitizeSSTI,
		xxe:          config.SanitizeXXE,
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
		maxInputSize: core.DefaultMaxInputSize,
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

	// Path traversal prevention — loop until stable to prevent bypass via
	// nested sequences: "....//".replace("../","") → "../"
	if s.path {
		// SECURITY: Normalize Unicode to NFKC before path pattern matching.
		// Fullwidth dot U+FF0E normalizes to '.', preventing bypass of ../ detection.
		result = norm.NFKC.String(result)
		for {
			prev := result
			for _, pattern := range pathPatterns {
				result = pattern.ReplaceAllString(result, "")
			}
			if result == prev {
				break
			}
		}
	}

	// Command injection prevention
	if s.cmd {
		for _, pattern := range cmdPatterns {
			result = pattern.ReplaceAllString(result, "[BLOCKED]")
		}
	}

	// SSTI prevention
	if s.ssti {
		for _, pattern := range sstiRemovePatterns {
			result = pattern.ReplaceAllString(result, "")
		}
	}

	// XXE prevention
	if s.xxe {
		for _, pattern := range xxeRemovePatterns {
			result = pattern.ReplaceAllString(result, "")
		}
	}

	return result
}

// SanitizeMap sanitizes a map recursively.
func (s *Sanitizer) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	return s.sanitizeMapDepth(data, 0)
}

func (s *Sanitizer) sanitizeMapDepth(data map[string]interface{}, depth int) map[string]interface{} {
	if depth > core.MaxRecursionDepth || data == nil {
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
	if depth > core.MaxRecursionDepth || data == nil {
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
