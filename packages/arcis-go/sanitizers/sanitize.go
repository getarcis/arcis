package sanitizers

import (
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/getarcis/arcis/v2/core"
	"golang.org/x/text/unicode/norm"
)

// multiDecode peels off URL + HTML entity layers until the string is
// stable or maxPasses is hit (improvements.md §1.1.b). Closes the
// encoding-stack bypass class: `%2526%2523x3c%253bscript%2526%2523x3e%253b`
// is a triple-encoded `<script>` that needs three decode rounds before
// the literal ASCII shape appears for the XSS regex to match. Bounded
// at 4 passes to keep pathological inputs from looping forever. Base64
// is intentionally not in the chain (false-positive rate on arbitrary
// text would be too high).
func multiDecode(value string, maxPasses int) string {
	for i := 0; i < maxPasses; i++ {
		prev := value
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		value = html.UnescapeString(value)
		if value == prev {
			break
		}
	}
	return value
}

// XSS / SQL / path / command patterns moved to `loader.go` —
// loaded from the embedded `data/patterns.json` (a sync'd copy of
// `packages/core/patterns.json`) at startup. The package-scope
// slices `xssPatterns`, `sqlPatterns`, `pathPatterns`,
// `commandPatterns` are declared and populated there.
// improvements.md §1.1.c.

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

	// SECURITY: Normalize Unicode to NFKC BEFORE every detector runs.
	// Fullwidth glyphs (`＜script＞`, `１+１＝２`) collapse to their ASCII
	// equivalents, closing the entire fullwidth-bypass class for XSS,
	// SQL, command-injection, and path-traversal in a single pass.
	// improvements.md §1.1.a. Bypass example closed:
	//   `＜script＞alert(1)＜/script＞`  →  `<script>alert(1)</script>`
	result := norm.NFKC.String(value)

	// SECURITY: Multi-pass URL + HTML decode (improvements.md §1.1.b).
	// Closes the encoding-stack bypass class. After NFKC,
	// `%2526%2523x3c%253bscript%2526%2523x3e%253b` (triple-encoded
	// `<script>`) decodes all the way to `<script>` and hits the
	// normal XSS strip below. Bounded at 4 passes.
	result = multiDecode(result, 4)

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
	// NFKC normalization happens at the top of SanitizeString (above);
	// don't double-normalize here — input is already in NFKC form.
	if s.path {
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
		for _, pattern := range commandPatterns {
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
