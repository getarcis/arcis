package sanitizers

import "regexp"

// XPath injection prevention (sdk-vectors.md tier 1 #23).
//
// XPath 1.0 has no escape syntax for string literals. The only way to
// embed user input safely is parameterised queries via variable
// bindings (/foo[@name = $username]). Neither libxml2 nor most Go XPath
// libraries expose a canonical escape function for XPath. The pragmatic
// answer everyone ships:
//
//   - Detect: scan for unescaped quotes or expression-control
//     characters that suggest the user is trying to break out of a
//     string literal.
//   - Sanitize: strip the offending control characters. Lossy by
//     design; callers that need lossless input should bind variables.
//
// Detection is the load-bearing surface for this vector. Sanitization
// is a fallback for code that concatenates user input into XPath.
//
// Mirrors arcis-python/arcis/sanitizers/xpath.py byte-for-byte on the
// detection contract — same regex pair, same fast-path skip on the
// control-char pre-check.

var (
	// XPath expression-control characters that an attacker uses to
	// escape a string literal: single quote, double quote, comma
	// (changes function arity), the union operator |, and parens
	// (used in `) or (` toggles against XPath function calls).
	xpathInjectionChars = regexp.MustCompile(`['"|,()]`)

	// Common operator-injection patterns: unescaped boolean injection
	// (`' or '1'='1`), function tampering (`,`), and union (`|`).
	xpathInjectionPattern = regexp.MustCompile(
		`(?i)('\s*(or|and)\s*'|"\s*(or|and)\s*"|\)\s*(or|and)\s*\(|\|\s*/)`,
	)

	// Sanitization strips the dangerous control characters. Lossy.
	xpathStrip = regexp.MustCompile(`['"|,]`)
)

// DetectXPathInjection returns true when the input looks like XPath
// injection.
//
// Conservative on purpose: triggers only when a control character is
// present AND combined with a boolean / function-arity / union pattern.
// Plain user names and emails (no quotes, no pipes) pass clean.
//
//	DetectXPathInjection("' or '1'='1")          // true
//	DetectXPathInjection("john")                  // false
//	DetectXPathInjection("john@example.com")      // false
func DetectXPathInjection(input string) bool {
	if input == "" {
		return false
	}
	// Fast path: skip the regex test entirely when no control chars exist.
	if !xpathInjectionChars.MatchString(input) {
		return false
	}
	return xpathInjectionPattern.MatchString(input)
}

// SanitizeXPath strips XPath expression-control characters.
//
// Lossy. `O'Brien` becomes `OBrien`. Use only when migrating legacy
// code that concatenates user input into XPath; new code should bind
// variables via the underlying XPath library instead.
//
//	SanitizeXPath("' or '1'='1")  // " or 1=1"
//	SanitizeXPath("O'Brien")       // "OBrien"
func SanitizeXPath(input string) string {
	return xpathStrip.ReplaceAllString(input, "")
}
