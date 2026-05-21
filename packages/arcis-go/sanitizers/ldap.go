package sanitizers

import (
	"fmt"
	"regexp"
)

// LDAP injection prevention.
//
// LDAP special characters in filter context: * ( ) \ NUL  (RFC 4515)
// LDAP special characters in DN context:     , + < > ; " = / \ NUL  (RFC 4514)
//
// Sanitization escapes rather than strips — preserves the original value
// while making it safe to embed in LDAP queries.

var (
	// Detection: unescaped LDAP filter special chars
	ldapDetectPattern = regexp.MustCompile(`[*()\\\x00]`)

	// Detection: OR/AND bypass and wildcard abuse
	ldapInjectionPattern = regexp.MustCompile(`\)\s*\(|\*\s*\)\s*\(`)

	// Filter chars per RFC 4515
	ldapFilterChars = regexp.MustCompile(`[*()\\\x00]`)

	// DN chars per RFC 4514 (superset of filter chars)
	ldapDnChars = regexp.MustCompile(`[,+<>;"=/\\\x00]`)
)

func escapeLdapChar(char string) string {
	return fmt.Sprintf("\\%02x", char[0])
}

// SanitizeLdapFilter sanitizes a string for safe use in LDAP filter expressions.
// Escapes * ( ) \ and NUL per RFC 4515.
//
//	SanitizeLdapFilter("user*(admin)")
//	// Returns: "user\2a\28admin\29"
func SanitizeLdapFilter(input string) string {
	result := ldapFilterChars.ReplaceAllStringFunc(input, escapeLdapChar)
	return result
}

// SanitizeLdapDn sanitizes a string for safe use in LDAP Distinguished Names.
// Escapes , + < > ; " = / \ and NUL per RFC 4514.
//
//	SanitizeLdapDn("cn=admin,dc=example")
//	// Returns: "cn\3dadmin\2cdc\3dexample"
func SanitizeLdapDn(input string) string {
	return ldapDnChars.ReplaceAllStringFunc(input, escapeLdapChar)
}

// DetectLdapInjection checks if a string contains LDAP injection patterns.
// Does not sanitize — use SanitizeLdapFilter() or SanitizeLdapDn() for that.
//
// Broad mode: matches any LDAP filter special character. Safe to call
// when you KNOW the value is heading into an LDAP filter context, but
// NOT safe at the request boundary where any parenthesised string would
// trip it. Use DetectLdapInjectionStrict() for scan-threats-style use.
//
//	DetectLdapInjection("*)(uid=*))(|(uid=*")  // true
//	DetectLdapInjection("john")                 // false
//	DetectLdapInjection("call me (when you can)")  // true (parens trip it)
func DetectLdapInjection(input string) bool {
	return ldapDetectPattern.MatchString(input) || ldapInjectionPattern.MatchString(input)
}

// DetectLdapInjectionStrict is the request-boundary-safe LDAP detector.
//
// Uses only the attack-specific filter-break shapes ')(' and '*)('. Doesn't
// false-positive on legitimate input containing parens. Wire this into
// ScanThreats / request-boundary scanners.
//
//	DetectLdapInjectionStrict("*)(uid=*))(|(uid=*")  // true
//	DetectLdapInjectionStrict("john")                 // false
//	DetectLdapInjectionStrict("call me (when you can)")  // false
//	DetectLdapInjectionStrict("Acme (USA) Inc")         // false
func DetectLdapInjectionStrict(input string) bool {
	return ldapInjectionPattern.MatchString(input)
}
