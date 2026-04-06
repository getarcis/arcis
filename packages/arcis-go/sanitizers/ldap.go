package sanitizers

import (
	"fmt"
	"regexp"
	"strings"
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
	// First escape filter chars, then DN-specific chars
	result := strings.NewReplacer().Replace(input)
	result = ldapDnChars.ReplaceAllStringFunc(input, escapeLdapChar)
	return result
}

// DetectLdapInjection checks if a string contains LDAP injection patterns.
// Does not sanitize — use SanitizeLdapFilter() or SanitizeLdapDn() for that.
//
//	DetectLdapInjection("*)(uid=*))(|(uid=*")  // true
//	DetectLdapInjection("john")                 // false
func DetectLdapInjection(input string) bool {
	return ldapDetectPattern.MatchString(input) || ldapInjectionPattern.MatchString(input)
}
