package arcis

import "regexp"

// headerInjectionPattern matches CRLF sequences, bare CR/LF, and null bytes
// that enable HTTP header injection / response splitting attacks.
var headerInjectionPattern = regexp.MustCompile(`\r\n|\r|\n|\x00`)

// SanitizeHeaderValue strips CRLF sequences, bare CR/LF, and null bytes
// from a header value to prevent HTTP header injection.
func SanitizeHeaderValue(value string) string {
	return headerInjectionPattern.ReplaceAllString(value, "")
}

// SanitizeHeaders sanitizes a map of HTTP header key-value pairs.
// Strips CRLF/null bytes from both keys and values.
func SanitizeHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return map[string]string{}
	}

	result := make(map[string]string, len(headers))
	for key, value := range headers {
		sanitizedKey := SanitizeHeaderValue(key)
		sanitizedValue := SanitizeHeaderValue(value)
		result[sanitizedKey] = sanitizedValue
	}
	return result
}

// DetectHeaderInjection checks if a string contains HTTP header injection
// patterns (CRLF, bare CR/LF, null bytes). Does not sanitize.
func DetectHeaderInjection(value string) bool {
	return headerInjectionPattern.MatchString(value)
}
