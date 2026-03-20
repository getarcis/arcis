package sanitizers

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PiiType represents a type of personally identifiable information.
type PiiType string

const (
	PiiEmail      PiiType = "email"
	PiiPhone      PiiType = "phone"
	PiiCreditCard PiiType = "credit_card"
	PiiSSN        PiiType = "ssn"
	PiiIPAddress  PiiType = "ip_address"
)

// PiiMatch represents a detected PII occurrence in text.
type PiiMatch struct {
	Type  PiiType `json:"type"`
	Value string  `json:"value"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Field string  `json:"field,omitempty"` // Set when scanning objects
}

// PiiScanOptions configures PII scanning.
type PiiScanOptions struct {
	Types []PiiType // Filter to specific PII types (nil = all)
}

// PiiRedactOptions configures PII redaction.
type PiiRedactOptions struct {
	Types       []PiiType // Filter to specific PII types (nil = all)
	Replacement string    // Custom replacement (default: "[REDACTED]")
	TypeLabels  bool      // Use type-specific labels like [EMAIL], [PHONE]
}

var (
	piiEmailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+`)
	piiPhoneRegex = regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	piiCCRegex    = regexp.MustCompile(`\b(?:\d[ \-]*?){13,19}\b`)
	piiSSNRegex   = regexp.MustCompile(`\b\d{3}[-\s]\d{2}[-\s]\d{4}\b`)
	piiIPv4Regex  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	piiIPv6Regex  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b`)
)

var typeLabels = map[PiiType]string{
	PiiEmail:      "[EMAIL]",
	PiiPhone:      "[PHONE]",
	PiiCreditCard: "[CREDIT_CARD]",
	PiiSSN:        "[SSN]",
	PiiIPAddress:  "[IP_ADDRESS]",
}

// ScanPii finds all PII occurrences in a string.
func ScanPii(text string, opts *PiiScanOptions) []PiiMatch {
	types := allPiiTypes()
	if opts != nil && len(opts.Types) > 0 {
		types = opts.Types
	}

	typeSet := make(map[PiiType]bool)
	for _, t := range types {
		typeSet[t] = true
	}

	var matches []PiiMatch

	if typeSet[PiiEmail] {
		for _, loc := range piiEmailRegex.FindAllStringIndex(text, -1) {
			matches = append(matches, PiiMatch{Type: PiiEmail, Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]})
		}
	}

	if typeSet[PiiPhone] {
		for _, loc := range piiPhoneRegex.FindAllStringIndex(text, -1) {
			matches = append(matches, PiiMatch{Type: PiiPhone, Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]})
		}
	}

	if typeSet[PiiCreditCard] {
		for _, loc := range piiCCRegex.FindAllStringIndex(text, -1) {
			val := text[loc[0]:loc[1]]
			if luhnCheck(val) {
				matches = append(matches, PiiMatch{Type: PiiCreditCard, Value: val, Start: loc[0], End: loc[1]})
			}
		}
	}

	if typeSet[PiiSSN] {
		for _, loc := range piiSSNRegex.FindAllStringIndex(text, -1) {
			val := text[loc[0]:loc[1]]
			if isValidSSN(val) {
				matches = append(matches, PiiMatch{Type: PiiSSN, Value: val, Start: loc[0], End: loc[1]})
			}
		}
	}

	if typeSet[PiiIPAddress] {
		for _, loc := range piiIPv4Regex.FindAllStringIndex(text, -1) {
			matches = append(matches, PiiMatch{Type: PiiIPAddress, Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]})
		}
		for _, loc := range piiIPv6Regex.FindAllStringIndex(text, -1) {
			matches = append(matches, PiiMatch{Type: PiiIPAddress, Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]})
		}
	}

	// Sort by start position
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Start < matches[j].Start
	})

	return matches
}

// DetectPii checks if a string contains any PII.
func DetectPii(text string, opts *PiiScanOptions) bool {
	return len(ScanPii(text, opts)) > 0
}

// RedactPii replaces all PII in a string with placeholders.
func RedactPii(text string, opts *PiiRedactOptions) string {
	var scanOpts *PiiScanOptions
	if opts != nil && len(opts.Types) > 0 {
		scanOpts = &PiiScanOptions{Types: opts.Types}
	}

	matches := ScanPii(text, scanOpts)
	if len(matches) == 0 {
		return text
	}

	// Replace from end to start to preserve positions
	result := text
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		replacement := "[REDACTED]"
		if opts != nil {
			if opts.Replacement != "" {
				replacement = opts.Replacement
			} else if opts.TypeLabels {
				if label, ok := typeLabels[m.Type]; ok {
					replacement = label
				}
			}
		}
		result = result[:m.Start] + replacement + result[m.End:]
	}

	return result
}

// ScanObjectPii recursively scans a map for PII in string values.
func ScanObjectPii(data map[string]interface{}, opts *PiiScanOptions) []PiiMatch {
	return scanObjectRecursive(data, "", opts)
}

// RedactObjectPii recursively redacts PII in a map, returning a new map.
func RedactObjectPii(data map[string]interface{}, opts *PiiRedactOptions) map[string]interface{} {
	return redactObjectRecursive(data, opts)
}

func scanObjectRecursive(data map[string]interface{}, prefix string, opts *PiiScanOptions) []PiiMatch {
	var matches []PiiMatch

	for key, val := range data {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			for _, m := range ScanPii(v, opts) {
				m.Field = path
				matches = append(matches, m)
			}
		case map[string]interface{}:
			matches = append(matches, scanObjectRecursive(v, path, opts)...)
		case []interface{}:
			for i, item := range v {
				itemPath := path + "[" + strconv.Itoa(i) + "]"
				switch iv := item.(type) {
				case string:
					for _, m := range ScanPii(iv, opts) {
						m.Field = itemPath
						matches = append(matches, m)
					}
				case map[string]interface{}:
					matches = append(matches, scanObjectRecursive(iv, itemPath, opts)...)
				}
			}
		}
	}

	return matches
}

func redactObjectRecursive(data map[string]interface{}, opts *PiiRedactOptions) map[string]interface{} {
	result := make(map[string]interface{})

	for key, val := range data {
		switch v := val.(type) {
		case string:
			result[key] = RedactPii(v, opts)
		case map[string]interface{}:
			result[key] = redactObjectRecursive(v, opts)
		case []interface{}:
			arr := make([]interface{}, len(v))
			for i, item := range v {
				switch iv := item.(type) {
				case string:
					arr[i] = RedactPii(iv, opts)
				case map[string]interface{}:
					arr[i] = redactObjectRecursive(iv, opts)
				default:
					arr[i] = item
				}
			}
			result[key] = arr
		default:
			result[key] = val
		}
	}

	return result
}

func luhnCheck(number string) bool {
	// Extract only digits
	var digits []int
	for _, c := range number {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}

	return sum%10 == 0
}

func isValidSSN(ssn string) bool {
	// Extract digits
	var digits []byte
	for _, c := range ssn {
		if c >= '0' && c <= '9' {
			digits = append(digits, byte(c))
		}
	}

	if len(digits) != 9 {
		return false
	}

	area := string(digits[:3])

	// Reject 000, 666, 900-999
	if area == "000" || area == "666" {
		return false
	}
	areaNum, _ := strconv.Atoi(area)
	if areaNum >= 900 {
		return false
	}

	return true
}

func allPiiTypes() []PiiType {
	return []PiiType{PiiEmail, PiiPhone, PiiCreditCard, PiiSSN, PiiIPAddress}
}

// stripDigits extracts only digit characters from a string.
func stripDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
