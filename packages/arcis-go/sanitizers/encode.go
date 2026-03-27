package sanitizers

import (
	"fmt"
	"net/url"
	"strings"
)

// Context-aware output encoding for XSS prevention.
//
// Wrong-context encoding is the #1 cause of XSS bypasses in "protected" apps.
// A single Sanitize() is not enough when output goes to JS, CSS, or attribute contexts.

// isAlphanumeric checks if a byte is ASCII alphanumeric.
func isAlphanumeric(ch byte) bool {
	return (ch >= '0' && ch <= '9') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= 'a' && ch <= 'z')
}

// isRuneAlphanumeric checks if a rune is ASCII alphanumeric.
func isRuneAlphanumeric(r rune) bool {
	return (r >= '0' && r <= '9') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z')
}

// EncodeForHTML encodes for HTML body context. Entity-encodes & < > " '
//
// Use when outputting to HTML element content:
//
//	"<p>" + EncodeForHTML(userInput) + "</p>"
func EncodeForHTML(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#x27;")
		default:
			b.WriteByte(value[i])
		}
	}
	return b.String()
}

// EncodeForAttribute encodes for HTML attribute context.
// All non-alphanumeric characters are encoded as &#xHH; hex entities.
//
// Use when outputting to HTML attributes:
//
//	`<div title="` + EncodeForAttribute(userInput) + `">`
func EncodeForAttribute(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value) * 2)
	for _, r := range value {
		if isRuneAlphanumeric(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "&#x%X;", r)
		}
	}
	return b.String()
}

// EncodeForJS encodes for JavaScript string context.
// Non-alphanumeric characters are escaped as \xHH (ASCII) or \uHHHH (Unicode).
//
// Use when embedding in JS string literals:
//
//	"var x = '" + EncodeForJS(userInput) + "';"
func EncodeForJS(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value) * 2)
	for _, r := range value {
		if isRuneAlphanumeric(r) {
			b.WriteRune(r)
		} else if r < 0x100 {
			fmt.Fprintf(&b, "\\x%02X", r)
		} else {
			fmt.Fprintf(&b, "\\u%04X", r)
		}
	}
	return b.String()
}

// EncodeForURL encodes for URL parameter context.
// Percent-encodes all non-unreserved characters.
//
// Use when building query strings:
//
//	"?q=" + EncodeForURL(userInput)
func EncodeForURL(value string) string {
	if value == "" {
		return ""
	}
	return url.QueryEscape(value)
}

// EncodeForCSS encodes for CSS value context.
// Non-alphanumeric characters are hex-escaped as \HH (trailing space per CSS spec).
//
// Use when embedding in CSS values:
//
//	"content: '" + EncodeForCSS(userInput) + "';"
func EncodeForCSS(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value) * 2)
	for _, r := range value {
		if isRuneAlphanumeric(r) {
			b.WriteRune(r)
		} else {
			// CSS hex escape: backslash + hex code + trailing space
			fmt.Fprintf(&b, "\\%X ", r)
		}
	}
	return b.String()
}
