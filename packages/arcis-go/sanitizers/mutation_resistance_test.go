package sanitizers

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// Mutation resistance tests for SanitizeString (improvements.md §1.1.d).
//
// Generates encoding/case/unicode variants of every base attack payload
// and asserts that SanitizeString still strips the threat from each
// variant. Structural safeguard preventing future regex or normalization
// changes from silently re-opening a bypass class.
//
// Mirrors the Python and Node mutation testers (test_mutation_resistance.py
// and mutation-resistance.test.ts).

// ─── Mutators ─────────────────────────────────────────────────────────────

func mutAlternatingCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		if i%2 == 0 {
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

func mutUppercase(s string) string {
	return strings.ToUpper(s)
}

func mutURLEncodeOnce(s string) string {
	// Encode every non-alphanumeric char.
	var b strings.Builder
	b.Grow(len(s) * 3)
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteString(url.QueryEscape(string(r)))
		}
	}
	return b.String()
}

func mutURLEncodeTwice(s string) string {
	return mutURLEncodeOnce(mutURLEncodeOnce(s))
}

func mutHTMLEntityHex(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "&#x%x;", r)
		}
	}
	return b.String()
}

func mutHTMLEntityDecimal(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "&#%d;", r)
		}
	}
	return b.String()
}

func mutHTMLEntityNamed(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// mutFullwidthASCII replaces ASCII printable chars with their fullwidth
// equivalents. NFKC normalization inside SanitizeString folds them back
// to ASCII; if normalization regresses, this mutation surfaces the bug.
func mutFullwidthASCII(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x21 && r <= 0x7E {
			b.WriteRune(r + 0xFEE0)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type mutator struct {
	name string
	fn   func(string) string
}

// Mutators excluded for SQL: html_entity_named is excluded because SQL
// payloads don't pass through HTML rendering paths in the wild.
var allMutators = []mutator{
	{"alternating_case", mutAlternatingCase},
	{"uppercase", mutUppercase},
	{"url_encode_once", mutURLEncodeOnce},
	{"url_encode_twice", mutURLEncodeTwice},
	{"html_entity_hex", mutHTMLEntityHex},
	{"html_entity_decimal", mutHTMLEntityDecimal},
	{"html_entity_named", mutHTMLEntityNamed},
	{"fullwidth_ascii", mutFullwidthASCII},
}

var sqlMutators = []mutator{
	{"alternating_case", mutAlternatingCase},
	{"uppercase", mutUppercase},
	{"url_encode_once", mutURLEncodeOnce},
	{"url_encode_twice", mutURLEncodeTwice},
	{"html_entity_hex", mutHTMLEntityHex},
	{"html_entity_decimal", mutHTMLEntityDecimal},
	{"fullwidth_ascii", mutFullwidthASCII},
}

// ─── Cases ────────────────────────────────────────────────────────────────

type mutCase struct {
	base   string
	tokens []string // post-sanitize, lowercased output must NOT contain any of these
}

var xssCases = []mutCase{
	{"<script>alert(1)</script>", []string{"<script", "</script"}},
	{"<img onerror=alert(1) src=x>", []string{"onerror="}},
	{"javascript:alert(1)", []string{"javascript:"}},
	{"<iframe src=evil.com>", []string{"<iframe"}},
	{"<svg onload=alert(1)>", []string{"onload="}},
	{"<object data=evil>", []string{"<object"}},
	{"<embed src=evil>", []string{"<embed"}},
	{"<style>body{x:expression(alert(1))}</style>", []string{"<style"}},
}

var sqlCases = []mutCase{
	{"' OR 1=1--", []string{"or 1=1"}},
	{"'; DROP TABLE users--", []string{"drop"}},
	{"UNION SELECT * FROM users", []string{"union", "select"}},
	{"admin'--", []string{"--"}},
	{"1; DELETE FROM users", []string{"delete"}},
	{"SLEEP(5)", []string{"sleep("}},
	// Oracle DBMS_* packages (improvements.md §1.1.e Q3).
	{"foo; DBMS_LOCK.SLEEP(5)", []string{"dbms_"}},
	{"foo; DBMS_PIPE.RECEIVE_MESSAGE(x,5)", []string{"dbms_"}},
	{"foo; DBMS_JAVA.RUNJAVA('...')", []string{"dbms_"}},
}

var pathCases = []mutCase{
	{"../../etc/passwd", []string{"../"}},
	{"..\\..\\windows\\system32", []string{"..\\"}},
	{"/var/www/../../etc/shadow", []string{"../"}},
	{strings.Repeat("../", 5) + "etc/passwd", []string{"../"}},
}

// ─── Test runners ─────────────────────────────────────────────────────────

func runMutationCases(t *testing.T, category string, cases []mutCase, mutators []mutator) {
	t.Helper()
	for _, c := range cases {
		for _, m := range mutators {
			c, m := c, m
			t.Run(fmt.Sprintf("%s/%s/%s", category, m.name, c.base), func(t *testing.T) {
				mutated := m.fn(c.base)
				output := strings.ToLower(SanitizeString(mutated))
				for _, tok := range c.tokens {
					if strings.Contains(output, strings.ToLower(tok)) {
						t.Errorf(
							"BYPASS: %s payload %q survived mutation %q as %q -> output %q still contains %q",
							category, c.base, m.name, mutated, output, tok,
						)
					}
				}
			})
		}
	}
}

func TestMutationResistance_XSS(t *testing.T) {
	runMutationCases(t, "xss", xssCases, allMutators)
}

func TestMutationResistance_SQL(t *testing.T) {
	runMutationCases(t, "sql", sqlCases, sqlMutators)
}

func TestMutationResistance_PathTraversal(t *testing.T) {
	runMutationCases(t, "path_traversal", pathCases, allMutators)
}

// ─── Mutator sanity tests ─────────────────────────────────────────────────

func TestMutator_AlternatingCaseChangesInput(t *testing.T) {
	if mutAlternatingCase("abcdef") == "abcdef" {
		t.Error("expected case to change")
	}
}

func TestMutator_URLEncodeTwiceDoubles(t *testing.T) {
	once := mutURLEncodeOnce("<x>")
	twice := mutURLEncodeTwice("<x>")
	if strings.Count(twice, "%25") < 2 {
		t.Errorf("expected double-encoded %% but got %q (once=%q)", twice, once)
	}
}

func TestMutator_FullwidthASCIIUsesFullwidth(t *testing.T) {
	out := mutFullwidthASCII("abc")
	for _, r := range out {
		if !(r >= 0xFF21 && r <= 0xFF7A) {
			t.Errorf("expected fullwidth char, got %q (0x%x)", r, r)
		}
	}
}

func TestMutator_HTMLEntityHexEncodesBrackets(t *testing.T) {
	if !strings.Contains(mutHTMLEntityHex("<"), "&#x3c;") {
		t.Errorf("expected &#x3c; in output for `<`, got %q", mutHTMLEntityHex("<"))
	}
}
