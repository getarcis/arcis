package sanitizers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cross-SDK conformance: load spec/TEST_VECTORS.json and verify the Go
// implementation produces output matching the spec's expected_behavior.
//
// Only a handful of unambiguously-describable behaviors are checked here.
// Many vectors describe "must not contain X" constraints that translate
// directly to Go assertions; ambiguous or SDK-specific ones are skipped.

type vector struct {
	Input            string `json:"input"`
	ExpectedBehavior string `json:"expected_behavior"`
	ExpectedContains string `json:"expected_contains,omitempty"`
}

type sanitizeStringVectors struct {
	XSS []vector `json:"xss"`
	SQL []vector `json:"sql"`
}

type testVectorsDoc struct {
	SanitizeString sanitizeStringVectors `json:"sanitize_string"`
}

func loadVectors(t *testing.T) testVectorsDoc {
	t.Helper()
	// Walk up from CWD to find spec/TEST_VECTORS.json.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "spec", "TEST_VECTORS.json")
		if _, err := os.Stat(candidate); err == nil {
			data, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatalf("read vectors: %v", err)
			}
			var doc testVectorsDoc
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse vectors: %v", err)
			}
			return doc
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("spec/TEST_VECTORS.json not found (run from repo checkout)")
	return testVectorsDoc{}
}

// forbiddenSubstring derives a "must not contain X" token from expected_behavior.
// Returns ("", false) when the vector is not of that form.
func forbiddenSubstring(behavior string) (string, bool) {
	b := strings.ToLower(behavior)
	marker := "must not contain '"
	idx := strings.Index(b, marker)
	if idx < 0 {
		return "", false
	}
	rest := behavior[idx+len(marker):]
	end := strings.Index(rest, "'")
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

func TestConformance_SanitizeString_XSS(t *testing.T) {
	doc := loadVectors(t)
	for i, v := range doc.SanitizeString.XSS {
		forbidden, ok := forbiddenSubstring(v.ExpectedBehavior)
		if !ok {
			continue
		}
		got := SanitizeXSS(v.Input)
		if strings.Contains(strings.ToLower(got), strings.ToLower(forbidden)) {
			t.Errorf("xss vector %d (input=%q): output %q still contains forbidden %q",
				i, v.Input, got, forbidden)
		}
	}
}

func TestConformance_SanitizeString_SQL(t *testing.T) {
	doc := loadVectors(t)
	for i, v := range doc.SanitizeString.SQL {
		forbidden, ok := forbiddenSubstring(v.ExpectedBehavior)
		if !ok {
			continue
		}
		got := SanitizeSQL(v.Input)
		if strings.Contains(strings.ToLower(got), strings.ToLower(forbidden)) {
			t.Errorf("sql vector %d (input=%q): output %q still contains forbidden %q",
				i, v.Input, got, forbidden)
		}
	}
}
