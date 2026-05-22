package sanitizers

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmbeddedPatternsLoad confirms the package init() successfully
// parsed `data/patterns.json` and populated each of the four primary
// pattern slices. improvements.md §1.1.c.
func TestEmbeddedPatternsLoad(t *testing.T) {
	if LoadedSpecVersion() == "" {
		t.Fatal("embedded patterns.json did not load (LoadedSpecVersion is empty)")
	}
	if len(xssPatterns) == 0 {
		t.Error("xssPatterns slice is empty — loader.compileCategory('xss') returned nothing")
	}
	if len(sqlPatterns) == 0 {
		t.Error("sqlPatterns slice is empty")
	}
	if len(pathPatterns) == 0 {
		t.Error("pathPatterns slice is empty")
	}
	if len(commandPatterns) == 0 {
		t.Error("commandPatterns slice is empty")
	}
}

// TestEmbeddedPatternsAllCompile ensures every rule in patterns.json
// produced a usable compiled regex. compileCategory silently skips
// patterns that fail to compile (so a single bad rule doesn't crash
// the package init), but it leaves us blind to drift. This test
// catches that by counting rules-in vs compiled-out per category.
func TestEmbeddedPatternsAllCompile(t *testing.T) {
	cats := map[string]int{
		"xss":               len(xssPatterns),
		"sql_injection":     len(sqlPatterns),
		"path_traversal":    len(pathPatterns),
		"command_injection": len(commandPatterns),
	}
	for category, compiledCount := range cats {
		cat, ok := loadedPatterns.Patterns[category]
		if !ok {
			t.Errorf("category %q missing from loadedPatterns", category)
			continue
		}
		ruleCount := 0
		for _, r := range cat.Rules {
			if r.Pattern != "" || r.PatternSafe != "" {
				ruleCount++
			}
		}
		if compiledCount != ruleCount {
			t.Errorf(
				"category %q: %d rules in spec, %d compiled — %d patterns failed to compile silently",
				category, ruleCount, compiledCount, ruleCount-compiledCount,
			)
		}
	}
}

// TestDangerousKeysForLoadsNoSQL exercises the helper that future
// SanitizeMap-style code will use to walk the dangerous-keys list.
func TestDangerousKeysForLoadsNoSQL(t *testing.T) {
	keys := DangerousKeysFor("nosql_injection")
	if len(keys) == 0 {
		t.Fatal("nosql_injection dangerous_keys is empty")
	}
	found := make(map[string]bool, len(keys))
	for _, k := range keys {
		found[k] = true
	}
	for _, expected := range []string{"$gt", "$where", "$jsonSchema", "$elemMatch"} {
		if !found[expected] {
			t.Errorf("nosql_injection dangerous_keys missing %q", expected)
		}
	}
}

// TestBundledPatternsMatchCanonical guards the bundled copy at
// `sanitizers/data/patterns.json` against drift from the canonical
// spec at `packages/core/patterns.json`. The Go SDK embeds the
// bundled copy via //go:embed (which can't reach outside the
// module), but the canonical spec is the single source of truth for
// Python + Node. If they drift, every cross-SDK contract breaks.
//
// This test runs only when the canonical file is reachable from the
// test environment — i.e. inside the dev tree. CI executes it.
// `go test` against an installed `go get`-fetched copy of the
// module skips it.
func TestBundledPatternsMatchCanonical(t *testing.T) {
	// Walk up from the test file's directory until we find the
	// canonical patterns.json. Bounded at 6 levels so we don't
	// wander off into the filesystem on unexpected layouts.
	canonical := findCanonicalPatterns()
	if canonical == "" {
		t.Skip("canonical packages/core/patterns.json not reachable; bundled-vs-canonical sync check skipped")
	}

	canonicalBytes, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("failed to read canonical spec at %s: %v", canonical, err)
	}
	canonicalHash := sha256.Sum256(canonicalBytes)
	embeddedHash := sha256.Sum256(embeddedPatternsJSON)
	if canonicalHash != embeddedHash {
		t.Errorf(
			"BUNDLED patterns.json at sanitizers/data/ is OUT OF SYNC with canonical packages/core/patterns.json.\n"+
				"  canonical sha256: %x\n"+
				"  bundled   sha256: %x\n"+
				"Resync by running:\n"+
				"  cp packages/core/patterns.json packages/arcis-go/sanitizers/data/patterns.json",
			canonicalHash, embeddedHash,
		)
	}
}

// findCanonicalPatterns walks up looking for the canonical spec file.
// Returns empty string when the file isn't in the expected dev tree
// location (e.g. when running against a `go get`-fetched copy).
func findCanonicalPatterns() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := cwd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "packages", "core", "patterns.json")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: walk relatively up from packages/arcis-go/sanitizers
	// (this file's package) to packages/core/.
	parts := strings.Split(filepath.ToSlash(cwd), "/")
	for i := len(parts); i > 0; i-- {
		candidate := filepath.Join(filepath.Join(parts[:i]...), "core", "patterns.json")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}
