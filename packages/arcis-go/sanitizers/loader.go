package sanitizers

// loader.go — read security regex patterns from the shared
// `packages/core/patterns.json` spec at startup, instead of
// hardcoding them in `sanitize.go`. improvements.md §1.1.c.
//
// # Why this exists
//
// Pre-v1.6, Go SDK kept its own hardcoded `var xssPatterns = []`
// blocks. Whenever `packages/core/patterns.json` changed (e.g. the
// greedy XSS patterns landing in v1.6 §1.1.a, or the multi-decode
// chain's effect on regex semantics in §1.1.b), Python and Node
// picked up the new patterns automatically because they read from
// patterns.json at runtime. Go did not — until someone manually
// re-typed the changes into `sanitize.go`. That's a Pattern 2
// violation per `arcis/CLAUDE.md`:
//
//   > Pattern 2 — Shared Pattern Repository: All security regex
//   > patterns live in a single JSON file shared across all SDKs.
//   > No SDK should hardcode patterns that diverge from this
//   > repository.
//
// # How this works
//
// Go's `//go:embed` is build-time and only reads files inside the
// module root. `packages/core/patterns.json` is OUTSIDE the
// `arcis-go` module, so a bundled copy lives at
// `sanitizers/data/patterns.json`. That bundled copy MUST stay in
// sync with the canonical spec; see the CI sync check at
// `.github/workflows/ci.yml` (to be added) and the sync helper
// described in the package README.
//
// At init() time we parse the embedded JSON and compile each rule's
// regex into the global pattern slices (`xssPatterns`,
// `sqlPatterns`, etc.) that `sanitize.go` and `standalone.go`
// already consume. Existing call sites need no changes.

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

//go:embed data/patterns.json
var embeddedPatternsJSON []byte

// patternSpec mirrors the shape of `packages/core/patterns.json`.
// Only the fields the Go SDK actually uses are decoded; extra fields
// (severity, owasp, description, redos_safe, encoding) are dropped
// because Go doesn't surface them today. Node + Python do similar.
type patternSpec struct {
	Version  string                     `json:"version"`
	Patterns map[string]patternCategory `json:"patterns"`
}

type patternCategory struct {
	Rules         []patternRule `json:"rules"`
	DangerousKeys []string      `json:"dangerous_keys"`
}

type patternRule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	PatternSafe string `json:"pattern_safe"`
	Flags       string `json:"flags"`
}

// Package-scope state. `loadedPatterns` holds the parsed spec so
// future helpers (e.g. dangerous-key lookups for SanitizeMap) can
// reach into the same data without re-parsing. The four
// `*Patterns` slices are bare-declared here and populated by
// `init()`; consumers in `sanitize.go` and `standalone.go`
// reference them directly.
var (
	loadedPatterns  patternSpec
	xssPatterns     []*regexp.Regexp
	sqlPatterns     []*regexp.Regexp
	pathPatterns    []*regexp.Regexp
	commandPatterns []*regexp.Regexp
)

// init parses the embedded JSON and compiles each category. Panics
// on parse failure — patterns.json is shipped inside the binary, so
// a parse failure means the build is broken. Better to fail loud at
// startup than silently produce wrong findings later (mirrors the
// Rust CLI's `check_embedded_schemas` gate).
func init() {
	if err := json.Unmarshal(embeddedPatternsJSON, &loadedPatterns); err != nil {
		panic("arcis: failed to parse embedded patterns.json: " + err.Error())
	}
	xssPatterns = compileCategory("xss")
	sqlPatterns = compileCategory("sql_injection")
	pathPatterns = compileCategory("path_traversal")
	commandPatterns = compileCategory("command_injection")
}

// compileCategory turns the rule list for a category into the
// `[]*regexp.Regexp` slice the sanitizer functions iterate over.
// Prefers `pattern_safe` (the ReDoS-safe variant) when present,
// falls back to `pattern`. Mirrors the loader logic in Python's
// `arcis/sanitizers/sanitize.py:_compile_rules` and Node's
// pattern-consumption convention.
func compileCategory(category string) []*regexp.Regexp {
	cat, ok := loadedPatterns.Patterns[category]
	if !ok {
		return nil
	}
	out := make([]*regexp.Regexp, 0, len(cat.Rules))
	for _, rule := range cat.Rules {
		// Prefer the ReDoS-safe variant when both are provided.
		raw := rule.PatternSafe
		if raw == "" {
			raw = rule.Pattern
		}
		if raw == "" {
			continue
		}
		// Go regex uses `(?i)` prefix syntax for the case-insensitive
		// flag. Other flags ("g", "m") are noise here — `g` is implicit
		// in `ReplaceAllString`, `m` we don't currently use.
		if strings.Contains(rule.Flags, "i") {
			raw = "(?i)" + raw
		}
		re, err := regexp.Compile(raw)
		if err != nil {
			// Don't panic on a single bad pattern — log via panic in
			// init() would crash apps. Skip the rule and continue;
			// loud-fail in tests instead via TestEmbeddedPatternsAllCompile.
			continue
		}
		out = append(out, re)
	}
	return out
}

// LoadedSpecVersion returns the version string from the embedded
// patterns.json. Used by tests to confirm the bundled copy matches
// what's expected.
func LoadedSpecVersion() string {
	return loadedPatterns.Version
}

// DangerousKeysFor returns the list of dangerous keys for a given
// category (e.g. `nosql_injection`, `prototype_pollution`). Used by
// SanitizeMap-style helpers that need to strip dangerous object keys.
// Returns nil if the category has no `dangerous_keys` field.
func DangerousKeysFor(category string) []string {
	cat, ok := loadedPatterns.Patterns[category]
	if !ok {
		return nil
	}
	return cat.DangerousKeys
}
