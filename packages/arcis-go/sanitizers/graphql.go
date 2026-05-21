package sanitizers

import "regexp"

// GraphQL injection prevention (sdk-vectors.md tier 1 #21).
//
// Two threats covered:
//
//  1. Depth-bomb DoS — nested-query payloads like
//     `query { x { x { x { ... } } } }` to ridiculous depth that explode
//     resolver work (each `{` typically maps to a database round-trip).
//     Even a 50-deep query against a real schema can hammer the
//     backend; 1000-deep crashes the resolver entirely.
//
//  2. Introspection abuse — `__schema` / `__type` / `__typeKind` /
//     `__directive` queries that let an attacker enumerate the entire
//     schema, then use that map to find sensitive fields, deprecated
//     mutations, or unprotected admin paths.
//
// v1 is character-counting based: count `{` / `}` for nesting depth (no
// string-literal escape handling — strings inside the query that
// contain `{` will over-count). False positives are an acceptable
// tradeoff for v1 because (a) the depth threshold is well above
// legitimate query shapes, (b) a real GraphQL parser pulls in
// github.com/graphql-go/graphql as a runtime dep, significant for a
// sanitizer that ships stdlib-only.
//
// Mirrors arcis-node/src/sanitizers/graphql.ts and
// arcis-python/arcis/sanitizers/graphql.py byte-for-byte on the
// inspection contract — same defaults, same precedence
// (depth > introspection > length).
//
// NOT included in v1:
// - Field-count limit (some servers have this; orthogonal to depth)
// - Alias-bomb detection (`q { f1: foo, f2: foo, ...}`)
// - Variable rebinding attacks

// Word-boundary `__` reflection markers. GraphQL spec reserves the
// `__` prefix for introspection — `__schema`, `__type`, `__typename`,
// `__typeKind`, `__directive`. Matching the prefix catches them all
// without enumerating; the boundary anchor (`\b__`) avoids
// false-matches on user fields like `last__updated_at`.
//
// `__typename` is the one introspection field that's commonly used
// legitimately (Apollo client requests it on every query). We
// deliberately let it through by listing the others explicitly.
var graphqlIntrospectionPattern = regexp.MustCompile(`\b__(schema|type|typeKind|directive)\b`)

// GraphqlGuardOptions configures the inspector.
type GraphqlGuardOptions struct {
	// MaxDepth — maximum allowed nesting depth. Default 10. Most legit
	// queries are under 8.
	MaxDepth int

	// MaxLength — maximum query string length in characters. Default
	// 10000.
	MaxLength int

	// BlockIntrospection — block introspection queries (`__schema`,
	// `__type`). Default true. Set false in development if you rely on
	// GraphiQL / Apollo Studio. Production should leave this on.
	BlockIntrospection bool
}

// GraphqlGuardResult is the outcome of inspecting a query.
type GraphqlGuardResult struct {
	// Blocked is true if the query violated any configured limit.
	Blocked bool

	// Reason is which limit fired first (depth > introspection >
	// length precedence). Empty when Blocked is false.
	Reason string

	// Depth is the observed nesting depth. Always returned, even on
	// clean queries.
	Depth int

	// Length is the observed length. Always returned.
	Length int
}

// defaultGraphqlOptions returns the canonical defaults so passing a
// zero-value options struct still gets the sane behavior. Mirrors
// Node's DEFAULTS const and Python's GraphqlGuardOptions dataclass
// defaults.
func defaultGraphqlOptions() GraphqlGuardOptions {
	return GraphqlGuardOptions{
		MaxDepth:           10,
		MaxLength:          10000,
		BlockIntrospection: true,
	}
}

// resolveGraphqlOptions fills in zero-valued fields from the defaults.
// Lets callers override only the fields they care about while staying
// safe-by-default. (Pattern 6: Defensive Defaults.)
func resolveGraphqlOptions(opts GraphqlGuardOptions) GraphqlGuardOptions {
	d := defaultGraphqlOptions()
	if opts.MaxDepth == 0 {
		opts.MaxDepth = d.MaxDepth
	}
	if opts.MaxLength == 0 {
		opts.MaxLength = d.MaxLength
	}
	// BlockIntrospection is a bool — Go has no nil for it. Caller
	// either passes the zero-value options struct (which gives them
	// BlockIntrospection=false, NOT the documented default), or they
	// build it explicitly. We document this explicitly and provide
	// the helper NewGraphqlGuardOptions() below so callers can opt
	// into the "all defaults" path safely.
	return opts
}

// NewGraphqlGuardOptions returns the documented defaults. Callers who
// want non-zero defaults but Go's zero-value semantics would otherwise
// bite them (BlockIntrospection=false) should use this.
//
//	opts := NewGraphqlGuardOptions()
//	opts.MaxDepth = 5     // tighter than default
//	result := InspectGraphqlQuery(q, opts)
func NewGraphqlGuardOptions() GraphqlGuardOptions {
	return defaultGraphqlOptions()
}

// computeGraphqlDepth computes the maximum nesting depth by counting
// `{` and `}` runs. Strings inside the query (e.g.
// `field(arg: "{...}")`) inflate this — accepted v1 tradeoff.
func computeGraphqlDepth(query string) int {
	depth := 0
	maxDepth := 0
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '{' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if c == '}' {
			// Don't go negative on malformed input — clamp at 0.
			if depth > 0 {
				depth--
			}
		}
	}
	return maxDepth
}

// InspectGraphqlQuery inspects a GraphQL query against the configured
// limits. Returns a structured result; middleware uses this directly.
// Pure function — no I/O, no framework handles.
//
// Use NewGraphqlGuardOptions() as your starting point to get safe
// defaults; Go's zero-value semantics on bool would otherwise leave
// BlockIntrospection=false if you pass a literal GraphqlGuardOptions{}.
//
// Precedence: depth > introspection > length. Most security-critical
// signal wins so the caller knows the right reason to surface.
func InspectGraphqlQuery(query string, opts GraphqlGuardOptions) GraphqlGuardResult {
	resolved := resolveGraphqlOptions(opts)
	length := len(query)
	depth := computeGraphqlDepth(query)

	if depth > resolved.MaxDepth {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "depth",
			Depth:   depth,
			Length:  length,
		}
	}
	if resolved.BlockIntrospection && graphqlIntrospectionPattern.MatchString(query) {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "introspection",
			Depth:   depth,
			Length:  length,
		}
	}
	if length > resolved.MaxLength {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "length",
			Depth:   depth,
			Length:  length,
		}
	}
	return GraphqlGuardResult{Blocked: false, Depth: depth, Length: length}
}

// DetectGraphqlAbuse is the boolean-only API matching the rest of the
// sanitizer module surface (DetectXSS / DetectSQL / etc.). Returns true
// when InspectGraphqlQuery would block the query at default settings.
//
// Use InspectGraphqlQuery when you need the structured reason.
func DetectGraphqlAbuse(query string) bool {
	if query == "" {
		return false
	}
	return InspectGraphqlQuery(query, NewGraphqlGuardOptions()).Blocked
}
