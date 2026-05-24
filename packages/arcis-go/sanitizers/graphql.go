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

// V34 — `label: fieldName` alias pattern. Bound by GraphQL Name shape:
// label must be a valid identifier; fieldName likewise. Argument
// type-decls (e.g. `id: ID!`) are excluded because the trailing token
// is not a Name. Real queries rarely exceed 20 aliases.
var graphqlAliasPattern = regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([a-zA-Z_][a-zA-Z0-9_]*)\b`)

// V34 — fragment definition header. Used to locate fragment bodies for
// the cycle-detection pass.
var graphqlFragmentDefPattern = regexp.MustCompile(`\bfragment\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+on\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{`)

// V34 — fragment spread inside a selection set (`...FragmentName`).
var graphqlFragmentSpreadPattern = regexp.MustCompile(`\.\.\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\b`)

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

	// MaxAliases — maximum number of field aliases per query (v1.6 V34).
	// Default 50. Alias-bomb attacks (`a:foo b:foo c:foo ...`) repeat the
	// same expensive resolver under many labels to amplify backend cost.
	// Counting alias occurrences is a cheap cap that legit queries rarely
	// hit (real apps use 5-15 aliases at most). Set higher only if you
	// have a documented reason.
	MaxAliases int

	// BlockFragmentCycles — reject queries whose fragment definitions
	// form a directed cycle (v1.6 V34). A fragment that recursively
	// spreads itself (directly or via A->B->A) can cause unbounded
	// resolver work. Default true.
	BlockFragmentCycles bool
}

// GraphqlGuardResult is the outcome of inspecting a query.
type GraphqlGuardResult struct {
	// Blocked is true if the query violated any configured limit.
	Blocked bool

	// Reason is which limit fired first (depth > introspection >
	// aliases > fragment_cycle > length precedence). Empty when
	// Blocked is false.
	Reason string

	// Depth is the observed nesting depth. Always returned, even on
	// clean queries.
	Depth int

	// Length is the observed length. Always returned.
	Length int

	// Aliases is the observed alias count (v1.6 V34). Always returned.
	Aliases int
}

// defaultGraphqlOptions returns the canonical defaults so passing a
// zero-value options struct still gets the sane behavior. Mirrors
// Node's DEFAULTS const and Python's GraphqlGuardOptions dataclass
// defaults.
func defaultGraphqlOptions() GraphqlGuardOptions {
	return GraphqlGuardOptions{
		MaxDepth:            10,
		MaxLength:           10000,
		BlockIntrospection:  true,
		MaxAliases:          50,
		BlockFragmentCycles: true,
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
	if opts.MaxAliases == 0 {
		opts.MaxAliases = d.MaxAliases
	}
	// BlockIntrospection + BlockFragmentCycles are bool — Go has no nil
	// for them. Caller either passes the zero-value options struct
	// (which gives them both =false, NOT the documented default), or
	// they build it explicitly. We document this explicitly and provide
	// NewGraphqlGuardOptions() below so callers can opt into the "all
	// defaults" path safely.
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

// countGraphqlAliases counts aliased fields in the query (v1.6 V34).
// Alias-bomb attacks repeat the same resolver under many labels;
// counting occurrences is a cheap cap that legit queries rarely hit.
func countGraphqlAliases(query string) int {
	return len(graphqlAliasPattern.FindAllStringIndex(query, -1))
}

// hasGraphqlFragmentCycle detects cycles in the fragment spread graph
// (v1.6 V34). Builds adjacency from `fragment X on T { ...Y }`
// definitions and runs DFS for a back-edge. Catches both direct
// self-reference (`fragment A on T { ...A }`) and indirect cycles
// (`A -> B -> A`). Inline fragments (`... on Type`) have no name so
// they cannot form a named cycle and are ignored.
//
// Uses brace-matched body extraction so that spreads in a fragment's
// body are scoped correctly — without this, a fragment's "body" would
// extend into the subsequent query operation and capture spurious
// spreads (false-positive cycles).
func hasGraphqlFragmentCycle(query string) bool {
	deps := map[string]map[string]struct{}{}

	for _, m := range graphqlFragmentDefPattern.FindAllStringSubmatchIndex(query, -1) {
		// m = [matchStart, matchEnd, group1Start, group1End]
		name := query[m[2]:m[3]]
		bodyStart := m[1] // right after the opening `{`
		depth := 1
		i := bodyStart
		for i < len(query) && depth > 0 {
			c := query[i]
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
			}
			i++
		}
		var body string
		if depth == 0 {
			body = query[bodyStart : i-1]
		} else {
			body = query[bodyStart:i]
		}
		spreads := map[string]struct{}{}
		for _, sm := range graphqlFragmentSpreadPattern.FindAllStringSubmatch(body, -1) {
			spreads[sm[1]] = struct{}{}
		}
		deps[name] = spreads
	}

	if len(deps) == 0 {
		return false
	}

	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	for name := range deps {
		color[name] = white
	}

	var visit func(name string) bool
	visit = func(name string) bool {
		if color[name] == gray {
			return true // back-edge -> cycle
		}
		if color[name] == black {
			return false
		}
		children, ok := deps[name]
		if !ok {
			// Spread referencing a fragment that's not defined — not a
			// cycle in our graph; treat as terminal.
			return false
		}
		color[name] = gray
		for child := range children {
			if visit(child) {
				return true
			}
		}
		color[name] = black
		return false
	}

	for name := range deps {
		if visit(name) {
			return true
		}
	}
	return false
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
// BlockIntrospection + BlockFragmentCycles =false if you pass a literal
// GraphqlGuardOptions{}.
//
// Precedence: depth > introspection > aliases > fragment_cycle >
// length. Most security-critical signal wins so the caller knows the
// right reason to surface.
func InspectGraphqlQuery(query string, opts GraphqlGuardOptions) GraphqlGuardResult {
	resolved := resolveGraphqlOptions(opts)
	length := len(query)
	depth := computeGraphqlDepth(query)
	aliases := countGraphqlAliases(query)

	if depth > resolved.MaxDepth {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "depth",
			Depth:   depth,
			Length:  length,
			Aliases: aliases,
		}
	}
	if resolved.BlockIntrospection && graphqlIntrospectionPattern.MatchString(query) {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "introspection",
			Depth:   depth,
			Length:  length,
			Aliases: aliases,
		}
	}
	if aliases > resolved.MaxAliases {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "aliases",
			Depth:   depth,
			Length:  length,
			Aliases: aliases,
		}
	}
	if resolved.BlockFragmentCycles && hasGraphqlFragmentCycle(query) {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "fragment_cycle",
			Depth:   depth,
			Length:  length,
			Aliases: aliases,
		}
	}
	if length > resolved.MaxLength {
		return GraphqlGuardResult{
			Blocked: true,
			Reason:  "length",
			Depth:   depth,
			Length:  length,
			Aliases: aliases,
		}
	}
	return GraphqlGuardResult{Blocked: false, Depth: depth, Length: length, Aliases: aliases}
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
