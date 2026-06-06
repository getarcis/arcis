package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/GagancM/arcis/sanitizers"
)

// GraphQL guard middleware (sdk-vectors.md tier 1 #21).
//
// HTTP adapter for sanitizers.InspectGraphqlQuery. Wraps the request
// body on configured paths (default /graphql) and blocks queries that
// violate the configured depth / introspection / length limits before
// the resolver sees them.
//
// Why a separate module from sanitizers/graphql.go: the sanitizer is
// the pure logic; this file is the framework adapter (Pattern 3).
//
// Mirrors arcis-python/arcis/middleware/graphql.py.
//
// Example:
//
//	mux := http.NewServeMux()
//	guarded := GraphqlGuard(GraphqlGuardMiddlewareOptions{
//	    Options: sanitizers.NewGraphqlGuardOptions(),
//	    OnlyPaths: []string{"/graphql", "/api/graphql"},
//	})(graphqlHandler)

// GraphqlGuardMiddlewareOptions configures the middleware.
type GraphqlGuardMiddlewareOptions struct {
	// Options is the inspector configuration. Use
	// sanitizers.NewGraphqlGuardOptions() for safe defaults; Go's
	// zero-value bool semantics on the embedded BlockIntrospection
	// would otherwise leave introspection unblocked.
	Options sanitizers.GraphqlGuardOptions

	// OnlyPaths scopes the middleware. Defaults to ["/graphql"].
	// Apps that mount GraphQL elsewhere (Hasura at /v1/graphql,
	// custom mounts) should override.
	OnlyPaths []string

	// StatusCode for the deny path. Default 400 Bad Request.
	StatusCode int
}

// GraphqlGuard returns middleware that inspects GraphQL POST bodies
// against the configured limits.
//
// Catches three threats:
//   - Depth-bomb (default max_depth=10)
//   - Introspection enumeration (__schema, __type, __typeKind, __directive)
//   - Over-long queries (default max_length=10000)
//
// Blocked queries get a 400 with body:
//
//	{"error": "graphql_query_blocked", "reason": "...", "depth": N, "length": N}
func GraphqlGuard(opts GraphqlGuardMiddlewareOptions) func(http.Handler) http.Handler {
	paths := opts.OnlyPaths
	if len(paths) == 0 {
		paths = []string{"/graphql"}
	}
	statusCode := opts.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadRequest
	}
	// Materialize options once so we don't re-resolve defaults per request.
	resolved := opts.Options
	if resolved.MaxDepth == 0 && resolved.MaxLength == 0 {
		// Caller passed the literal zero-value struct — give them
		// documented defaults rather than silently disabling every
		// limit. Matches the Go-zero-value rescue in
		// sanitizers.NewGraphqlGuardOptions().
		resolved = sanitizers.NewGraphqlGuardOptions()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			if !pathMatches(r.URL.Path, paths) {
				next.ServeHTTP(w, r)
				return
			}
			if !isJSONContentType(r.Header.Get("Content-Type")) {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			_ = r.Body.Close()

			queries := collectGraphqlQueries(body)
			for _, q := range queries {
				result := sanitizers.InspectGraphqlQuery(q, resolved)
				if result.Blocked {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(statusCode)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error":  "graphql_query_blocked",
						"reason": result.Reason,
						"depth":  result.Depth,
						"length": result.Length,
					})
					return
				}
			}

			// Replay the body so the inner handler can read it.
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r)
		})
	}
}

// pathMatches checks if `path` matches any prefix in `prefixes`. A
// prefix matches when the path is exactly equal OR when path starts
// with `<prefix>/` so that `/graphql/foo` matches the `/graphql` prefix
// but `/graphqlx` does not.
func pathMatches(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p {
			return true
		}
		if strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// collectGraphqlQueries pulls every `query` field out of a GraphQL
// request body. Accepts:
//   - {"query": "...", ...}                — single
//   - [{"query": "..."}, {"query": "..."}] — batched
//
// Anything else returns an empty slice — the middleware lets it through
// and the resolver returns its own error.
func collectGraphqlQueries(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	// Try single-query shape first.
	var single map[string]interface{}
	if err := json.Unmarshal(body, &single); err == nil {
		if q, ok := single["query"].(string); ok {
			return []string{q}
		}
		return nil
	}
	// Try batched shape.
	var batch []map[string]interface{}
	if err := json.Unmarshal(body, &batch); err == nil {
		out := make([]string, 0, len(batch))
		for _, entry := range batch {
			if q, ok := entry["query"].(string); ok {
				out = append(out, q)
			}
		}
		return out
	}
	return nil
}
