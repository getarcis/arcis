package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Mass-assignment runtime guard (sdk-vectors.md tier 1 #25).
//
// The classic mass-assignment vulnerability:
//
//	var u User
//	json.NewDecoder(r.Body).Decode(&u)   // attacker sets IsAdmin = true
//	db.Save(&u)
//
// This middleware filters the JSON request body to a per-route
// allowlist before the handler runs. Two modes:
//
//   - "strip" (default) silently drop disallowed keys, continue.
//   - "reject" return statusCode (default 400) listing the offending keys.
//
// Pair it with the audit rule (MASS-ASSIGN in `arcis audit`) for the
// static-analysis side. Audit catches `json.Unmarshal(body, &user)`
// patterns at build time; this middleware catches the runtime data flow.
//
// Default scope is top-level keys only. Nested objects pass through
// untouched — that's deliberate: nested allowlists encourage
// `allow: []string{"profile.bio"}` style strings which become a parser,
// not a guard.
//
// Mirrors arcis-python/arcis/middleware/mass_assignment.py.

// ErrEmptyAllowlist is returned by MassAssign when the allow list is empty.
// A missing allowlist would silently strip every key — almost certainly
// a configuration mistake, so fail loud at construction.
var ErrEmptyAllowlist = errors.New("mass assign: allow list must not be empty")

// MassAssignMode controls the action taken when disallowed keys are
// detected.
type MassAssignMode string

const (
	// MassAssignStrip silently drops disallowed keys. Preserves
	// availability; existing handlers don't break.
	MassAssignStrip MassAssignMode = "strip"
	// MassAssignReject returns the configured status code with the
	// disallowed key list. Use when the route should fail-closed.
	MassAssignReject MassAssignMode = "reject"
)

// MassAssignOptions configures the middleware.
type MassAssignOptions struct {
	// Allow lists the permitted top-level JSON keys. MUST be non-empty.
	Allow []string

	// Mode is "strip" (default) or "reject".
	Mode MassAssignMode

	// StatusCode for the reject path. Default 400.
	StatusCode int

	// Message in the reject body. Default "Disallowed fields".
	Message string
}

// MassAssign returns an http.Handler middleware factory that filters
// JSON request bodies to the configured allowlist.
//
// Only triggers on application/json requests; other content types pass
// through. The middleware reads the full body, applies the filter, and
// forwards a rebuilt body downstream so the handler sees only allowed
// keys.
//
// Example with net/http:
//
//	mux := http.NewServeMux()
//	mux.Handle("/users", MassAssign(MassAssignOptions{
//	    Allow: []string{"email", "password", "name"},
//	})(usersHandler))
//
// Returns an error from the middleware factory if Allow is empty.
func MassAssign(opts MassAssignOptions) func(http.Handler) http.Handler {
	if len(opts.Allow) == 0 {
		// Wrap an always-error handler — fail at first request rather
		// than silently strip every field. Mirrors Node's TypeError
		// thrown at middleware construction.
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, ErrEmptyAllowlist.Error(), http.StatusInternalServerError)
			})
		}
	}
	allowSet := make(map[string]struct{}, len(opts.Allow))
	for _, k := range opts.Allow {
		allowSet[k] = struct{}{}
	}
	mode := opts.Mode
	if mode == "" {
		mode = MassAssignStrip
	}
	statusCode := opts.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadRequest
	}
	message := opts.Message
	if message == "" {
		message = "Disallowed fields"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			if len(body) == 0 {
				r.Body = io.NopCloser(bytes.NewReader(nil))
				next.ServeHTTP(w, r)
				return
			}

			// Try to decode as a JSON object. Anything that isn't an
			// object (array, string, etc.) flows through unchanged —
			// mass-assignment applies only to top-level field expansion.
			var parsed map[string]interface{}
			if err := json.Unmarshal(body, &parsed); err != nil {
				// Not a JSON object. Replay the body unchanged and let
				// the handler return its own validation error.
				r.Body = io.NopCloser(bytes.NewReader(body))
				next.ServeHTTP(w, r)
				return
			}

			var disallowed []string
			filtered := make(map[string]interface{}, len(parsed))
			for k, v := range parsed {
				if _, ok := allowSet[k]; ok {
					filtered[k] = v
				} else {
					disallowed = append(disallowed, k)
				}
			}

			if len(disallowed) > 0 && mode == MassAssignReject {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(statusCode)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":  message,
					"fields": disallowed,
				})
				return
			}

			rebuilt, err := json.Marshal(filtered)
			if err != nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(rebuilt))
			r.ContentLength = int64(len(rebuilt))
			next.ServeHTTP(w, r)
		})
	}
}

// isJSONContentType returns true when the Content-Type header indicates
// a JSON body. Tolerates the common application/json + charset shape.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	// Cheap prefix check — covers application/json, application/json;
	// charset=utf-8, and the older application/vnd.api+json shape.
	return containsCaseInsensitive(ct, "application/json") ||
		containsCaseInsensitive(ct, "+json")
}

// containsCaseInsensitive is a small helper to avoid pulling strings
// when we only need a case-insensitive substring check.
func containsCaseInsensitive(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	// Walk-and-compare with ASCII case folding. Faster than ToLower
	// allocation for the typical short Content-Type header.
	subLen := len(substr)
	for i := 0; i <= len(s)-subLen; i++ {
		match := true
		for j := 0; j < subLen; j++ {
			a := s[i+j]
			b := substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
