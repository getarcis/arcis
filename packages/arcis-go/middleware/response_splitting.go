package middleware

import (
	"net/http"

	"github.com/getarcis/arcis/sanitizers"
)

// HTTP response splitting prevention (sdk-vectors.md tier 1 #27).
//
// Response splitting is the output counterpart to header injection:
// app code passes user input into a response header without stripping
// CR/LF, and an attacker uses the embedded newline to break out of the
// header block and forge a second response. Most often weaponised
// against Location: after a redirect that reflects user input
// (`/redirect?to=...`).
//
// SanitizeHeaderValue (in sanitizers/headers.go) covers the byte-level
// fix on the way in; this middleware wraps the response on the way out
// so every header that leaves the app gets sanitised even when the app
// forgets.
//
// Two modes:
//
//   - "strip" (default) silently sanitise the value before it reaches
//     the wire. Preserves availability; existing routes don't break.
//   - "reject" emit a 500 instead. Use in apps that would rather
//     fail-closed than emit a partial response. The wrapped
//     ResponseWriter buffers the WriteHeader call; if any header
//     value contains CR/LF/NUL, the response is replaced with a 500
//     before any body is written.
//
// Mirrors arcis-python/arcis/middleware/response_splitting.py.

// ResponseSplittingMode controls behavior when a CR/LF/NUL is detected
// in an outgoing header value.
type ResponseSplittingMode string

const (
	// ResponseSplittingStrip silently sanitises offending header values.
	ResponseSplittingStrip ResponseSplittingMode = "strip"
	// ResponseSplittingReject emits a 500 instead of letting a partial
	// response leave the server.
	ResponseSplittingReject ResponseSplittingMode = "reject"
)

// ResponseSplittingOptions configures the middleware.
type ResponseSplittingOptions struct {
	// Mode is "strip" (default) or "reject".
	Mode ResponseSplittingMode

	// OnDetect fires before strip/reject when a CRLF/NUL payload is
	// detected. Receives (headerName, originalValue). Useful for
	// logging or alerting when an attempted split slips through into
	// the response builder.
	OnDetect func(header, value string)
}

// ResponseSplittingGuard returns middleware that sanitises every
// outgoing response header value against CR/LF/NUL response-splitting
// payloads.
//
// Pair with ValidateRedirect for full coverage: this middleware blocks
// the response-splitting payload, ValidateRedirect blocks the
// open-redirect payload.
//
//	mux.Use(ResponseSplittingGuard(ResponseSplittingOptions{}))
func ResponseSplittingGuard(opts ResponseSplittingOptions) func(http.Handler) http.Handler {
	mode := opts.Mode
	if mode == "" {
		mode = ResponseSplittingStrip
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapped := &responseSplittingWriter{
				ResponseWriter: w,
				mode:           mode,
				onDetect:       opts.OnDetect,
			}
			next.ServeHTTP(wrapped, r)
		})
	}
}

// responseSplittingWriter intercepts WriteHeader to sanitise (or
// reject) any outgoing header value containing CR/LF/NUL. Wrapping
// happens once per request; the overhead is one header-map walk per
// response, no extra allocations on clean headers.
type responseSplittingWriter struct {
	http.ResponseWriter
	mode          ResponseSplittingMode
	onDetect      func(header, value string)
	headerWritten bool
	rejected      bool
}

func (w *responseSplittingWriter) WriteHeader(status int) {
	if w.headerWritten {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.headerWritten = true

	header := w.ResponseWriter.Header()
	rejectFound := false
	for name, values := range header {
		for i, value := range values {
			if !sanitizers.DetectHeaderInjection(value) {
				continue
			}
			if w.onDetect != nil {
				w.onDetect(name, value)
			}
			if w.mode == ResponseSplittingReject {
				rejectFound = true
				break
			}
			values[i] = sanitizers.SanitizeHeaderValue(value)
		}
		if rejectFound {
			break
		}
		header[name] = values
	}

	if rejectFound {
		// Replace the about-to-be-sent response with a 500. We can't
		// rewind any body that might already have been written via
		// w.Write before WriteHeader was called (Go's http.ResponseWriter
		// allows Write-without-WriteHeader-first, which implicitly calls
		// WriteHeader(200) — but in the strip/reject path the handler is
		// almost always calling WriteHeader explicitly, e.g. via
		// http.Redirect, so this is the right point to intervene).
		header := w.ResponseWriter.Header()
		for k := range header {
			header.Del(k)
		}
		header.Set("Content-Type", "application/json")
		w.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		_, _ = w.ResponseWriter.Write([]byte(`{"error":"response_splitting_blocked"}`))
		w.rejected = true
		return
	}

	w.ResponseWriter.WriteHeader(status)
}

func (w *responseSplittingWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	if w.rejected {
		// Suppress further writes; rejection response already emitted.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
