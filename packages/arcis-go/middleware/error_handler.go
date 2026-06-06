package middleware

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/getarcis/arcis/v2/logging"
)

// Patterns that indicate database or infrastructure internals in error messages.
var sensitiveErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(SQLITE_ERROR|SQLSTATE|ORA-\d|PG::|mysql_|pg_query|ECONNREFUSED)`),
	regexp.MustCompile(`(?i)\b(syntax error at or near|relation ".*" does not exist)`),
	regexp.MustCompile(`(?i)\b(duplicate key value violates unique constraint)`),
	regexp.MustCompile(`(?i)\b(table .* doesn't exist|unknown column)`),
	regexp.MustCompile(`(?i)\b(MongoError|MongoServerError|MongoNetworkError|E11000 duplicate key)`),
	regexp.MustCompile(`(?i)\b(WRONGTYPE|CROSSSLOT|CLUSTERDOWN|READONLY|ReplyError)`),
	regexp.MustCompile(`(?i)\b(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://)`),
	regexp.MustCompile(`(?i)\bat\s+.*\.(js|ts|py|go|java):\d+`),
	regexp.MustCompile(`\b(127\.0\.0\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b`),
}

// ContainsSensitiveInfo checks if an error message contains sensitive
// infrastructure details (database errors, connection strings, internal IPs).
func ContainsSensitiveInfo(message string) bool {
	for _, pattern := range sensitiveErrorPatterns {
		if pattern.MatchString(message) {
			return true
		}
	}
	return false
}

// ErrorHandler provides production-safe error responses.
type ErrorHandler struct {
	isDev     bool
	logErrors bool
	logger    *logging.SafeLogger
}

// NewErrorHandler creates a new ErrorHandler.
// In production (isDev=false), error details are hidden.
func NewErrorHandler(isDev bool) *ErrorHandler {
	return &ErrorHandler{
		isDev:     isDev,
		logErrors: true,
		logger:    logging.NewSafeLogger(),
	}
}

// NewErrorHandlerWithLogger creates an ErrorHandler with a custom logger.
func NewErrorHandlerWithLogger(isDev bool, logger *logging.SafeLogger) *ErrorHandler {
	return &ErrorHandler{
		isDev:     isDev,
		logErrors: true,
		logger:    logger,
	}
}

// Handle writes an error response, hiding details in production.
// In production mode, scrubs database errors, connection strings, and internal IPs.
func (eh *ErrorHandler) Handle(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{}

	if statusCode >= 500 {
		response["error"] = "Internal Server Error"
	} else {
		msg := err.Error()
		if !eh.isDev && ContainsSensitiveInfo(msg) {
			response["error"] = "Internal Server Error"
		} else {
			response["error"] = msg
		}
	}

	if eh.isDev {
		response["details"] = err.Error()
	}

	json.NewEncoder(w).Encode(response)
}

// HandleFunc returns an http.HandlerFunc for error handling.
func (eh *ErrorHandler) HandleFunc(next func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := next(w, r); err != nil {
			statusCode := http.StatusInternalServerError
			if httpErr, ok := err.(interface{ StatusCode() int }); ok {
				statusCode = httpErr.StatusCode()
			}
			eh.Handle(w, err, statusCode)
		}
	}
}
