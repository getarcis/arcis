package telemetry

import "fmt"

// HTTPError is surfaced through Options.OnError when the dashboard returns
// a non-2xx response. The body is truncated to 500 bytes to match the
// Node + Python clients.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("telemetry ingest returned HTTP %d", e.Status)
}
