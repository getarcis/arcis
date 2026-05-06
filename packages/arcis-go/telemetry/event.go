package telemetry

// Decision is the final middleware decision attached to a TelemetryEvent.
// Wire values are lowercase per spec/API_SPEC.md §9.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionDeny      Decision = "deny"
	DecisionChallenge Decision = "challenge"
)

// Severity is the finding severity for a denied/challenged request.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Event mirrors spec/API_SPEC.md §9 wire shape (camelCase JSON keys).
//
// Required-on-wire fields carry no omitempty so a zero value still emits.
// LatencyMs in particular always emits — a measured 0ms is signal, an
// absent field is server-side fallback. Optional fields use omitempty
// so the on-wire shape stays minimal when middleware doesn't fill them.
type Event struct {
	Ts             string   `json:"ts,omitempty"`
	IP             string   `json:"ip"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	Decision       Decision `json:"decision"`
	Vector         string   `json:"vector,omitempty"`
	Rule           string   `json:"rule,omitempty"`
	Severity       Severity `json:"severity,omitempty"`
	Country        string   `json:"country,omitempty"`
	UserAgent      string   `json:"userAgent,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Status         int      `json:"status"`
	MatchedPattern string   `json:"matchedPattern,omitempty"`
	LatencyMs      float64  `json:"latencyMs"`
}
