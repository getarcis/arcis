package telemetry

import "time"

// Default and bound constants matching the Node + Python clients
// (packages/arcis-node/src/telemetry/client.ts and
// packages/arcis-python/arcis/telemetry/client.py).
const (
	DefaultBatchSize     = 50
	MaxBatchSize         = 500
	DefaultFlushInterval = 5 * time.Second
	MinFlushInterval     = 500 * time.Millisecond
	DefaultMaxQueueSize  = 10_000

	flushTimeout     = 10 * time.Second
	closeJoinTimeout = 2 * time.Second
)

// Options configures a Client. Endpoint is required; everything else has
// a sensible default. Construct with a struct literal — no builder.
type Options struct {
	// Endpoint is the full ingest URL, e.g.
	// "https://arcis.mycompany.com/v1/events". Required.
	Endpoint string

	// APIKey, if set, is sent as "Authorization: Bearer <APIKey>".
	APIKey string

	// WorkspaceID, if set, is sent as the "X-Workspace-Id" header.
	WorkspaceID string

	// BatchSize triggers a flush when the queue reaches this length.
	// Clamped to [1, MaxBatchSize]. Zero/unset = DefaultBatchSize.
	BatchSize int

	// FlushInterval is the periodic flush cadence. Zero/unset =
	// DefaultFlushInterval. Values below MinFlushInterval are clamped up.
	FlushInterval time.Duration

	// MaxQueueSize bounds the in-memory queue. When exceeded, drop-oldest
	// kicks in: the oldest events are discarded to make room for the
	// freshest. Zero/unset = DefaultMaxQueueSize. Always >= BatchSize.
	MaxQueueSize int

	// OnError is called for transport / non-2xx failures. The batch is
	// dropped — no retry, no disk persistence. Default: silent.
	OnError func(error)

	// OnQueueOverflow fires once per overflow window with the number of
	// events dropped since the last successful flush. Resets to 0 on each
	// successful POST. Default: silent.
	OnQueueOverflow func(int)
}
