// Package telemetry ships TelemetryEvents to an Arcis dashboard server.
//
// The Client is the Go counterpart of TelemetryClient in
// packages/arcis-node/src/telemetry/client.ts and
// packages/arcis-python/arcis/telemetry/client.py. It follows the same
// spec/API_SPEC.md §9 contract:
//
//  1. Send is non-blocking and never panics — safe from request hot paths.
//  2. Flushes trigger on BatchSize OR FlushInterval, whichever fires first.
//  3. Network errors are fail-open: OnError fires, batch is dropped.
//  4. Close attempts one final flush; idempotent.
//  5. Drop-oldest when the queue exceeds MaxQueueSize.
//
// Stdlib only: net/http, encoding/json, sync, time, context, os/signal.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Client is an in-memory, batching telemetry shipper. Construct with
// NewClient and dispose with Close. Safe for concurrent Send from many
// request goroutines.
type Client struct {
	endpoint    string
	apiKey      string
	workspaceID string
	batchSize   int
	flushEvery  time.Duration
	maxQueue    int
	onError     func(error)
	onOverflow  func(int)
	httpClient  *http.Client

	mu                sync.Mutex
	queue             []Event
	droppedSinceFlush int
	closed            bool

	flushMu sync.Mutex

	wakeup chan struct{}
	done   chan struct{}
	wg     sync.WaitGroup

	closeOnce sync.Once
	closeErr  error

	sigOnce sync.Once
	sigCh   chan os.Signal
}

// batchEnvelope is the on-wire payload shape: {"events":[...]}. Declared
// as a struct (not map[string]any) so encoding/json emits a fixed key.
type batchEnvelope struct {
	Events []Event `json:"events"`
}

// NewClient validates Options, applies defaults, and starts the background
// flush goroutine. Returns an error if Endpoint is empty.
func NewClient(opts Options) (*Client, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("telemetry: Endpoint is required")
	}

	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}

	flushEvery := opts.FlushInterval
	if flushEvery <= 0 {
		flushEvery = DefaultFlushInterval
	}
	if flushEvery < MinFlushInterval {
		flushEvery = MinFlushInterval
	}

	maxQueue := opts.MaxQueueSize
	if maxQueue <= 0 {
		maxQueue = DefaultMaxQueueSize
	}
	if maxQueue < batchSize {
		maxQueue = batchSize
	}

	onError := opts.OnError
	if onError == nil {
		onError = func(error) {}
	}
	onOverflow := opts.OnQueueOverflow
	if onOverflow == nil {
		onOverflow = func(int) {}
	}

	c := &Client{
		endpoint:    opts.Endpoint,
		apiKey:      opts.APIKey,
		workspaceID: opts.WorkspaceID,
		batchSize:   batchSize,
		flushEvery:  flushEvery,
		maxQueue:    maxQueue,
		onError:     onError,
		onOverflow:  onOverflow,
		httpClient:  &http.Client{Timeout: flushTimeout},
		queue:       make([]Event, 0, batchSize),
		wakeup:      make(chan struct{}, 1),
		done:        make(chan struct{}),
	}

	c.wg.Add(1)
	go c.run()
	return c, nil
}

// Send enqueues an event. Non-blocking, safe from any goroutine, never
// panics — a recovered panic from a user-supplied callback is swallowed.
// Send after Close is a silent no-op.
func (c *Client) Send(evt Event) {
	defer func() { _ = recover() }()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.queue = append(c.queue, evt)

	var dropped int
	if len(c.queue) > c.maxQueue {
		n := len(c.queue) - c.maxQueue
		c.queue = c.queue[n:]
		c.droppedSinceFlush += n
		dropped = c.droppedSinceFlush
	}
	triggerFlush := len(c.queue) >= c.batchSize
	c.mu.Unlock()

	if dropped > 0 {
		c.safeOverflow(dropped)
	}
	if triggerFlush {
		c.signalWakeup()
	}
}

// Flush synchronously POSTs up to BatchSize queued events. Serialized by
// flushMu so concurrent callers (worker + manual Flush) never overlap.
// Errors are routed to OnError; Flush itself does not return an error.
func (c *Client) Flush() {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()

	c.mu.Lock()
	if len(c.queue) == 0 {
		c.mu.Unlock()
		return
	}
	n := c.batchSize
	if n > len(c.queue) {
		n = len(c.queue)
	}
	batch := make([]Event, n)
	copy(batch, c.queue[:n])
	c.queue = c.queue[n:]
	c.mu.Unlock()

	if err := c.send(batch); err != nil {
		c.safeError(err)
		return
	}

	c.mu.Lock()
	c.droppedSinceFlush = 0
	pending := len(c.queue)
	closed := c.closed
	c.mu.Unlock()

	if !closed && pending > 0 {
		c.signalWakeup()
	}
}

// Close stops the background goroutine and attempts one final flush.
// Idempotent — second and later calls return the first call's error.
// ctx bounds the wait for the worker to exit; on timeout, no final flush
// runs and ctx.Err() is returned.
func (c *Client) Close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()

		close(c.done)

		if c.sigCh != nil {
			signal.Stop(c.sigCh)
		}

		if ctx == nil {
			ctx = context.Background()
		}

		joinCh := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(joinCh)
		}()

		select {
		case <-joinCh:
			c.Flush()
		case <-ctx.Done():
			c.closeErr = ctx.Err()
		}
	})
	return c.closeErr
}

// InstallShutdownHooks registers SIGTERM / SIGINT handlers that call
// Close. Opt-in — libraries should not silently grab process signals.
// Idempotent. The handler closes with a closeJoinTimeout-bounded context.
func (c *Client) InstallShutdownHooks() {
	c.sigOnce.Do(func() {
		c.sigCh = make(chan os.Signal, 1)
		signal.Notify(c.sigCh, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			_, ok := <-c.sigCh
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), closeJoinTimeout)
			defer cancel()
			_ = c.Close(ctx)
		}()
	})
}

// PendingCount returns the number of events currently waiting to be sent.
// Useful for tests and operators surfacing a queue-depth metric.
func (c *Client) PendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queue)
}

// ── internals ─────────────────────────────────────────────────────────

func (c *Client) run() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.Flush()
		case <-c.wakeup:
			c.Flush()
		}
	}
}

func (c *Client) signalWakeup() {
	select {
	case c.wakeup <- struct{}{}:
	default:
	}
}

func (c *Client) safeError(err error) {
	defer func() { _ = recover() }()
	c.onError(err)
}

func (c *Client) safeOverflow(n int) {
	defer func() { _ = recover() }()
	c.onOverflow(n)
}

func (c *Client) send(batch []Event) error {
	body, err := json.Marshal(batchEnvelope{Events: batch})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.workspaceID != "" {
		req.Header.Set("X-Workspace-Id", c.workspaceID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return &HTTPError{Status: resp.StatusCode, Body: string(b)}
	}
	return nil
}
