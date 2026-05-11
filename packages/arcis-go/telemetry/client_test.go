package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─── Helpers ──────────────────────────────────────────────────────────

type capturedRequest struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// recordingServer captures every request body + headers and replies with
// the supplied status code. Cleanup is registered on t.
func recordingServer(t *testing.T, status int) (*httptest.Server, <-chan capturedRequest) {
	t.Helper()
	ch := make(chan capturedRequest, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- capturedRequest{
			method:  r.Method,
			path:    r.URL.Path,
			headers: r.Header.Clone(),
			body:    body,
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// blockingServer accepts requests but blocks each handler until a value
// is sent on `release`. Used to wedge the worker goroutine in-flight so
// the test goroutine can deterministically observe queue overflow.
func blockingServer(t *testing.T) (*httptest.Server, chan struct{}, <-chan capturedRequest) {
	t.Helper()
	release := make(chan struct{})
	ch := make(chan capturedRequest, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		ch <- capturedRequest{method: r.Method, path: r.URL.Path, headers: r.Header.Clone(), body: body}
		w.WriteHeader(200)
	}))
	t.Cleanup(func() {
		// Drain anything still parked on release so srv.Close() can return.
		select {
		case <-release:
		default:
			close(release)
		}
		srv.Close()
	})
	return srv, release, ch
}

func waitFor(t *testing.T, cond func() bool, deadline time.Duration, msg string) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func mustReceive(t *testing.T, ch <-chan capturedRequest, deadline time.Duration) capturedRequest {
	t.Helper()
	select {
	case req := <-ch:
		return req
	case <-time.After(deadline):
		t.Fatal("timeout waiting for captured request")
		return capturedRequest{}
	}
}

func mustNotReceive(t *testing.T, ch <-chan capturedRequest, window time.Duration) {
	t.Helper()
	select {
	case req := <-ch:
		t.Fatalf("unexpected request: %+v", req)
	case <-time.After(window):
	}
}

// sampleEvent returns a minimal event whose Path doubles as a probe ID.
func sampleEvent(id string) Event {
	return Event{
		Ts:        "2026-05-06T00:00:00Z",
		IP:        "1.2.3.4",
		Method:    "GET",
		Path:      "/" + id,
		Decision:  DecisionDeny,
		Status:    403,
		LatencyMs: 0,
	}
}

func decodeBatch(t *testing.T, body []byte) []Event {
	t.Helper()
	var env batchEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode batch: %v (body=%q)", err, body)
	}
	return env.Events
}

func paths(events []Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Path
	}
	return out
}

// ─── 1. BatchSize trigger ─────────────────────────────────────────────

func TestSend_BatchSizeTrigger_FiresPOST(t *testing.T) {
	srv, reqs := recordingServer(t, 200)
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     3,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	c.Send(sampleEvent("a"))
	c.Send(sampleEvent("b"))
	c.Send(sampleEvent("c"))

	req := mustReceive(t, reqs, time.Second)
	if req.method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.method)
	}
	if got := paths(decodeBatch(t, req.body)); !equalStrings(got, []string{"/a", "/b", "/c"}) {
		t.Errorf("paths = %v, want [/a /b /c]", got)
	}
}

// ─── 2. Ticker trigger ────────────────────────────────────────────────

func TestSend_TickerTrigger_FiresPOST(t *testing.T) {
	srv, reqs := recordingServer(t, 200)
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     1000,             // ticker is the only flush trigger
		FlushInterval: MinFlushInterval, // 500ms floor
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	c.Send(sampleEvent("solo"))

	req := mustReceive(t, reqs, MinFlushInterval+750*time.Millisecond)
	if got := paths(decodeBatch(t, req.body)); !equalStrings(got, []string{"/solo"}) {
		t.Errorf("paths = %v, want [/solo]", got)
	}
}

// ─── 3. Drop-oldest when queue full ───────────────────────────────────

func TestSend_DropOldest_KeepsFreshest(t *testing.T) {
	srv, release, reqs := blockingServer(t)

	var overflowCalls []int
	var overflowMu sync.Mutex
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     3,
		MaxQueueSize:  3,
		FlushInterval: 10 * time.Second,
		OnQueueOverflow: func(n int) {
			overflowMu.Lock()
			overflowCalls = append(overflowCalls, n)
			overflowMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Same defensive non-blocking release as TestOverflow's cleanup —
		// drains any wedged in-flight POST so c.Close doesn't wait on the
		// 10s flushTimeout when teardown happens in the wrong order.
		select {
		case release <- struct{}{}:
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = c.Close(ctx)
	})

	// Phase 1: queue 3 → batch trigger → worker drains them into in-flight
	// POST → blocks on `release`. PendingCount drops to 0.
	c.Send(sampleEvent("1"))
	c.Send(sampleEvent("2"))
	c.Send(sampleEvent("3"))
	waitFor(t, func() bool { return c.PendingCount() == 0 }, time.Second, "worker drains first batch")

	// Phase 2: queue is empty + worker is wedged. Fill to capacity, then
	// overflow. Each Send beyond capacity drops the oldest synchronously
	// on the calling goroutine.
	c.Send(sampleEvent("4")) // queue 1
	c.Send(sampleEvent("5")) // queue 2
	c.Send(sampleEvent("6")) // queue 3 (= MaxQueueSize, no drop)
	c.Send(sampleEvent("7")) // overflow: drop 1 → counter=1
	c.Send(sampleEvent("8")) // overflow: drop 1 → counter=2
	c.Send(sampleEvent("9")) // overflow: drop 1 → counter=3

	overflowMu.Lock()
	got := append([]int(nil), overflowCalls...)
	overflowMu.Unlock()
	if !equalInts(got, []int{1, 2, 3}) {
		t.Errorf("overflowCalls = %v, want [1 2 3]", got)
	}

	// Release worker so cleanup is clean.
	release <- struct{}{}
	first := mustReceive(t, reqs, time.Second)
	if got := paths(decodeBatch(t, first.body)); !equalStrings(got, []string{"/1", "/2", "/3"}) {
		t.Errorf("first batch paths = %v, want [/1 /2 /3]", got)
	}

	// Tail re-flush: worker drains the surviving 3 events.
	release <- struct{}{}
	second := mustReceive(t, reqs, time.Second)
	if got := paths(decodeBatch(t, second.body)); !equalStrings(got, []string{"/7", "/8", "/9"}) {
		t.Errorf("second batch paths = %v, want [/7 /8 /9] (freshest 3)", got)
	}
}

// ─── 4. Non-2xx → OnError, batch dropped ──────────────────────────────

func TestFlush_Non2xx_FiresOnError(t *testing.T) {
	srv, _ := recordingServer(t, 500)
	errCh := make(chan error, 4)
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     2,
		FlushInterval: 10 * time.Second,
		OnError:       func(e error) { errCh <- e },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	c.Send(sampleEvent("a"))
	c.Send(sampleEvent("b"))

	select {
	case got := <-errCh:
		var httpErr *HTTPError
		if !errors.As(got, &httpErr) {
			t.Fatalf("err type = %T (%v), want *HTTPError", got, got)
		}
		if httpErr.Status != 500 {
			t.Errorf("status = %d, want 500", httpErr.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("OnError not called within 1s")
	}

	// Batch was dropped on first failure — no retry.
	waitFor(t, func() bool { return c.PendingCount() == 0 }, 200*time.Millisecond, "queue drained (no retry)")
}

// ─── 5. Close drains pending events ───────────────────────────────────

func TestClose_DrainsPending(t *testing.T) {
	srv, reqs := recordingServer(t, 200)
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     50,               // batch trigger won't fire
		FlushInterval: 10 * time.Second, // ticker trigger won't fire
	})
	if err != nil {
		t.Fatal(err)
	}

	c.Send(sampleEvent("x"))
	c.Send(sampleEvent("y"))

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	req := mustReceive(t, reqs, time.Second)
	if got := paths(decodeBatch(t, req.body)); !equalStrings(got, []string{"/x", "/y"}) {
		t.Errorf("drained paths = %v, want [/x /y]", got)
	}
}

// ─── 6. Send after Close is a no-op ───────────────────────────────────

func TestSend_AfterClose_NoOp(t *testing.T) {
	srv, reqs := recordingServer(t, 200)
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     2,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c.Send(sampleEvent("post-close-1"))
	c.Send(sampleEvent("post-close-2"))

	if c.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0 (Send must be no-op after Close)", c.PendingCount())
	}
	mustNotReceive(t, reqs, 100*time.Millisecond)
}

// ─── 7. Empty endpoint returns error ──────────────────────────────────

func TestNewClient_EmptyEndpoint_ReturnsError(t *testing.T) {
	if _, err := NewClient(Options{}); err == nil {
		t.Fatal("expected error from empty Endpoint, got nil")
	}
}

// ─── 8. Wire format byte-equal fixture (LatencyMs:0 emits) ────────────

func TestEvent_WireFormat_ByteEqualFixture(t *testing.T) {
	evt := Event{
		Ts:       "2026-05-06T00:00:00Z",
		IP:       "1.2.3.4",
		Method:   "GET",
		Path:     "/api",
		Decision: DecisionDeny,
		Vector:   "xss",
		Status:   403,
		// LatencyMs intentionally 0 — must still serialize.
	}
	got, err := json.Marshal(batchEnvelope{Events: []Event{evt}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"events":[{"ts":"2026-05-06T00:00:00Z","ip":"1.2.3.4","method":"GET","path":"/api","decision":"deny","vector":"xss","status":403,"latencyMs":0}]}`
	if string(got) != want {
		t.Errorf("byte mismatch\n want %s\n got  %s", want, got)
	}
}

// ─── 9. Headers: auth + workspace when set, absent when blank ─────────

func TestSend_Headers_AuthAndWorkspace(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		srv, reqs := recordingServer(t, 200)
		c, err := NewClient(Options{
			Endpoint:      srv.URL,
			APIKey:        "sek",
			WorkspaceID:   "ws-42",
			BatchSize:     1,
			FlushInterval: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })

		c.Send(sampleEvent("h"))
		req := mustReceive(t, reqs, time.Second)
		if got := req.headers.Get("Authorization"); got != "Bearer sek" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer sek")
		}
		if got := req.headers.Get("X-Workspace-Id"); got != "ws-42" {
			t.Errorf("X-Workspace-Id = %q, want %q", got, "ws-42")
		}
		if got := req.headers.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
	})

	t.Run("absent when blank", func(t *testing.T) {
		srv, reqs := recordingServer(t, 200)
		c, err := NewClient(Options{
			Endpoint:      srv.URL,
			BatchSize:     1,
			FlushInterval: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })

		c.Send(sampleEvent("h"))
		req := mustReceive(t, reqs, time.Second)
		if got := req.headers.Get("Authorization"); got != "" {
			t.Errorf("Authorization unexpectedly set: %q", got)
		}
		if got := req.headers.Get("X-Workspace-Id"); got != "" {
			t.Errorf("X-Workspace-Id unexpectedly set: %q", got)
		}
	})
}

// ─── 10. Close is idempotent ──────────────────────────────────────────

func TestClose_Idempotent(t *testing.T) {
	srv, reqs := recordingServer(t, 200)
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     50,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	c.Send(sampleEvent("once"))
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	mustReceive(t, reqs, time.Second)

	// Second Close: no-op, no extra POST, no error.
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	mustNotReceive(t, reqs, 100*time.Millisecond)
}

// ─── 11. Drop-oldest counter resets after a successful flush ──────────

func TestOverflow_CounterResetsAfterSuccessfulFlush(t *testing.T) {
	srv, release, reqs := blockingServer(t)

	var overflowCalls []int
	var overflowMu sync.Mutex
	c, err := NewClient(Options{
		Endpoint:      srv.URL,
		BatchSize:     3,
		MaxQueueSize:  3,
		FlushInterval: 10 * time.Second,
		OnQueueOverflow: func(n int) {
			overflowMu.Lock()
			overflowCalls = append(overflowCalls, n)
			overflowMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Drain any in-flight POST that is still wedged on `<-release`
		// before c.Close runs. Otherwise c.Close's worker keeps the HTTP
		// request alive until the 10s flushTimeout fires — observable on
		// Docker-on-Windows when local TCP teardown is slower than usual.
		// Non-blocking send: if no handler is wedged the default branch
		// fires and this is a no-op.
		select {
		case release <- struct{}{}:
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = c.Close(ctx)
	})

	// Round 1: drive counter to 2.
	c.Send(sampleEvent("1"))
	c.Send(sampleEvent("2"))
	c.Send(sampleEvent("3"))
	waitFor(t, func() bool { return c.PendingCount() == 0 }, time.Second, "worker drains first batch")
	c.Send(sampleEvent("4"))
	c.Send(sampleEvent("5"))
	c.Send(sampleEvent("6")) // queue full, no drop yet
	c.Send(sampleEvent("7")) // drop 1 → counter 1
	c.Send(sampleEvent("8")) // drop 1 → counter 2

	// Release the wedged POST. Counter resets to 0 inside Flush.
	release <- struct{}{}
	mustReceive(t, reqs, time.Second) // first batch [1,2,3]
	// The tail re-flush of [6,7,8] also wedges on the next release; wait
	// for the worker to enter that POST so PendingCount==0 again.
	waitFor(t, func() bool { return c.PendingCount() == 0 }, time.Second, "worker drains tail batch")

	// Round 2: counter must start at 1, not at 3 (= 2+1).
	c.Send(sampleEvent("a"))
	c.Send(sampleEvent("b"))
	c.Send(sampleEvent("c")) // queue full
	c.Send(sampleEvent("d")) // drop 1 → counter 1 (PROOF of reset)
	c.Send(sampleEvent("e")) // drop 1 → counter 2

	overflowMu.Lock()
	got := append([]int(nil), overflowCalls...)
	overflowMu.Unlock()
	want := []int{1, 2, 1, 2}
	if !equalInts(got, want) {
		t.Errorf("overflowCalls = %v, want %v (reset to 1 in round 2 proves counter cleared)", got, want)
	}

	// Drain Round 2.
	release <- struct{}{}
	mustReceive(t, reqs, time.Second)
}

// ─── 12. Network error: server gone, OnError fires, no panic ──────────

func TestSend_NetworkError_FiresOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close() // listener stopped: subsequent dials get ECONNREFUSED

	var errs atomic.Int32
	errCh := make(chan error, 1)
	c, err := NewClient(Options{
		Endpoint:      deadURL,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
		OnError: func(e error) {
			errs.Add(1)
			select {
			case errCh <- e:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	c.Send(sampleEvent("dead"))

	select {
	case got := <-errCh:
		if got == nil {
			t.Fatal("OnError received nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnError not called within 2s")
	}
	if errs.Load() < 1 {
		t.Errorf("errs counter = %d, want >= 1", errs.Load())
	}
}

// ─── small string/int slice equality (saves a slices import gate) ─────

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
