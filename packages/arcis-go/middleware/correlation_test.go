package middleware

import (
	"strconv"
	"testing"
	"time"
)

func TestCorrelationWindow_EmptyIPReturnsZero(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	d := cw.Record("", "xss", "/a", "GET", "", time.Time{})
	if d.RequestsInWindow != 0 || d.Scanner || d.CredentialStuffing || d.RaceWindow {
		t.Errorf("empty IP should produce zero-value detections, got %+v", d)
	}
}

func TestCorrelationWindow_BasicRecord(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	d := cw.Record("1.2.3.4", "xss", "/a", "GET", "", time.Time{})
	if d.RequestsInWindow != 1 {
		t.Errorf("expected requestsInWindow=1, got %d", d.RequestsInWindow)
	}
	if d.DistinctVectors != 1 {
		t.Errorf("expected distinctVectors=1, got %d", d.DistinctVectors)
	}
}

// ─── Scanner detection ────────────────────────────────────────────────────

func TestCorrelationWindow_Scanner_TripleVector_AboveMinRequests(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		v := []string{"xss", "sql", "path"}[i%3]
		cw.Record("9.9.9.9", v, "/api", "GET", "", t0.Add(time.Duration(i)*time.Second))
	}
	if !cw.DetectScanner("9.9.9.9", t0.Add(21*time.Second)) {
		t.Fatal("expected scanner=true after 20 requests across 3 vectors")
	}
}

func TestCorrelationWindow_Scanner_BelowMinRequests_NotFlagged(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 3 vectors but only 5 events — below default scanner_min_requests=20.
	for i := 0; i < 5; i++ {
		v := []string{"xss", "sql", "path"}[i%3]
		cw.Record("9.9.9.9", v, "/api", "GET", "", t0.Add(time.Duration(i)*time.Second))
	}
	if cw.DetectScanner("9.9.9.9", t0.Add(6*time.Second)) {
		t.Fatal("5 requests should not trigger scanner (below min_requests=20)")
	}
}

func TestCorrelationWindow_Scanner_SingleVector_NotFlagged(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		cw.Record("9.9.9.9", "request", "/api", "GET", "", t0.Add(time.Duration(i)*time.Second))
	}
	if cw.DetectScanner("9.9.9.9", t0.Add(26*time.Second)) {
		t.Fatal("25 requests but only 1 vector should not trigger scanner")
	}
}

// ─── Credential stuffing ──────────────────────────────────────────────────

func TestCorrelationWindow_CredentialStuffing_DistinctUsers(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		cw.Record("9.9.9.9", "login", "/login", "POST", "user"+strconv.Itoa(i), t0.Add(time.Duration(i)*time.Second))
	}
	if !cw.DetectCredentialStuffing("9.9.9.9", "/login", t0.Add(13*time.Second)) {
		t.Fatal("12 distinct usernames in 12s should trigger credential stuffing")
	}
}

func TestCorrelationWindow_CredentialStuffing_SameUserNotFlagged(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		cw.Record("9.9.9.9", "login", "/login", "POST", "alice", t0.Add(time.Duration(i)*time.Second))
	}
	if cw.DetectCredentialStuffing("9.9.9.9", "/login", t0.Add(13*time.Second)) {
		t.Fatal("12 attempts on one username should not trigger credential stuffing")
	}
}

// ─── Race window ──────────────────────────────────────────────────────────

func TestCorrelationWindow_RaceWindow_Within200ms(t *testing.T) {
	opts := NewCorrelationWindowOptions()
	opts.RacePairs = [][2]string{{"/transfer", "/balance"}}
	cw := NewCorrelationWindow(opts)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cw.Record("9.9.9.9", "request", "/transfer", "POST", "", t0)
	cw.Record("9.9.9.9", "request", "/balance", "GET", "", t0.Add(100*time.Millisecond))
	if !cw.DetectRaceWindow("9.9.9.9", "/transfer", "/balance", t0.Add(200*time.Millisecond)) {
		t.Fatal("two requests 100ms apart should trigger race window")
	}
}

func TestCorrelationWindow_RaceWindow_Outside200msNotFlagged(t *testing.T) {
	opts := NewCorrelationWindowOptions()
	opts.RacePairs = [][2]string{{"/transfer", "/balance"}}
	cw := NewCorrelationWindow(opts)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cw.Record("9.9.9.9", "request", "/transfer", "POST", "", t0)
	cw.Record("9.9.9.9", "request", "/balance", "GET", "", t0.Add(500*time.Millisecond))
	if cw.DetectRaceWindow("9.9.9.9", "/transfer", "/balance", t0.Add(600*time.Millisecond)) {
		t.Fatal("two requests 500ms apart should NOT trigger race window (default cap 200ms)")
	}
}

func TestCorrelationWindow_RaceWindow_UnorderedPair(t *testing.T) {
	opts := NewCorrelationWindowOptions()
	opts.RacePairs = [][2]string{{"/balance", "/transfer"}} // reverse order in pair
	cw := NewCorrelationWindow(opts)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cw.Record("9.9.9.9", "request", "/transfer", "POST", "", t0)
	cw.Record("9.9.9.9", "request", "/balance", "GET", "", t0.Add(50*time.Millisecond))
	// Caller passes pair in third order — should still match.
	if !cw.DetectRaceWindow("9.9.9.9", "/transfer", "/balance", t0.Add(100*time.Millisecond)) {
		t.Fatal("race pair lookups should be order-insensitive")
	}
}

// ─── Eviction ─────────────────────────────────────────────────────────────

func TestCorrelationWindow_StaleEventsEvicted(t *testing.T) {
	opts := NewCorrelationWindowOptions()
	opts.WindowSeconds = 10
	cw := NewCorrelationWindow(opts)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cw.Record("9.9.9.9", "xss", "/a", "GET", "", t0)
	cw.Record("9.9.9.9", "sql", "/a", "GET", "", t0.Add(5*time.Second))
	// 30s later, both events should evict.
	d := cw.Record("9.9.9.9", "path", "/a", "GET", "", t0.Add(30*time.Second))
	if d.RequestsInWindow != 1 {
		t.Errorf("expected stale events to evict; got requestsInWindow=%d", d.RequestsInWindow)
	}
}

func TestCorrelationWindow_PerIpCapEnforced(t *testing.T) {
	opts := NewCorrelationWindowOptions()
	opts.MaxEventsPerIp = 5
	cw := NewCorrelationWindow(opts)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		cw.Record("9.9.9.9", "request", "/a", "GET", "", t0.Add(time.Duration(i)*time.Second))
	}
	tracked, events := cw.Stats()
	if tracked != 1 || events != 5 {
		t.Errorf("expected (1 ip, 5 events), got (%d, %d)", tracked, events)
	}
}

func TestCorrelationWindow_MaxIpsLRUEvicts(t *testing.T) {
	opts := NewCorrelationWindowOptions()
	opts.MaxIps = 3
	cw := NewCorrelationWindow(opts)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cw.Record("1.1.1.1", "x", "/", "GET", "", t0)
	cw.Record("2.2.2.2", "x", "/", "GET", "", t0.Add(1*time.Second))
	cw.Record("3.3.3.3", "x", "/", "GET", "", t0.Add(2*time.Second))
	cw.Record("4.4.4.4", "x", "/", "GET", "", t0.Add(3*time.Second))
	// 1.1.1.1 should be evicted (oldest).
	tracked, _ := cw.Stats()
	if tracked != 3 {
		t.Errorf("expected 3 tracked IPs after LRU eviction, got %d", tracked)
	}
	if cw.DetectScanner("1.1.1.1", t0.Add(4*time.Second)) {
		// detect should return false because bucket is gone
	}
}

// ─── Reset + Stats ────────────────────────────────────────────────────────

func TestCorrelationWindow_Reset_Single(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	cw.Record("9.9.9.9", "x", "/", "GET", "", time.Time{})
	cw.Record("8.8.8.8", "x", "/", "GET", "", time.Time{})
	cw.Reset("9.9.9.9")
	tracked, _ := cw.Stats()
	if tracked != 1 {
		t.Errorf("expected 1 tracked IP after Reset of one, got %d", tracked)
	}
}

func TestCorrelationWindow_Reset_All(t *testing.T) {
	cw := NewCorrelationWindow(NewCorrelationWindowOptions())
	cw.Record("9.9.9.9", "x", "/", "GET", "", time.Time{})
	cw.Record("8.8.8.8", "x", "/", "GET", "", time.Time{})
	cw.Reset("")
	tracked, events := cw.Stats()
	if tracked != 0 || events != 0 {
		t.Errorf("expected (0,0) after full reset, got (%d, %d)", tracked, events)
	}
}
