package middleware

import (
	"container/list"
	"sort"
	"sync"
	"time"
)

// V1.6 / improvements.md §1.3 — Stateful per-IP correlation window.
//
// Mirrors the Python and Node implementations. Today's middleware is
// stateless; each request is judged on its own. That misses three
// categories of attacks:
//
//   - Scanner sweep. One IP firing payloads from every category in
//     quick succession is a scanner, not a real user.
//
//   - Credential stuffing. Same login route, same IP, dozens of
//     distinct usernames in 60 seconds. Each individual login is well
//     within the rate limit; the pattern is the signal.
//
//   - Race-condition probe. POST /transfer immediately followed by
//     GET /balance from the same IP, within 200ms.
//
// Design:
//
//   - In-memory by default. sync.Mutex serializes record/detect.
//   - LRU eviction across IPs: keep at most MaxIps (default 10,000)
//     recent IPs. Each IP's event deque is bounded at
//     MaxEventsPerIp (default 200) so a single attacker can't blow
//     past the global memory cap.
//   - Pattern 4 (fail-open) applies: detection is additive, not
//     load-bearing. A panicking call falls through to existing
//     defenses.

// CorrelationEvent is one recorded request event for a given IP.
type CorrelationEvent struct {
	Timestamp     time.Time
	Vector        string // "xss" / "sql" / "login" / "request" / etc.
	Route         string
	Method        string
	DistinctValue string // username / email / token (optional, empty when not credential-stuffing-related)
}

// CorrelationDetections is the result returned from CorrelationWindow.Record.
// Each boolean is independent. Callers typically log all that fire and
// refuse the request when any fires (or pick a subset based on the route).
type CorrelationDetections struct {
	Scanner            bool
	CredentialStuffing bool
	RaceWindow         bool
	DistinctVectors    int
	DistinctValues     int
	RequestsInWindow   int
}

// CorrelationWindowOptions configures CorrelationWindow.
type CorrelationWindowOptions struct {
	WindowSeconds                    float64
	MaxIps                           int
	MaxEventsPerIp                   int
	ScannerDistinctVectors           int
	ScannerMinRequests               int
	CredentialStuffingDistinctValues int
	RaceWindowMs                     int
	// RacePairs is the set of route pairs to watch for race-windows.
	// Each pair is unordered; CorrelationWindow normalizes by sorting.
	RacePairs [][2]string
}

// NewCorrelationWindowOptions returns the documented defaults. Use this
// when constructing a CorrelationWindow because Go's zero-value
// semantics on the int fields would otherwise disable every threshold.
func NewCorrelationWindowOptions() CorrelationWindowOptions {
	return CorrelationWindowOptions{
		WindowSeconds:                    60.0,
		MaxIps:                           10000,
		MaxEventsPerIp:                   200,
		ScannerDistinctVectors:           3,
		ScannerMinRequests:               20,
		CredentialStuffingDistinctValues: 10,
		RaceWindowMs:                     200,
	}
}

// CorrelationWindow tracks a rolling per-IP event window and exposes
// three detection helpers (scanner, credential stuffing, race window).
//
// All thresholds are tunable via CorrelationWindowOptions. Record is
// the only mutating method; the Detect* helpers are read-only.
type CorrelationWindow struct {
	windowSeconds      time.Duration
	maxIps             int
	maxEventsPerIp     int
	scannerDistinct    int
	scannerMinRequests int
	credStuffDistinct  int
	raceWindow         time.Duration
	racePairs          map[[2]string]struct{}

	mu      sync.Mutex
	order   *list.List               // LRU order over IPs (front = most-recent)
	buckets map[string]*list.Element // ip -> *list.Element whose Value is *ipBucket
}

type ipBucket struct {
	ip     string
	events []CorrelationEvent
}

// NewCorrelationWindow returns a configured CorrelationWindow. Pass
// NewCorrelationWindowOptions() as a starting point and override what
// you need.
func NewCorrelationWindow(opts CorrelationWindowOptions) *CorrelationWindow {
	d := NewCorrelationWindowOptions()
	if opts.WindowSeconds <= 0 {
		opts.WindowSeconds = d.WindowSeconds
	}
	if opts.MaxIps < 1 {
		opts.MaxIps = d.MaxIps
	}
	if opts.MaxEventsPerIp < 1 {
		opts.MaxEventsPerIp = d.MaxEventsPerIp
	}
	if opts.ScannerDistinctVectors < 1 {
		opts.ScannerDistinctVectors = d.ScannerDistinctVectors
	}
	if opts.ScannerMinRequests < 1 {
		opts.ScannerMinRequests = d.ScannerMinRequests
	}
	if opts.CredentialStuffingDistinctValues < 1 {
		opts.CredentialStuffingDistinctValues = d.CredentialStuffingDistinctValues
	}
	if opts.RaceWindowMs < 1 {
		opts.RaceWindowMs = d.RaceWindowMs
	}
	racePairs := map[[2]string]struct{}{}
	for _, p := range opts.RacePairs {
		racePairs[normalizeRacePair(p[0], p[1])] = struct{}{}
	}
	return &CorrelationWindow{
		windowSeconds:      time.Duration(opts.WindowSeconds * float64(time.Second)),
		maxIps:             opts.MaxIps,
		maxEventsPerIp:     opts.MaxEventsPerIp,
		scannerDistinct:    opts.ScannerDistinctVectors,
		scannerMinRequests: opts.ScannerMinRequests,
		credStuffDistinct:  opts.CredentialStuffingDistinctValues,
		raceWindow:         time.Duration(opts.RaceWindowMs) * time.Millisecond,
		racePairs:          racePairs,
		order:              list.New(),
		buckets:            map[string]*list.Element{},
	}
}

func normalizeRacePair(a, b string) [2]string {
	pair := []string{a, b}
	sort.Strings(pair)
	return [2]string{pair[0], pair[1]}
}

// Record adds an event for ip and returns the current detection state.
// distinctValue may be empty when the event is not credential-related.
// Pass a non-zero `now` only in tests.
func (cw *CorrelationWindow) Record(
	ip, vector, route, method, distinctValue string,
	now time.Time,
) CorrelationDetections {
	if ip == "" {
		return CorrelationDetections{}
	}
	if now.IsZero() {
		now = time.Now()
	}
	event := CorrelationEvent{
		Timestamp:     now,
		Vector:        vector,
		Route:         route,
		Method:        method,
		DistinctValue: distinctValue,
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	bucket := cw.touchOrCreate(ip)
	bucket.events = append(bucket.events, event)
	cw.evictStale(bucket, now)
	return cw.evaluate(bucket, route, now)
}

// DetectScanner reports whether ip currently looks like an active scanner.
func (cw *CorrelationWindow) DetectScanner(ip string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	cw.mu.Lock()
	defer cw.mu.Unlock()
	elem, ok := cw.buckets[ip]
	if !ok {
		return false
	}
	bucket := elem.Value.(*ipBucket)
	cw.evictStale(bucket, now)
	return cw.isScanner(bucket)
}

// DetectCredentialStuffing reports whether ip is firing distinct
// credentials at route.
func (cw *CorrelationWindow) DetectCredentialStuffing(ip, route string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	cw.mu.Lock()
	defer cw.mu.Unlock()
	elem, ok := cw.buckets[ip]
	if !ok {
		return false
	}
	bucket := elem.Value.(*ipBucket)
	cw.evictStale(bucket, now)
	return cw.isCredentialStuffing(bucket, route)
}

// DetectRaceWindow reports whether ip hit the two routes within the
// race window. routePair is unordered.
func (cw *CorrelationWindow) DetectRaceWindow(ip string, a, b string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	cw.mu.Lock()
	defer cw.mu.Unlock()
	elem, ok := cw.buckets[ip]
	if !ok {
		return false
	}
	bucket := elem.Value.(*ipBucket)
	cw.evictStale(bucket, now)
	pair := normalizeRacePair(a, b)
	return cw.racePairInBucket(bucket, pair)
}

// Reset drops state for one IP, or for all IPs when ip is "".
func (cw *CorrelationWindow) Reset(ip string) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if ip == "" {
		cw.order.Init()
		cw.buckets = map[string]*list.Element{}
		return
	}
	if elem, ok := cw.buckets[ip]; ok {
		cw.order.Remove(elem)
		delete(cw.buckets, ip)
	}
}

// Stats returns a snapshot for dashboards: tracked IPs + total events.
func (cw *CorrelationWindow) Stats() (trackedIps int, eventsInWindow int) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	trackedIps = cw.order.Len()
	for e := cw.order.Front(); e != nil; e = e.Next() {
		eventsInWindow += len(e.Value.(*ipBucket).events)
	}
	return
}

// ---------------------------------------------------- internals

func (cw *CorrelationWindow) touchOrCreate(ip string) *ipBucket {
	if elem, ok := cw.buckets[ip]; ok {
		cw.order.MoveToFront(elem)
		return elem.Value.(*ipBucket)
	}
	bucket := &ipBucket{ip: ip}
	elem := cw.order.PushFront(bucket)
	cw.buckets[ip] = elem
	// LRU evict.
	for cw.order.Len() > cw.maxIps {
		oldest := cw.order.Back()
		if oldest == nil {
			break
		}
		cw.order.Remove(oldest)
		delete(cw.buckets, oldest.Value.(*ipBucket).ip)
	}
	return bucket
}

func (cw *CorrelationWindow) evictStale(bucket *ipBucket, now time.Time) {
	cutoff := now.Add(-cw.windowSeconds)
	// Drop leading entries older than the window.
	i := 0
	for i < len(bucket.events) && bucket.events[i].Timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		bucket.events = append(bucket.events[:0], bucket.events[i:]...)
	}
	// Cap deque length (drop oldest extras).
	if extra := len(bucket.events) - cw.maxEventsPerIp; extra > 0 {
		bucket.events = append(bucket.events[:0], bucket.events[extra:]...)
	}
}

func (cw *CorrelationWindow) evaluate(bucket *ipBucket, route string, now time.Time) CorrelationDetections {
	distinctVectors := map[string]struct{}{}
	distinctValues := map[string]struct{}{}
	for _, e := range bucket.events {
		distinctVectors[e.Vector] = struct{}{}
		if e.Route == route && e.DistinctValue != "" {
			distinctValues[e.DistinctValue] = struct{}{}
		}
	}
	return CorrelationDetections{
		Scanner:            cw.isScanner(bucket),
		CredentialStuffing: cw.isCredentialStuffing(bucket, route),
		RaceWindow:         cw.isRaceAny(bucket),
		DistinctVectors:    len(distinctVectors),
		DistinctValues:     len(distinctValues),
		RequestsInWindow:   len(bucket.events),
	}
}

func (cw *CorrelationWindow) isScanner(bucket *ipBucket) bool {
	if len(bucket.events) < cw.scannerMinRequests {
		return false
	}
	vectors := map[string]struct{}{}
	for _, e := range bucket.events {
		vectors[e.Vector] = struct{}{}
	}
	return len(vectors) >= cw.scannerDistinct
}

func (cw *CorrelationWindow) isCredentialStuffing(bucket *ipBucket, route string) bool {
	values := map[string]struct{}{}
	for _, e := range bucket.events {
		if e.Route == route && e.DistinctValue != "" {
			values[e.DistinctValue] = struct{}{}
		}
	}
	return len(values) >= cw.credStuffDistinct
}

func (cw *CorrelationWindow) isRaceAny(bucket *ipBucket) bool {
	for pair := range cw.racePairs {
		if cw.racePairInBucket(bucket, pair) {
			return true
		}
	}
	return false
}

// racePairInBucket reports whether any timestamp from route a is within
// the race window of any timestamp from route b. The two timestamp
// slices are sorted (append-only) so a two-pointer scan is sufficient.
func (cw *CorrelationWindow) racePairInBucket(bucket *ipBucket, pair [2]string) bool {
	a, b := pair[0], pair[1]
	var aTs, bTs []time.Time
	for _, e := range bucket.events {
		switch e.Route {
		case a:
			aTs = append(aTs, e.Timestamp)
		case b:
			bTs = append(bTs, e.Timestamp)
		}
	}
	if len(aTs) == 0 || len(bTs) == 0 {
		return false
	}
	ai, bi := 0, 0
	for ai < len(aTs) && bi < len(bTs) {
		diff := aTs[ai].Sub(bTs[bi])
		abs := diff
		if abs < 0 {
			abs = -abs
		}
		if abs <= cw.raceWindow {
			return true
		}
		if diff < 0 {
			ai++
		} else {
			bi++
		}
	}
	return false
}
