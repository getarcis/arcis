"""V1.6 / improvements.md §1.3 — Stateful per-IP correlation window.

Today's middleware is stateless: each request is judged on its own.
That misses three categories of attacks:

* **Scanner sweep.** One IP firing payloads from every category in
  quick succession is a scanner, not a real user. A single XSS attempt
  looks the same as a typo; ten attempts across five categories in 60
  seconds doesn't.
* **Credential stuffing.** Same login route, same IP, dozens of
  distinct usernames in 60 seconds. Each individual login is well
  within the rate limit; the *pattern* is the signal.
* **Race-condition probe.** ``POST /transfer`` immediately followed by
  ``GET /balance`` from the same IP, within 200 ms. Either request is
  legitimate on its own; the pair is suspicious.

This module is the building block for all three. It records a small
rolling event log per IP (capped) and exposes detection helpers that
the surrounding middleware can chain into the request-handling path.

# Design

* In-memory by default. ``threading.Lock`` makes it safe under
  concurrent request threads (sync) or async tasks (the lock is only
  held briefly).
* LRU eviction across IPs: keep at most ``max_ips`` (default 10,000)
  recent IPs. Each IP's event deque is bounded at
  ``max_events_per_ip`` (default 200) so a single attacker can't blow
  past the global memory cap.
* No Redis backend in this first cut. The interface is small enough
  that a Redis adapter can land later without changing callers.
* Pattern 4 (fail-open) applies: if something goes wrong inside this
  module, callers fall through to the existing rate-limiter +
  per-vector defenses. Detection is *additive*, not load-bearing.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, Optional, Tuple


@dataclass(frozen=True)
class CorrelationEvent:
    """One recorded request event for a given IP."""

    timestamp: float
    vector: str  # "xss" / "sql" / "path" / "command" / "login" / "request" / etc.
    route: str
    method: str
    distinct_value: Optional[str] = None  # username / email / token bucket


@dataclass(frozen=True)
class CorrelationDetections:
    """Result returned from :meth:`CorrelationWindow.record`.

    Each boolean is independent. Callers typically log all that fire
    and refuse the request when any fires (or pick a subset based on
    the route).
    """

    scanner: bool
    credential_stuffing: bool
    race_window: bool
    distinct_vectors: int
    distinct_values: int
    requests_in_window: int


# Pre-frozen "nothing to see here" result. Re-use to avoid allocating.
_EMPTY_DETECTIONS = CorrelationDetections(
    scanner=False,
    credential_stuffing=False,
    race_window=False,
    distinct_vectors=0,
    distinct_values=0,
    requests_in_window=0,
)


@dataclass
class _IpBucket:
    """Per-IP state. Held inside the OrderedDict under the IP key."""

    events: Deque[CorrelationEvent] = field(default_factory=deque)


class CorrelationWindow:
    """Rolling per-IP correlation window.

    Stores recent events keyed by IP and exposes three detection
    helpers (scanner, credential stuffing, race window). All thresholds
    are tunable.

    The detection helpers are pure functions over the IP's current
    deque snapshot - calling them does not mutate state. ``record`` is
    the only mutating method.
    """

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        max_ips: int = 10_000,
        max_events_per_ip: int = 200,
        scanner_distinct_vectors: int = 3,
        scanner_min_requests: int = 20,
        credential_stuffing_distinct_values: int = 10,
        race_window_ms: int = 200,
        race_pairs: Optional[Iterable[Tuple[str, str]]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_ips < 1:
            raise ValueError("max_ips must be >= 1")
        if max_events_per_ip < 1:
            raise ValueError("max_events_per_ip must be >= 1")

        self._window_seconds = float(window_seconds)
        self._max_ips = int(max_ips)
        self._max_events_per_ip = int(max_events_per_ip)
        self._scanner_distinct_vectors = int(scanner_distinct_vectors)
        self._scanner_min_requests = int(scanner_min_requests)
        self._cs_distinct_values = int(credential_stuffing_distinct_values)
        self._race_window_seconds = float(race_window_ms) / 1000.0
        # Normalize race pairs to a frozenset of sorted tuples so that
        # ("/a","/b") and ("/b","/a") collapse to one entry.
        self._race_pairs = frozenset(
            tuple(sorted(p)) for p in (race_pairs or ())
        )

        self._buckets: "OrderedDict[str, _IpBucket]" = OrderedDict()
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- record

    def record(
        self,
        ip: str,
        vector: str,
        route: str,
        method: str = "GET",
        distinct_value: Optional[str] = None,
        *,
        now: Optional[float] = None,
    ) -> CorrelationDetections:
        """Record one event for `ip` and return detection results.

        Pass ``now`` only in tests; production callers omit it and the
        wall clock is used.
        """
        if not ip:
            return _EMPTY_DETECTIONS

        ts = float(now) if now is not None else time.time()
        event = CorrelationEvent(
            timestamp=ts,
            vector=vector,
            route=route,
            method=method,
            distinct_value=distinct_value,
        )

        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                bucket = _IpBucket()
                self._buckets[ip] = bucket
                # LRU evict if we just exceeded the IP cap.
                while len(self._buckets) > self._max_ips:
                    self._buckets.popitem(last=False)
            else:
                # Touch on access so LRU order stays accurate.
                self._buckets.move_to_end(ip)

            bucket.events.append(event)
            self._evict_stale(bucket, ts)
            return self._evaluate(bucket, route, ts)

    # ------------------------------------------------- detection (read-only)

    def detect_scanner(self, ip: str, *, now: Optional[float] = None) -> bool:
        """Return True if this IP looks like an active scanner."""
        ts = float(now) if now is not None else time.time()
        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                return False
            self._evict_stale(bucket, ts)
            return self._is_scanner(bucket)

    def detect_credential_stuffing(
        self, ip: str, route: str, *, now: Optional[float] = None
    ) -> bool:
        """Return True if `ip` is firing distinct credentials at `route`."""
        ts = float(now) if now is not None else time.time()
        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                return False
            self._evict_stale(bucket, ts)
            return self._is_credential_stuffing(bucket, route)

    def detect_race_window(
        self,
        ip: str,
        route_pair: Tuple[str, str],
        *,
        now: Optional[float] = None,
    ) -> bool:
        """Return True if `ip` hit the two routes within the race window."""
        ts = float(now) if now is not None else time.time()
        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                return False
            self._evict_stale(bucket, ts)
            return self._is_race(bucket, tuple(sorted(route_pair)))

    # ------------------------------------------------- lifecycle / inspection

    def reset(self, ip: Optional[str] = None) -> None:
        """Drop state for one IP, or all IPs if `ip` is None."""
        with self._lock:
            if ip is None:
                self._buckets.clear()
            else:
                self._buckets.pop(ip, None)

    def stats(self) -> Dict[str, int]:
        """Snapshot for dashboards: tracked IPs + total recent events."""
        with self._lock:
            ips = len(self._buckets)
            events = sum(len(b.events) for b in self._buckets.values())
        return {"tracked_ips": ips, "events_in_window": events}

    # ---------------------------------------------------- internal mechanics

    def _evict_stale(self, bucket: _IpBucket, now: float) -> None:
        """Drop events older than the window and cap deque length."""
        cutoff = now - self._window_seconds
        events = bucket.events
        while events and events[0].timestamp < cutoff:
            events.popleft()
        while len(events) > self._max_events_per_ip:
            events.popleft()

    def _evaluate(
        self, bucket: _IpBucket, route: str, now: float
    ) -> CorrelationDetections:
        distinct_vectors = {e.vector for e in bucket.events}
        distinct_values = {
            e.distinct_value
            for e in bucket.events
            if e.route == route and e.distinct_value is not None
        }
        return CorrelationDetections(
            scanner=self._is_scanner(bucket),
            credential_stuffing=self._is_credential_stuffing(bucket, route),
            race_window=self._is_race_any(bucket),
            distinct_vectors=len(distinct_vectors),
            distinct_values=len(distinct_values),
            requests_in_window=len(bucket.events),
        )

    def _is_scanner(self, bucket: _IpBucket) -> bool:
        if len(bucket.events) < self._scanner_min_requests:
            return False
        vectors = {e.vector for e in bucket.events}
        return len(vectors) >= self._scanner_distinct_vectors

    def _is_credential_stuffing(self, bucket: _IpBucket, route: str) -> bool:
        values = {
            e.distinct_value
            for e in bucket.events
            if e.route == route and e.distinct_value is not None
        }
        return len(values) >= self._cs_distinct_values

    def _is_race(self, bucket: _IpBucket, route_pair_sorted: Tuple[str, str]) -> bool:
        if route_pair_sorted not in self._race_pairs:
            # Caller asked about a pair we weren't told to track.
            # Still allow ad-hoc checks if both routes appear in the
            # bucket within the race window.
            return self._race_pair_in_bucket(bucket, route_pair_sorted)
        return self._race_pair_in_bucket(bucket, route_pair_sorted)

    def _race_pair_in_bucket(
        self, bucket: _IpBucket, route_pair_sorted: Tuple[str, str]
    ) -> bool:
        a, b = route_pair_sorted
        events_by_route: Dict[str, list] = {a: [], b: []}
        for e in bucket.events:
            if e.route in events_by_route:
                events_by_route[e.route].append(e.timestamp)
        if not events_by_route[a] or not events_by_route[b]:
            return False
        # Both lists are append-only ordered, so two-pointer scan.
        ai = bi = 0
        a_ts = events_by_route[a]
        b_ts = events_by_route[b]
        while ai < len(a_ts) and bi < len(b_ts):
            diff = a_ts[ai] - b_ts[bi]
            if abs(diff) <= self._race_window_seconds:
                return True
            if diff < 0:
                ai += 1
            else:
                bi += 1
        return False

    def _is_race_any(self, bucket: _IpBucket) -> bool:
        for pair in self._race_pairs:
            if self._race_pair_in_bucket(bucket, pair):
                return True
        return False


__all__ = [
    "CorrelationEvent",
    "CorrelationDetections",
    "CorrelationWindow",
]
