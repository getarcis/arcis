"""
Cloud IP-reputation client with a local LRU+TTL cache.

Python parity with packages/arcis-node/src/intelligence/client.ts.

Design rules:
  1. ``check()`` is synchronous and never blocks the request path. On a cache
     miss it returns ``found=False`` for THIS request and schedules a background
     refresh (on a small thread pool, so it is loop-agnostic and works from
     sync and async apps alike). Subsequent requests from the same IP read the
     cached verdict.
  2. Fail-open: a network error, timeout, or non-200 resolves to ``found=False``
     and never raises into the request path.
  3. Private / loopback / unresolved IPs are never looked up.
  4. A clean ("not found") result IS cached so clean IPs are not re-queried
     every request; transport errors are NOT cached so they retry.

HTTP transport prefers ``httpx`` (when installed) and falls back to stdlib
``urllib.request`` so the feature works on a zero-dependency install.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, Optional

from ..utils.ip import is_private_ip
from .types import IntelligenceOptions, IpReputation

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


_DEFAULT_CACHE_MAX = 1000
_DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000
_DEFAULT_TIMEOUT_MS = 2000
_MIN_TIMEOUT_MS = 100


def _request_json(url: str, headers: Dict[str, str], timeout_s: float) -> Dict[str, object]:
    """GET a JSON document. Raises on non-2xx or transport error.

    Isolated at module scope so tests can monkeypatch it without a network.
    """
    if httpx is not None:
        resp = httpx.get(url, headers=headers, timeout=timeout_s)
        if resp.status_code >= 300:
            raise RuntimeError(f"ip-reputation lookup returned HTTP {resp.status_code}")
        return resp.json()
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"ip-reputation lookup returned HTTP {resp.status}")
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"ip-reputation lookup returned HTTP {e.code}") from e


def _as_str_list(value: object) -> Optional[list]:
    if not isinstance(value, list):
        return None
    out = [s for s in value if isinstance(s, str)]
    return out or None


def _normalize(ip: str, body: Dict[str, object]) -> IpReputation:
    """Map the dashboard wire shape (snake_case) to an IpReputation."""
    if body.get("found") is not True:
        return IpReputation(ip=ip, found=False)
    rep = IpReputation(ip=ip, found=True)
    sev = body.get("severity")
    if isinstance(sev, (int, float)):
        rep.severity = int(sev)
    rep.categories = _as_str_list(body.get("categories"))
    rep.sources = _as_str_list(body.get("sources"))
    first_seen = body.get("first_seen")
    if isinstance(first_seen, str):
        rep.first_seen = first_seen
    last_seen = body.get("last_seen")
    if isinstance(last_seen, str):
        rep.last_seen = last_seen
    matched = body.get("matched")
    if isinstance(matched, str):
        rep.matched = matched
    return rep


def _is_bot_entry(e: object) -> bool:
    """A well-formed bot-corpus entry: id/category/name strings + string lists."""
    if not isinstance(e, dict):
        return False
    if not all(isinstance(e.get(k), str) for k in ("id", "category", "name")):
        return False
    pats = e.get("patterns")
    forb = e.get("forbidden")
    return (
        isinstance(pats, list)
        and all(isinstance(p, str) for p in pats)
        and isinstance(forb, list)
        and all(isinstance(p, str) for p in forb)
    )


def reputation_severity_tier(severity: Optional[int]) -> str:
    """Map a numeric reputation severity (1-10) to a coarse telemetry tier."""
    s = severity or 0
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    return "low"


class _LruTtlCache:
    """Thread-safe, insertion-ordered LRU with per-entry TTL."""

    def __init__(self, max_size: int, ttl_ms: int) -> None:
        self._max = max_size
        self._ttl_s = ttl_ms / 1000.0
        self._map: "OrderedDict[str, tuple[IpReputation, float]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[IpReputation]:
        with self._lock:
            entry = self._map.get(key)
            if entry is None:
                return None
            value, expires = entry
            if time.monotonic() > expires:
                del self._map[key]
                return None
            self._map.move_to_end(key)
            return value

    def set(self, key: str, value: IpReputation) -> None:
        with self._lock:
            if key in self._map:
                del self._map[key]
            self._map[key] = (value, time.monotonic() + self._ttl_s)
            while len(self._map) > self._max:
                self._map.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._map.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._map)


class IntelligenceClient:
    """Cloud IP-reputation client. See module docstring for the design rules."""

    def __init__(self, options: IntelligenceOptions) -> None:
        if not options.endpoint or not isinstance(options.endpoint, str):
            raise TypeError("IntelligenceClient: `endpoint` is required")
        self._base = options.endpoint.rstrip("/")
        self._headers: Dict[str, str] = {"accept": "application/json"}
        if options.api_key:
            self._headers["authorization"] = f"Bearer {options.api_key}"
        if options.workspace_id:
            self._headers["x-workspace-id"] = options.workspace_id
        self._timeout_s = max(_MIN_TIMEOUT_MS, options.timeout_ms or _DEFAULT_TIMEOUT_MS) / 1000.0
        self._ip_rep_enabled = "ip-rep" in (options.cloud_decisions or [])
        self._on_error: Callable[[Exception], None] = options.on_error or (lambda _e: None)
        self._cache = _LruTtlCache(
            max(1, options.cache_max or _DEFAULT_CACHE_MAX),
            max(1000, options.cache_ttl_ms or _DEFAULT_CACHE_TTL_MS),
        )
        self._in_flight: set[str] = set()
        self._in_flight_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="arcis-intel")
        self._closed = False

    def check(self, ip: str) -> IpReputation:
        """Synchronous, cache-first read. Never blocks: a cache miss returns
        ``found=False`` and schedules a background refresh."""
        if not self._ip_rep_enabled or self._closed:
            return IpReputation(ip=ip, found=False)
        if not ip or ip == "unknown" or is_private_ip(ip):
            return IpReputation(ip=ip, found=False)
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        self._schedule_refresh(ip)
        return IpReputation(ip=ip, found=False)

    def lookup(self, ip: str) -> IpReputation:
        """Blocking lookup. Fail-open: any transport error returns found=False.

        Used by direct callers and tests; the request path uses ``check()``.
        """
        if not ip or ip == "unknown" or is_private_ip(ip):
            return IpReputation(ip=ip, found=False)
        try:
            return self._fetch_reputation(ip)
        except Exception as e:  # noqa: BLE001 - fail-open by design
            self._safe_notify(e)
            return IpReputation(ip=ip, found=False)

    def fetch_bot_corpus(self) -> list:
        """Fetch the full bot corpus from the intelligence endpoint. Fail-open:
        any transport/parse error returns an empty list (the caller keeps the
        bundled corpus). Returns only well-formed entries."""
        url = f"{self._base}/v1/intel/bot-corpus/snapshot"
        try:
            body = _request_json(url, self._headers, self._timeout_s)
        except Exception as e:  # noqa: BLE001 - fail-open
            self._safe_notify(e)
            return []
        entries = body.get("entries") if isinstance(body, dict) else None
        if not isinstance(entries, list):
            return []
        return [e for e in entries if _is_bot_entry(e)]

    @property
    def cache_size(self) -> int:
        return self._cache.size

    def close(self) -> None:
        """Stop scheduling refreshes and drop the cache. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._cache.clear()
        self._executor.shutdown(wait=False)

    # internals ----

    def _schedule_refresh(self, ip: str) -> None:
        with self._in_flight_lock:
            if ip in self._in_flight or self._closed:
                return
            self._in_flight.add(ip)
        try:
            self._executor.submit(self._refresh_worker, ip)
        except RuntimeError:
            # Executor already shut down (closed concurrently). Drop quietly.
            with self._in_flight_lock:
                self._in_flight.discard(ip)

    def _refresh_worker(self, ip: str) -> None:
        try:
            rep = self._fetch_reputation(ip)
            if not self._closed:
                # Cache real results (incl. a clean not-found); errors raise
                # and are handled below, so they are not cached and will retry.
                self._cache.set(ip, rep)
        except Exception as e:  # noqa: BLE001
            self._safe_notify(e)
        finally:
            with self._in_flight_lock:
                self._in_flight.discard(ip)

    def _fetch_reputation(self, ip: str) -> IpReputation:
        url = f"{self._base}/v1/intel/ip-reputation/{urllib.parse.quote(ip, safe='')}"
        body = _request_json(url, self._headers, self._timeout_s)
        return _normalize(ip, body)

    def _safe_notify(self, err: Exception) -> None:
        try:
            self._on_error(err)
        except Exception:
            pass


__all__ = ["IntelligenceClient", "reputation_severity_tier"]
