"""
Telemetry client — Python parity with packages/arcis-node/src/telemetry/client.ts.

Two clients ship from this module:

* ``TelemetryClient`` — synchronous, daemon-thread + ``queue.Queue``. Use from
  Flask / Django / any sync WSGI app.
* ``AsyncTelemetryClient`` — asyncio-native, ``asyncio.Queue`` + background
  task. Use from FastAPI / Starlette / any async ASGI app.

Both share the spec/API_SPEC.md §9 contract:

1. ``record(event)`` is non-blocking and never raises.
2. Flush triggers: queue size >= ``batch_size`` OR ``flush_interval_ms`` elapsed.
3. Network failures are fail-open: ``on_error`` is invoked (if set) and the
   batch is dropped. No retry, no disk persistence.
4. ``close()`` attempts one final flush; idempotent.

HTTP transport prefers ``httpx`` (when installed via ``arcis[telemetry]``) and
falls back to stdlib ``urllib.request`` so the feature stays usable on a
zero-dependency install.
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import urllib.error
import urllib.request
from typing import Callable, Optional

from .types import TelemetryEvent, TelemetryOptions

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


_LOG = logging.getLogger("arcis.telemetry")

_DEFAULT_BATCH_SIZE = 50
_MAX_BATCH_SIZE = 500
_DEFAULT_FLUSH_INTERVAL_MS = 5000
_MIN_FLUSH_INTERVAL_MS = 500
_FLUSH_TIMEOUT_S = 10.0


class TelemetryHttpError(Exception):
    """Raised internally when the dashboard returns a non-2xx response.

    Always handled before reaching user code: surfaced through ``on_error``,
    never propagated out of ``record()`` or ``flush()``.
    """

    def __init__(self, status: int, response_body: str = "") -> None:
        super().__init__(f"Telemetry ingest returned HTTP {status}")
        self.status = status
        self.response_body = response_body


def _clamp(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _build_headers(opts: TelemetryOptions) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if opts.api_key:
        headers["authorization"] = f"Bearer {opts.api_key}"
    if opts.workspace_id:
        headers["x-workspace-id"] = opts.workspace_id
    return headers


def _serialize_batch(events: list[TelemetryEvent]) -> bytes:
    payload = {"events": [e.to_wire() for e in events]}
    return json.dumps(payload).encode("utf-8")


def _post_sync_urllib(
    endpoint: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> None:
    """POST batch using stdlib only. Raises TelemetryHttpError on non-2xx."""
    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status >= 300:
                text = resp.read().decode("utf-8", "replace")[:500]
                raise TelemetryHttpError(resp.status, text)
    except urllib.error.HTTPError as e:
        text = ""
        try:
            text = e.read().decode("utf-8", "replace")[:500]
        except Exception:
            pass
        raise TelemetryHttpError(e.code, text) from e


def _post_sync_httpx(
    endpoint: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> None:
    """POST batch using httpx. Raises TelemetryHttpError on non-2xx."""
    assert httpx is not None
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(endpoint, headers=headers, content=body)
        if resp.status_code >= 300:
            raise TelemetryHttpError(resp.status_code, resp.text[:500])


async def _post_async_httpx(
    endpoint: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> None:
    """POST batch async using httpx. Raises TelemetryHttpError on non-2xx."""
    assert httpx is not None
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(endpoint, headers=headers, content=body)
        if resp.status_code >= 300:
            raise TelemetryHttpError(resp.status_code, resp.text[:500])


# ─── Sync client ───────────────────────────────────────────────────────────


class TelemetryClient:
    """In-memory batching client for sync apps (Flask, Django, plain WSGI).

    Internals:
      * a thread-safe ``queue.Queue``
      * a daemon ``threading.Thread`` that wakes on the flush interval
      * ``record()`` returns immediately; the worker thread does I/O
      * fail-open on every error path
    """

    def __init__(self, options: TelemetryOptions) -> None:
        if not options.endpoint or not isinstance(options.endpoint, str):
            raise TypeError("TelemetryClient: `endpoint` is required")

        self._endpoint = options.endpoint
        self._headers = _build_headers(options)
        self._batch_size = _clamp(
            options.batch_size if options.batch_size is not None else _DEFAULT_BATCH_SIZE,
            1,
            _MAX_BATCH_SIZE,
        )
        self._flush_interval_s = (
            max(options.flush_interval_ms or _DEFAULT_FLUSH_INTERVAL_MS, _MIN_FLUSH_INTERVAL_MS)
            / 1000.0
        )
        # Cap the queue to bound memory under sustained dashboard outage.
        # Bounded queue raises queue.Full on put_nowait; record() catches
        # that and drop-oldest's the queue to make room for the new event.
        self._max_queue_size = max(
            options.max_queue_size if options.max_queue_size else 10_000,
            self._batch_size,
        )
        self._on_error: Callable[[Exception], None] = options.on_error or (lambda _e: None)
        self._on_queue_overflow: Callable[[int], None] = (
            options.on_queue_overflow or (lambda _n: None)
        )
        self._dropped_since_last_flush = 0

        self._queue: "queue.Queue[TelemetryEvent]" = queue.Queue(maxsize=self._max_queue_size)
        self._closed = threading.Event()
        self._flush_lock = threading.Lock()
        self._wakeup = threading.Event()

        self._worker = threading.Thread(
            target=self._run, name="arcis-telemetry", daemon=True
        )
        self._worker.start()

    # public ----

    def record(self, event: TelemetryEvent) -> None:
        """Enqueue an event. Never raises, never blocks.

        Drop-oldest when the queue is full: better to lose stale events
        than to grow without bound during a dashboard outage. Each drop
        increments the overflow counter and notifies the caller via
        ``on_queue_overflow``.
        """
        if self._closed.is_set():
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Drop the oldest event to make room for the freshest one.
            try:
                self._queue.get_nowait()
                self._dropped_since_last_flush += 1
                try:
                    self._on_queue_overflow(self._dropped_since_last_flush)
                except Exception:
                    pass
                self._queue.put_nowait(event)
            except Exception:
                # Race: another consumer drained the queue between our
                # Full and get_nowait. Drop this event silently — we'll
                # retry on the next record() call.
                return
        except Exception:
            # Any other exception: never break the caller's hot path.
            return
        if self._queue.qsize() >= self._batch_size:
            self._wakeup.set()

    def flush(self) -> None:
        """Manually flush. Pulls up to batch_size events and POSTs them.

        Safe to call from any thread. Never raises.
        """
        with self._flush_lock:
            batch = self._drain(self._batch_size)
            if not batch:
                return
            try:
                self._send(batch)
                # Connected dashboard "clears" the overflow alert window.
                self._dropped_since_last_flush = 0
            except Exception as e:
                self._safe_notify(e)

        # Drain anything that arrived while we were posting.
        if not self._closed.is_set() and not self._queue.empty():
            self._wakeup.set()

    def close(self) -> None:
        """Stop the worker and attempt one final flush. Idempotent."""
        if self._closed.is_set():
            return
        self._closed.set()
        self._wakeup.set()
        # Best-effort: give the worker up to 2s to exit cleanly.
        self._worker.join(timeout=2.0)
        # Final drain on the calling thread in case the worker missed events.
        try:
            self.flush()
        except Exception:
            pass

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    # internals ----

    def _run(self) -> None:
        while not self._closed.is_set():
            self._wakeup.wait(timeout=self._flush_interval_s)
            self._wakeup.clear()
            if self._closed.is_set():
                break
            try:
                self.flush()
            except Exception as e:  # pragma: no cover - flush handles its own errors
                self._safe_notify(e)
        # one final flush on shutdown
        try:
            self.flush()
        except Exception:
            pass

    def _drain(self, limit: int) -> list[TelemetryEvent]:
        out: list[TelemetryEvent] = []
        for _ in range(limit):
            try:
                out.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return out

    def _send(self, batch: list[TelemetryEvent]) -> None:
        body = _serialize_batch(batch)
        if httpx is not None:
            _post_sync_httpx(self._endpoint, self._headers, body, _FLUSH_TIMEOUT_S)
        else:
            _post_sync_urllib(self._endpoint, self._headers, body, _FLUSH_TIMEOUT_S)

    def _safe_notify(self, err: Exception) -> None:
        try:
            self._on_error(err)
        except Exception:
            # user-provided hook must never bubble up
            pass


# ─── Async client ──────────────────────────────────────────────────────────


class AsyncTelemetryClient:
    """In-memory batching client for asyncio apps (FastAPI, Starlette).

    Internals:
      * ``asyncio.Queue``
      * a background ``asyncio.Task`` that wakes on the flush interval
      * ``record()`` is sync and non-blocking; ``flush()`` and ``close()``
        are coroutines
      * fail-open on every error path
    """

    def __init__(self, options: TelemetryOptions) -> None:
        if not options.endpoint or not isinstance(options.endpoint, str):
            raise TypeError("AsyncTelemetryClient: `endpoint` is required")

        self._endpoint = options.endpoint
        self._headers = _build_headers(options)
        self._batch_size = _clamp(
            options.batch_size if options.batch_size is not None else _DEFAULT_BATCH_SIZE,
            1,
            _MAX_BATCH_SIZE,
        )
        self._flush_interval_s = (
            max(options.flush_interval_ms or _DEFAULT_FLUSH_INTERVAL_MS, _MIN_FLUSH_INTERVAL_MS)
            / 1000.0
        )
        self._max_queue_size = max(
            options.max_queue_size if options.max_queue_size else 10_000,
            self._batch_size,
        )
        self._on_error: Callable[[Exception], None] = options.on_error or (lambda _e: None)
        self._on_queue_overflow: Callable[[int], None] = (
            options.on_queue_overflow or (lambda _n: None)
        )
        self._dropped_since_last_flush = 0

        self._queue: "asyncio.Queue[TelemetryEvent]" = asyncio.Queue(maxsize=self._max_queue_size)
        self._closed = False
        self._flushing = False
        self._wakeup = asyncio.Event()
        self._task: Optional[asyncio.Task[None]] = None
        self._start()

    # public ----

    def record(self, event: TelemetryEvent) -> None:
        """Enqueue an event. Sync, non-blocking, never raises.

        Drop-oldest when the queue is full so memory stays bounded under
        sustained dashboard outage. ``asyncio.Queue.put_nowait`` raises
        ``QueueFull`` when at capacity.
        """
        if self._closed:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self._dropped_since_last_flush += 1
                try:
                    self._on_queue_overflow(self._dropped_since_last_flush)
                except Exception:
                    pass
                self._queue.put_nowait(event)
            except Exception:
                return
        except Exception:
            return
        if self._queue.qsize() >= self._batch_size:
            self._wakeup.set()

    async def flush(self) -> None:
        """Manually flush. Pulls up to batch_size events and POSTs them."""
        if self._flushing:
            return
        if self._queue.empty():
            return
        self._flushing = True
        try:
            batch = self._drain(self._batch_size)
            if batch:
                try:
                    await self._send(batch)
                    self._dropped_since_last_flush = 0
                except Exception as e:
                    self._safe_notify(e)
        finally:
            self._flushing = False

        # tail re-flush — events arriving during the in-flight POST shouldn't strand
        if not self._closed and not self._queue.empty():
            self._wakeup.set()

    async def close(self) -> None:
        """Stop the worker and flush one final time. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._wakeup.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        try:
            await self.flush()
        except Exception:
            pass

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    # internals ----

    def _start(self) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — caller is constructing the client outside an
            # async context. Defer task creation to first record() / flush().
            self._task = None
            return
        self._task = loop.create_task(self._run(), name="arcis-telemetry")

    async def _run(self) -> None:
        while not self._closed:
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=self._flush_interval_s)
            except asyncio.TimeoutError:
                pass
            self._wakeup.clear()
            if self._closed:
                break
            try:
                await self.flush()
            except Exception as e:  # pragma: no cover
                self._safe_notify(e)

    def _drain(self, limit: int) -> list[TelemetryEvent]:
        out: list[TelemetryEvent] = []
        for _ in range(limit):
            try:
                out.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return out

    async def _send(self, batch: list[TelemetryEvent]) -> None:
        body = _serialize_batch(batch)
        if httpx is not None:
            await _post_async_httpx(self._endpoint, self._headers, body, _FLUSH_TIMEOUT_S)
            return
        # urllib fallback in a thread to avoid blocking the loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            _post_sync_urllib,
            self._endpoint,
            self._headers,
            body,
            _FLUSH_TIMEOUT_S,
        )

    def _safe_notify(self, err: Exception) -> None:
        try:
            self._on_error(err)
        except Exception:
            pass


__all__ = [
    "TelemetryClient",
    "AsyncTelemetryClient",
    "TelemetryHttpError",
]
