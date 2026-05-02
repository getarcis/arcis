"""
Dashboard upload helper used by `arcis scan`, `arcis audit`, `arcis sca`.

Each CLI runs locally and prints findings to the terminal. When the
`ARCIS_ENDPOINT` env var is set (same convention as middleware
telemetry), the CLI also POSTs a summary to the dashboard so the
workspace's run history is browsable in the UI.

Design rules:
    1. Opt-in via env vars. Local CLI usage must not break when the
       dashboard isn't reachable.
    2. Stdlib `urllib` only — no `httpx` runtime dependency. The Arcis
       package stays zero-deps.
    3. Fail silently. Network errors print a single short note to
       stderr and never raise. The CLI's exit code reflects findings,
       not telemetry-upload success.
    4. 5-second connect+read timeout. The user is waiting; we don't
       hang the terminal on a wedged dashboard endpoint.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


_TIMEOUT_SECONDS = 5
_DEFAULT_BASE = "http://localhost:3333"


def _read_endpoint() -> Optional[str]:
    """Resolve the dashboard endpoint base URL from env.

    Honors the same `ARCIS_ENDPOINT` var the middleware telemetry
    uses. Strips a trailing `/v1/events` if the user pasted the full
    middleware-telemetry URL — the CLI talks to `/v1/scans` etc., not
    the events route.
    """
    raw = os.environ.get("ARCIS_ENDPOINT", "").strip()
    if not raw:
        return None
    if raw.endswith("/v1/events"):
        raw = raw[: -len("/v1/events")]
    return raw.rstrip("/")


def _build_request(url: str, body: Dict[str, Any]) -> urllib.request.Request:
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "arcis-cli",
    }
    workspace = os.environ.get("ARCIS_WORKSPACE_ID", "").strip()
    if workspace:
        headers["x-workspace-id"] = workspace
    api_key = os.environ.get("ARCIS_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return urllib.request.Request(url, data=payload, headers=headers, method="POST")


def upload(
    *,
    kind: str,
    body: Dict[str, Any],
    quiet: bool = False,
) -> Optional[str]:
    """POST a CLI run summary to the dashboard.

    Args:
        kind: ``"scans"`` or ``"audits"``. Selects the route under
            ``/v1/`` so callers don't have to know URL structure.
        body: JSON-serializable dict matching the route's body schema:
            ``{language, target, summary, findingsCount}``.
        quiet: Suppress the "Dashboard: ..." stderr note even on success.

    Returns:
        The newly-created run's id on success, ``None`` if the upload
        was skipped (no endpoint set) or failed (network / 4xx / 5xx).
        Failure never raises — local CLI usage must keep working.
    """
    base = _read_endpoint()
    if base is None:
        return None
    url = f"{base}/v1/{kind}"
    try:
        req = _build_request(url, body)
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            raw = resp.read()
            data = json.loads(raw.decode("utf-8") or "{}") if raw else {}
            run_id = data.get("id") if isinstance(data, dict) else None
            if not quiet:
                short_url = f"{base}/{kind}"
                if run_id:
                    print(
                        f"  Dashboard:  uploaded as {run_id} -> {short_url}",
                        file=sys.stderr,
                    )
                else:
                    print(f"  Dashboard:  uploaded -> {short_url}", file=sys.stderr)
            return run_id
    except urllib.error.HTTPError as e:
        if not quiet:
            print(
                f"  Dashboard:  upload skipped (HTTP {e.code} from {url})",
                file=sys.stderr,
            )
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        if not quiet:
            print(
                f"  Dashboard:  upload skipped (cannot reach {base}: {e})",
                file=sys.stderr,
            )
        return None
    except Exception:
        # Last-resort guard — never let upload bugs break the CLI.
        return None


__all__ = ["upload"]
