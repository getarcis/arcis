"""
Mass-assignment runtime guard (sdk-vectors.md tier 1 #25).

The classic mass-assignment vulnerability::

    user = await User.find_one({"id": id})
    user.update(**request.json())   # attacker sets is_admin=True
    await user.save()

This module ships in two layers per Pattern 3:

- ``apply_mass_assign_filter()`` (framework-agnostic): pure function that
  takes a request body dict + an allowlist and returns the filtered
  body plus any disallowed keys. Call directly from any framework.

- ``MassAssignMiddleware`` (ASGI adapter): wraps the request body for
  FastAPI / Starlette / Litestar / Quart so the handler receives only
  allowed keys. Pair it with the audit rule (``MASS-ASSIGN`` in
  ``arcis audit``) for the static-analysis side.

Two modes:

- ``"strip"`` (default) silently drop disallowed keys, continue
- ``"reject"`` return ``status_code`` (default 400) listing the keys

Default scope is top-level keys only. Nested objects pass through
untouched — that's deliberate: nested allowlists encourage
``allow=["profile.bio", "profile.avatar"]`` style strings which become
a parser, not a guard. Use a schema validator (Pydantic / arcis
``validate``) when nested filtering is required.

Mirrors ``arcis-node/src/middleware/mass-assign.ts``.
"""

from dataclasses import dataclass
import json
from typing import Any, Callable, Iterable, List, Optional, Set, Tuple


# ── v1.7 W4: denylist detection of privilege-escalation fields ──────────
#
# The allowlist filter above is the robust fix but needs a per-route field
# list, so it cannot be default-on. This detector is the default-on
# complement: it recursively scans a body for a curated set of
# privilege/auth field NAMES a normal client request almost never sets.
# Mirrors arcis-node/src/sanitizers/mass-assignment.ts.

SENSITIVE_FIELD_NAMES: Set[str] = {
    "isadmin",
    "issuperuser",
    "superuser",
    "issuperadmin",
    "superadmin",
    "isstaff",
    "isverified",
    "isroot",
    "isowner",
    "role",
    "roles",
    "userrole",
    "permission",
    "permissions",
    "privilege",
    "privileges",
    "accesslevel",
    "accounttype",
    "isactive",
    "emailverified",
}


def _normalize_field_key(key: str) -> str:
    """Lowercase + strip ``_`` and ``-`` so is_admin / isAdmin / is-admin
    all collapse to the same canonical form."""
    return key.lower().replace("_", "").replace("-", "")


@dataclass(frozen=True)
class MassAssignDetectResult:
    """Outcome of scanning a body for privilege-escalation field names.

    Attributes:
        detected: True if a sensitive field name was found anywhere.
        field: The offending field name (original casing) or None.
    """

    detected: bool
    field: Optional[str]


def detect_mass_assignment(
    body: Any,
    *,
    sensitive_fields: Optional[Iterable[str]] = None,
    max_depth: int = 8,
) -> MassAssignDetectResult:
    """Recursively scan ``body`` for privilege-escalation field names.

    Detection only. Does not strip or rewrite. Recurses into nested
    dicts and lists so ``{"profile": {"permissions": [...]}}`` is caught.
    Value-agnostic: the presence of the key is the signal.

    Args:
        body: Parsed request body (typically from ``request.json()``).
        sensitive_fields: Override the default field set. Compared after
            normalization (lowercased, separators stripped).
        max_depth: Max recursion depth into nested structures. Default 8.

    Returns:
        ``MassAssignDetectResult`` with the first offending key, if any.
    """
    if sensitive_fields is not None:
        sensitive = {_normalize_field_key(f) for f in sensitive_fields}
    else:
        sensitive = SENSITIVE_FIELD_NAMES

    def walk(value: Any, depth: int) -> Optional[str]:
        if depth > max_depth:
            return None
        if isinstance(value, dict):
            for key in value.keys():
                if isinstance(key, str) and _normalize_field_key(key) in sensitive:
                    return key
            for v in value.values():
                hit = walk(v, depth + 1)
                if hit is not None:
                    return hit
            return None
        if isinstance(value, list):
            for item in value:
                hit = walk(item, depth + 1)
                if hit is not None:
                    return hit
        return None

    field = walk(body, 0)
    return MassAssignDetectResult(detected=field is not None, field=field)


@dataclass(frozen=True)
class MassAssignResult:
    """Outcome of filtering a request body against an allowlist.

    Attributes:
        filtered: The body with disallowed top-level keys removed.
            None if the input was not a dict (and ``pass_through_non_dict``
            was True).
        disallowed: List of keys that were present in the input but
            not in the allowlist.
        body_type: One of "dict", "list", "string", "bytes", "none",
            "other". Helps callers decide whether to apply the filter.
    """

    filtered: Optional[dict]
    disallowed: List[str]
    body_type: str


def apply_mass_assign_filter(
    body: Any,
    allow: Iterable[str],
    *,
    pass_through_non_dict: bool = True,
) -> MassAssignResult:
    """Filter ``body`` to the given allowlist of top-level keys.

    Pure function. No I/O. Safe to call repeatedly.

    Args:
        body: Request body (typically a dict from ``request.json()``).
        allow: Iterable of permitted top-level key names. MUST be
            non-empty — an empty allowlist would silently strip every
            key, almost certainly a configuration mistake.
        pass_through_non_dict: When True (default), non-dict bodies
            (strings, lists, bytes, None) pass through unchanged with
            empty ``disallowed``. When False, the caller knows the
            body must be a dict and gets back ``filtered=None`` so it
            can reject the request.

    Returns:
        ``MassAssignResult`` describing the filtered body and any
        disallowed keys.

    Raises:
        ValueError: When ``allow`` is empty.

    Example:
        result = apply_mass_assign_filter(
            {"email": "x@y.z", "is_admin": True},
            allow=["email", "password", "name"],
        )
        # result.filtered == {"email": "x@y.z"}
        # result.disallowed == ["is_admin"]
    """
    allow_set = set(allow)
    if not allow_set:
        raise ValueError(
            "apply_mass_assign_filter: allow must contain at least one key"
        )

    if body is None:
        return MassAssignResult(filtered=None, disallowed=[], body_type="none")
    if isinstance(body, dict):
        disallowed = [k for k in body.keys() if k not in allow_set]
        filtered = {k: v for k, v in body.items() if k in allow_set}
        return MassAssignResult(
            filtered=filtered, disallowed=disallowed, body_type="dict"
        )
    if isinstance(body, list):
        return MassAssignResult(
            filtered=None if pass_through_non_dict else None,
            disallowed=[],
            body_type="list",
        )
    if isinstance(body, (bytes, bytearray)):
        return MassAssignResult(
            filtered=None, disallowed=[], body_type="bytes"
        )
    if isinstance(body, str):
        return MassAssignResult(
            filtered=None, disallowed=[], body_type="string"
        )
    return MassAssignResult(filtered=None, disallowed=[], body_type="other")


# ── ASGI middleware adapter (works on FastAPI / Starlette / Litestar) ──


class MassAssignMiddleware:
    """ASGI middleware that filters request JSON bodies against an
    allowlist before they reach the route handler.

    Implementation notes:

    - Only triggers on ``application/json`` requests. Form-encoded,
      multipart, and plain-text payloads pass through.
    - Reads the full body, applies the filter, then forwards a
      reconstructed body to the inner app via the ``receive`` callable.
      Memory cost is proportional to body size (default ASGI body cap
      is 1 MB for most frameworks).
    - In ``reject`` mode, returns a JSON 400 response immediately
      without calling the inner app.

    Example (FastAPI / Starlette)::

        from arcis.middleware.mass_assignment import MassAssignMiddleware
        app.add_middleware(
            MassAssignMiddleware,
            allow=["email", "password", "name"],
            mode="strip",
        )

    Example (Litestar)::

        from litestar import Litestar
        from litestar.middleware import DefineMiddleware
        from arcis.middleware.mass_assignment import MassAssignMiddleware

        app = Litestar(
            middleware=[
                DefineMiddleware(MassAssignMiddleware, allow=["email", "name"])
            ],
        )
    """

    def __init__(
        self,
        app: Callable,
        *,
        allow: Iterable[str],
        mode: str = "strip",
        status_code: int = 400,
        message: str = "Disallowed fields",
        only_paths: Optional[Iterable[str]] = None,
    ):
        """Build the middleware.

        Args:
            app: Inner ASGI app.
            allow: Iterable of permitted top-level body keys. Non-empty.
            mode: ``"strip"`` (default) silently drops disallowed keys.
                ``"reject"`` returns a 400 with the disallowed key list.
            status_code: Status for the reject path. Default 400.
            message: Error message in the reject body. Default
                ``"Disallowed fields"``.
            only_paths: When set, the middleware only applies to
                requests whose path starts with one of these prefixes.
                Useful for scoping to ``/api/users`` style routes.
                Default: applies to all paths.
        """
        self.app = app
        self.allow = list(allow)
        if not self.allow:
            raise ValueError(
                "MassAssignMiddleware: allow must contain at least one key"
            )
        if mode not in ("strip", "reject"):
            raise ValueError("MassAssignMiddleware: mode must be 'strip' or 'reject'")
        self.mode = mode
        self.status_code = status_code
        self.message = message
        self.only_paths = list(only_paths) if only_paths is not None else None

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        if not self._should_apply(scope):
            await self.app(scope, receive, send)
            return

        # Buffer the full request body before deciding what to do.
        body, more_body_state = await _read_full_body(receive)
        if body is None:
            await self.app(scope, receive, send)
            return

        try:
            parsed = json.loads(body) if body else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not valid JSON — let the inner app deal with it (it will
            # likely return its own 422 / 400). We don't second-guess.
            await self.app(scope, _replay_receive(body), send)
            return

        if not isinstance(parsed, dict):
            await self.app(scope, _replay_receive(body), send)
            return

        result = apply_mass_assign_filter(parsed, self.allow)
        if result.disallowed and self.mode == "reject":
            await _send_json_reject(
                send, self.status_code, self.message, result.disallowed
            )
            return

        new_body = json.dumps(result.filtered).encode("utf-8")
        await self.app(scope, _replay_receive(new_body), send)

    def _should_apply(self, scope) -> bool:
        # Only filter application/json bodies.
        content_type = _header_value(scope, b"content-type")
        if content_type is None or b"application/json" not in content_type:
            return False
        if self.only_paths is None:
            return True
        path = scope.get("path", "")
        return any(path.startswith(p) for p in self.only_paths)


# ── ASGI helpers (shared across mass-assign / method-allow / response-split) ──


def _header_value(scope, name: bytes) -> Optional[bytes]:
    """Lookup the first header value matching ``name`` (case-insensitive)."""
    for key, value in scope.get("headers", []) or []:
        if key.lower() == name:
            return value
    return None


async def _read_full_body(receive) -> Tuple[Optional[bytes], bool]:
    """Drain an ASGI ``receive`` channel until ``more_body`` is False.

    Returns ``(body_bytes, had_more_body_segments)``. ``body_bytes`` is
    None when the request stream ended without an ``http.request`` event
    (disconnect mid-flight).
    """
    chunks: List[bytes] = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None, False
        if message["type"] != "http.request":
            continue
        chunks.append(message.get("body", b"") or b"")
        more = message.get("more_body", False)
    return b"".join(chunks), len(chunks) > 1


def _replay_receive(body: bytes):
    """Build a new ``receive`` callable that yields ``body`` once.

    ASGI middlewares that buffer the body must replay it for the inner
    app or the inner app will hang waiting for ``http.request``.
    """
    sent = {"done": False}

    async def receive():
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


async def _send_json_reject(send, status: int, message: str, fields: List[str]) -> None:
    """Emit a JSON error response and end the cycle."""
    payload = json.dumps({"error": message, "fields": fields}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload, "more_body": False})
