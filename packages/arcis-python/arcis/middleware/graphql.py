"""
GraphQL guard middleware (sdk-vectors.md tier 1 #21).

ASGI adapter for ``sanitizers/graphql.py``'s pure inspector. Wraps the
request body on configured paths (default: ``/graphql``) and blocks
queries that violate the configured depth / introspection / length
limits before the resolver sees them.

Why a separate module from ``sanitizers/graphql.py``: the sanitizer is
the pure logic (depth count + introspection regex + length check) and
returns a structured ``GraphqlGuardResult``. This file is the framework
adapter (Pattern 3: thin wire that bridges core to ASGI).

Example (FastAPI / Starlette)::

    from arcis.middleware.graphql import GraphqlGuardMiddleware
    from arcis.sanitizers.graphql import GraphqlGuardOptions

    app.add_middleware(
        GraphqlGuardMiddleware,
        options=GraphqlGuardOptions(max_depth=10, block_introspection=True),
        only_paths=["/graphql", "/api/graphql"],
    )
"""

import json
from typing import Callable, Iterable, Optional

from ..sanitizers.graphql import (
    GraphqlGuardOptions,
    inspect_graphql_query,
)
from .mass_assignment import (
    _header_value,
    _read_full_body,
    _replay_receive,
)


class GraphqlGuardMiddleware:
    """ASGI middleware that inspects GraphQL POST bodies against
    ``GraphqlGuardOptions`` limits.

    Default scope is ``/graphql``. Override with ``only_paths`` for apps
    that mount GraphQL at a different URL (Apollo Server defaults to
    ``/graphql``, Strawberry / Ariadne usually the same, Hasura mounts
    at ``/v1/graphql``).

    Catches three threats:

    - Depth-bomb (default max_depth=10)
    - Introspection enumeration (__schema, __type, __typeKind, __directive)
    - Over-long queries (default max_length=10000)

    Blocked queries get a 400 with body
    ``{"error": "graphql_query_blocked", "reason": "depth"|"introspection"|"length",
       "depth": N, "length": N}``.
    """

    DEFAULT_PATHS = ("/graphql",)

    def __init__(
        self,
        app: Callable,
        *,
        options: Optional[GraphqlGuardOptions] = None,
        only_paths: Optional[Iterable[str]] = None,
        status_code: int = 400,
    ):
        self.app = app
        self.options = options or GraphqlGuardOptions()
        self.only_paths = tuple(only_paths) if only_paths is not None else self.DEFAULT_PATHS
        self.status_code = status_code

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method", "").upper() != "POST":
            await self.app(scope, receive, send)
            return
        if not self._path_matches(scope):
            await self.app(scope, receive, send)
            return
        content_type = _header_value(scope, b"content-type")
        if content_type is None or b"application/json" not in content_type:
            # Not a JSON GraphQL body — let it through. GraphQL multipart
            # (file uploads) is out of scope for v1.
            await self.app(scope, receive, send)
            return

        body, _ = await _read_full_body(receive)
        if body is None:
            await self.app(scope, receive, send)
            return

        # Extract the query string. GraphQL over HTTP wraps it in a JSON
        # object: {"query": "...", "variables": {...}}. We don't try to
        # parse variables — depth-bomb / introspection live in the query
        # field. Batched queries (array of {query, ...}) are also checked
        # per-entry; if ANY entry violates, the whole batch is blocked.
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            await self.app(scope, _replay_receive(body), send)
            return

        queries = self._collect_queries(parsed)
        for q in queries:
            result = inspect_graphql_query(q, self.options)
            if result.blocked:
                await self._send_block(send, result)
                return

        await self.app(scope, _replay_receive(body), send)

    def _path_matches(self, scope) -> bool:
        path = scope.get("path", "")
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.only_paths)

    @staticmethod
    def _collect_queries(parsed) -> list:
        """Pull every ``query`` field out of a GraphQL request body.

        Accepted shapes:
        - ``{"query": "...", ...}`` (single)
        - ``[{"query": "..."}, {"query": "..."}, ...]`` (batched)

        Anything else returns an empty list — the middleware lets it
        through and the resolver returns its own error.
        """
        if isinstance(parsed, dict):
            q = parsed.get("query")
            return [q] if isinstance(q, str) else []
        if isinstance(parsed, list):
            return [
                item["query"]
                for item in parsed
                if isinstance(item, dict) and isinstance(item.get("query"), str)
            ]
        return []

    async def _send_block(self, send, result) -> None:
        payload = json.dumps(
            {
                "error": "graphql_query_blocked",
                "reason": result.reason,
                "depth": result.depth,
                "length": result.length,
            }
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": payload, "more_body": False}
        )
