"""v1.7 W3 GraphQL wire-up integration tests for ArcisMiddleware."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware
from arcis.sanitizers.graphql import GraphqlGuardOptions


_BROWSER_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}


def _make_app(**middleware_kwargs):
    app = FastAPI()
    middleware_kwargs.setdefault("rate_limit", False)
    app.add_middleware(ArcisMiddleware, **middleware_kwargs)

    @app.post("/graphql")
    async def graphql():
        return {"data": {}}

    return TestClient(app)


BENCH_PAYLOADS = [
    ("alias-bomb", "{a:user{id} b:user{id} c:user{id} d:user{id} e:user{id} f:user{id} g:user{id} h:user{id} i:user{id} j:user{id} k:user{id} l:user{id}}"),
    ("fragment-cycle", "fragment A on Query { ...B } fragment B on Query { ...A } { ...A }"),
    ("deep-query", "{user{posts{comments{replies{replies{replies{replies{replies{replies{replies{id}}}}}}}}}}}"),
    ("introspection", "{__schema{types{name fields{name type{name}}}}}"),
]


@pytest.mark.parametrize("name,query", BENCH_PAYLOADS)
def test_default_blocks_bench_payloads(name, query):
    client = _make_app()
    r = client.post("/graphql", json={"query": query}, headers=_BROWSER_HEADERS)
    assert r.status_code == 403, f"{name} should be blocked"


LEGIT_QUERIES = [
    "{ user { id name email } }",
    "{ user { posts { comments { author { name } } } } }",
    "{ user { __typename id name } }",  # __typename is allowed
    "{ a: user(id: 1) { name } b: user(id: 2) { name } }",  # 2 aliases under 10
]


@pytest.mark.parametrize("query", LEGIT_QUERIES)
def test_legit_queries_allowed(query):
    client = _make_app()
    r = client.post("/graphql", json={"query": query}, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


def test_no_query_field_passes():
    client = _make_app()
    r = client.post("/graphql", json={"other": "field"}, headers=_BROWSER_HEADERS)
    assert r.status_code == 200


def test_opt_out():
    client = _make_app(graphql=False)
    r = client.post(
        "/graphql",
        json={"query": "{a:u{id} b:u{id} c:u{id} d:u{id} e:u{id} f:u{id} g:u{id} h:u{id} i:u{id} j:u{id} k:u{id} l:u{id}}"},
        headers=_BROWSER_HEADERS,
    )
    assert r.status_code == 200


def test_custom_options():
    client = _make_app(graphql_options=GraphqlGuardOptions(block_introspection=False))
    r = client.post(
        "/graphql",
        json={"query": "{__schema{types{name}}}"},
        headers=_BROWSER_HEADERS,
    )
    assert r.status_code == 200


def test_dry_run_does_not_block():
    client = _make_app(dry_run=True)
    r = client.post(
        "/graphql",
        json={"query": "{a:u{id} b:u{id} c:u{id} d:u{id} e:u{id} f:u{id} g:u{id} h:u{id} i:u{id} j:u{id} k:u{id} l:u{id}}"},
        headers=_BROWSER_HEADERS,
    )
    assert r.status_code == 200
