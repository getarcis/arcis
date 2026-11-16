"""
Rate-limit keying regressions through each real framework adapter.

For every adapter:
- a public peer rotating ``X-Forwarded-For`` stays in ONE bucket and gets
  429 after ``max`` requests (the header is ignored from an untrusted peer);
- behind a trusted private proxy, distinct client IPs get distinct buckets.
"""

import pytest

PUBLIC_PEER = "203.0.113.5"
PROXY_PEER = "10.0.0.2"
MAX = 3


def _rotating_xff(i: int) -> str:
    return f"198.51.100.{i + 1}"


# ============================================================================
# FLASK
# ============================================================================


class TestFlask:
    @pytest.fixture
    def client(self):
        flask = pytest.importorskip("flask")
        from arcis import Arcis

        app = flask.Flask(__name__)
        arcis = Arcis(app, rate_limit_max=MAX, sanitize=False, headers=False)

        @app.route("/")
        def index():
            return "ok"

        yield app.test_client()
        arcis.close()

    def test_public_peer_rotating_xff_shares_one_bucket(self, client):
        statuses = [
            client.get(
                "/",
                headers={"X-Forwarded-For": _rotating_xff(i)},
                environ_base={"REMOTE_ADDR": PUBLIC_PEER},
            ).status_code
            for i in range(MAX + 2)
        ]
        assert statuses == [200] * MAX + [429, 429]

    def test_trusted_proxy_gives_each_client_its_own_bucket(self, client):
        for i in range(MAX + 2):
            resp = client.get(
                "/",
                headers={"X-Forwarded-For": _rotating_xff(i)},
                environ_base={"REMOTE_ADDR": PROXY_PEER},
            )
            assert resp.status_code == 200
        # The same client behind the proxy is still limited.
        statuses = [
            client.get(
                "/",
                headers={"X-Forwarded-For": "192.0.2.77"},
                environ_base={"REMOTE_ADDR": PROXY_PEER},
            ).status_code
            for _ in range(MAX + 1)
        ]
        assert statuses == [200] * MAX + [429]

    def test_empty_trusted_proxies_ignores_proxy_header(self):
        flask = pytest.importorskip("flask")
        from arcis import Arcis

        app = flask.Flask(__name__)
        arcis = Arcis(app, rate_limit_max=1, sanitize=False, headers=False, trusted_proxies=[])

        @app.route("/")
        def index():
            return "ok"

        client = app.test_client()
        try:
            statuses = [
                client.get(
                    "/",
                    headers={"X-Forwarded-For": _rotating_xff(i)},
                    environ_base={"REMOTE_ADDR": PROXY_PEER},
                ).status_code
                for i in range(2)
            ]
            assert statuses == [200, 429]
        finally:
            arcis.close()


# ============================================================================
# FASTAPI / STARLETTE
# ============================================================================


def _fastapi_app(**middleware_kwargs):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI

    from arcis.fastapi import ArcisMiddleware

    app = FastAPI()
    app.add_middleware(
        ArcisMiddleware,
        rate_limit_max=MAX,
        bot=False,
        headers=False,
        sanitize=False,
        **middleware_kwargs,
    )

    @app.get("/")
    async def index():
        return {"ok": True}

    return app


class TestFastAPI:
    @pytest.mark.parametrize("use_async", [True, False], ids=["async", "sync"])
    def test_public_peer_rotating_xff_shares_one_bucket(self, use_async):
        from fastapi.testclient import TestClient

        app = _fastapi_app(use_async_rate_limiter=use_async)
        client = TestClient(app, client=(PUBLIC_PEER, 50000))
        statuses = [
            client.get("/", headers={"X-Forwarded-For": _rotating_xff(i)}).status_code
            for i in range(MAX + 2)
        ]
        assert statuses == [200] * MAX + [429, 429]

    @pytest.mark.parametrize("use_async", [True, False], ids=["async", "sync"])
    def test_trusted_proxy_gives_each_client_its_own_bucket(self, use_async):
        from fastapi.testclient import TestClient

        app = _fastapi_app(use_async_rate_limiter=use_async)
        client = TestClient(app, client=(PROXY_PEER, 50000))
        for i in range(MAX + 2):
            resp = client.get("/", headers={"X-Forwarded-For": _rotating_xff(i)})
            assert resp.status_code == 200
        statuses = [
            client.get("/", headers={"X-Forwarded-For": "192.0.2.77"}).status_code
            for _ in range(MAX + 1)
        ]
        assert statuses == [200] * MAX + [429]

    def test_explicit_public_proxy_is_trusted(self):
        from fastapi.testclient import TestClient

        app = _fastapi_app(trusted_proxies=["203.0.113.0/24"])
        client = TestClient(app, client=(PUBLIC_PEER, 50000))
        for i in range(MAX + 2):
            assert client.get(
                "/", headers={"X-Forwarded-For": _rotating_xff(i)}
            ).status_code == 200

    def test_rate_limit_dependency(self):
        pytest.importorskip("fastapi")
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from arcis.fastapi import create_rate_limit_dependency

        app = FastAPI()
        limit = create_rate_limit_dependency(max_requests=MAX)

        @app.get("/", dependencies=[Depends(limit)])
        async def index():
            return {"ok": True}

        public = TestClient(app, client=(PUBLIC_PEER, 50000))
        statuses = [
            public.get("/", headers={"X-Forwarded-For": _rotating_xff(i)}).status_code
            for i in range(MAX + 1)
        ]
        assert statuses == [200] * MAX + [429]

        proxied = TestClient(app, client=(PROXY_PEER, 50000))
        for i in range(MAX + 1):
            assert proxied.get(
                "/", headers={"X-Forwarded-For": f"192.0.2.{i + 1}"}
            ).status_code == 200


# ============================================================================
# DJANGO
# ============================================================================


@pytest.fixture
def django_rf():
    pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        import django

        settings.configure(
            DEBUG=True,
            DATABASES={},
            INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
            MIDDLEWARE=[],
            ROOT_URLCONF="",
            SECRET_KEY="test-secret-key-for-arcis-tests",
        )
        django.setup()

    from django.test import RequestFactory

    from arcis.django import ArcisMiddleware, ArcisRateLimitMiddleware
    from arcis.stores.memory import InMemoryStore

    # Limiters are cached at class scope; give each test a fresh one.
    ArcisMiddleware._rate_limiter = None
    ArcisMiddleware._rate_limit_store = InMemoryStore()
    ArcisRateLimitMiddleware._rate_limiter = None
    ArcisRateLimitMiddleware._store = InMemoryStore()
    yield RequestFactory()
    ArcisMiddleware._rate_limiter = None
    ArcisRateLimitMiddleware._rate_limiter = None


def _django_middleware(kind, config):
    from django.http import HttpResponse
    from django.test import override_settings

    from arcis import django as arcis_django

    with override_settings(ARCIS_CONFIG=config):
        cls = getattr(arcis_django, kind)
        return cls(lambda request: HttpResponse("ok"))


@pytest.mark.parametrize("kind", ["ArcisMiddleware", "ArcisRateLimitMiddleware"])
class TestDjango:
    def test_public_peer_rotating_xff_shares_one_bucket(self, django_rf, kind):
        middleware = _django_middleware(kind, {"rate_limit_max": MAX, "headers": False})
        statuses = [
            middleware(
                django_rf.get("/", REMOTE_ADDR=PUBLIC_PEER, HTTP_X_FORWARDED_FOR=_rotating_xff(i))
            ).status_code
            for i in range(MAX + 2)
        ]
        assert statuses == [200] * MAX + [429, 429]

    def test_trusted_proxy_gives_each_client_its_own_bucket(self, django_rf, kind):
        middleware = _django_middleware(kind, {"rate_limit_max": MAX, "headers": False})
        for i in range(MAX + 2):
            request = django_rf.get(
                "/", REMOTE_ADDR=PROXY_PEER, HTTP_X_FORWARDED_FOR=_rotating_xff(i)
            )
            assert middleware(request).status_code == 200

    def test_trusted_proxies_setting(self, django_rf, kind):
        middleware = _django_middleware(
            kind, {"rate_limit_max": 1, "headers": False, "trusted_proxies": []}
        )
        statuses = [
            middleware(
                django_rf.get("/", REMOTE_ADDR=PROXY_PEER, HTTP_X_FORWARDED_FOR=_rotating_xff(i))
            ).status_code
            for i in range(2)
        ]
        assert statuses == [200, 429]


# ============================================================================
# LITESTAR
# ============================================================================


def _litestar_client(peer, **middleware_kwargs):
    pytest.importorskip("litestar")
    from litestar import Litestar, get
    from litestar.middleware.base import DefineMiddleware
    from litestar.testing import TestClient

    from arcis.litestar import ArcisMiddleware
    from tests._asgi_peer import with_peer

    @get("/")
    async def index() -> dict:
        return {"ok": True}

    app = Litestar(
        route_handlers=[index],
        middleware=[
            DefineMiddleware(
                ArcisMiddleware, rate_limit_max=MAX, headers=False, **middleware_kwargs
            )
        ],
    )
    return TestClient(app=with_peer(app, peer))


class TestLitestar:
    def test_public_peer_rotating_xff_shares_one_bucket(self):
        with _litestar_client(PUBLIC_PEER) as client:
            statuses = [
                client.get("/", headers={"X-Forwarded-For": _rotating_xff(i)}).status_code
                for i in range(MAX + 2)
            ]
        assert statuses == [200] * MAX + [429, 429]

    def test_trusted_proxy_gives_each_client_its_own_bucket(self):
        with _litestar_client(PROXY_PEER) as client:
            for i in range(MAX + 2):
                resp = client.get("/", headers={"X-Forwarded-For": _rotating_xff(i)})
                assert resp.status_code == 200

    def test_trusted_proxies_option(self):
        with _litestar_client(PROXY_PEER, trusted_proxies=[]) as client:
            statuses = [
                client.get("/", headers={"X-Forwarded-For": _rotating_xff(i)}).status_code
                for i in range(MAX + 1)
            ]
        assert statuses == [200] * MAX + [429]
