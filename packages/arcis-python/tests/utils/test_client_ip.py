"""
Client IP resolution and rate-limit key tests.

Runs every case of spec/client-ip-vectors.json (shared with the Node and Go
SDKs) plus the Python request-shape and diagnostics behavior.
"""

import json
import logging
from pathlib import Path

import pytest

from arcis.utils import ip as ip_module
from arcis.utils.ip import (
    DEFAULT_TRUSTED_PROXIES,
    client_ip_from_request,
    ip_key_generator,
    rate_limit_key,
    resolve_client_ip,
    validate_trusted_proxies,
)

_VECTORS_PATH = Path(__file__).resolve().parents[4] / "spec" / "client-ip-vectors.json"
_VECTORS = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _fresh_warnings():
    ip_module._reset_warnings()
    yield
    ip_module._reset_warnings()


def test_default_trust_set_matches_fixture():
    assert list(DEFAULT_TRUSTED_PROXIES) == _VECTORS["default_trusted_proxies"]


def test_fixture_counts():
    assert len(_VECTORS["resolution"]) == 624
    assert len(_VECTORS["keys"]) == 40


@pytest.mark.parametrize("case", _VECTORS["resolution"], ids=lambda c: c["id"])
def test_resolution_vector(case):
    resolved = resolve_client_ip(case["peer"], case["x_forwarded_for"], case["trusted_proxies"])
    assert resolved == case["expected_client_ip"]
    key = None if resolved is None else ip_key_generator(resolved)
    assert key == case["expected_key"]


@pytest.mark.parametrize(
    "case", _VECTORS["keys"], ids=lambda c: f"{c['ip']}|{c['ipv6_subnet']}"
)
def test_key_vector(case):
    assert ip_key_generator(case["ip"], case["ipv6_subnet"]) == case["expected_key"]


class TestResolverDetails:
    def test_no_peer_ignores_forwarded_for(self):
        assert resolve_client_ip(None, "203.0.113.7") is None

    def test_rotating_xff_from_public_peer_keeps_peer(self):
        for spoof in ("1.1.1.1", "2.2.2.2, 3.3.3.3", "garbage"):
            assert resolve_client_ip("203.0.113.5", spoof) == "203.0.113.5"

    def test_multiple_header_values_are_joined(self):
        assert resolve_client_ip("10.0.0.1", ["198.51.100.7", "10.0.0.3"]) == "198.51.100.7"

    def test_unix_peer_trusted_only_when_listed(self):
        assert resolve_client_ip("", "198.51.100.7") is None
        assert resolve_client_ip("", "198.51.100.7", ["unix"]) == "198.51.100.7"
        assert resolve_client_ip(None, "198.51.100.7, 10.0.0.2", ["unix", "10.0.0.0/8"]) == (
            "198.51.100.7"
        )

    def test_ipv4_mapped_trusted_range(self):
        assert resolve_client_ip("10.1.2.3", "198.51.100.7", ["::ffff:10.0.0.0/104"]) == (
            "198.51.100.7"
        )

    def test_ipv4_peer_matches_ipv6_mapped_network(self):
        # An IPv6 range that does not reduce to IPv4 still covers mapped hosts.
        assert resolve_client_ip("10.1.2.3", "198.51.100.7", ["::/0"]) == "198.51.100.7"

    def test_uncompressed_ipv6_is_canonical(self):
        assert resolve_client_ip("2001:0DB8:0000:0000:0000:0000:0000:0001", None) == "2001:db8::1"

    def test_single_string_trusted_proxies(self):
        assert resolve_client_ip("203.0.113.9", "198.51.100.7", "203.0.113.0/24") == (
            "198.51.100.7"
        )


class TestValidation:
    @pytest.mark.parametrize("bad", [["not-a-cidr"], ["10.0.0.0/33"], [42]])
    def test_invalid_trusted_proxies_raise(self, bad):
        with pytest.raises(ValueError):
            validate_trusted_proxies(bad)

    @pytest.mark.parametrize("bad", [0, 129, True, "56", 1.5])
    def test_invalid_ipv6_subnet_raises(self, bad):
        with pytest.raises(ValueError):
            ip_key_generator("2001:db8::1", bad)

    def test_non_ip_key_is_unchanged(self):
        assert ip_key_generator("tenant-a") == "tenant-a"


class TestDiagnostics:
    def test_untrusted_forwarded_for_warns_once(self, caplog):
        with caplog.at_level(logging.WARNING, logger="arcis.utils.ip"):
            resolve_client_ip("203.0.113.5", "1.1.1.1")
            resolve_client_ip("203.0.113.6", "2.2.2.2")
        warnings = [r for r in caplog.records if "not in trusted_proxies" in r.getMessage()]
        assert len(warnings) == 1

    def test_trust_all_range_warns_once(self, caplog):
        ip_module._compile_trust.cache_clear()
        with caplog.at_level(logging.WARNING, logger="arcis.utils.ip"):
            validate_trusted_proxies(["0.0.0.0/0"])
            validate_trusted_proxies(["::/0"])
        warnings = [r for r in caplog.records if "trusts every address" in r.getMessage()]
        assert len(warnings) == 1

    def test_no_warning_without_forwarded_header(self, caplog):
        with caplog.at_level(logging.WARNING, logger="arcis.utils.ip"):
            resolve_client_ip("203.0.113.5", None)
        assert not caplog.records


class TestRequestShapes:
    def test_asgi_scope(self):
        scope = {
            "type": "http",
            "client": ("10.0.0.2", 5000),
            "headers": [(b"x-forwarded-for", b"198.51.100.7"), (b"x-forwarded-for", b"10.0.0.9")],
        }
        assert client_ip_from_request(scope) == "198.51.100.7"

    def test_asgi_scope_without_client(self):
        scope = {"type": "http", "client": None, "headers": [(b"x-forwarded-for", b"1.1.1.1")]}
        assert client_ip_from_request(scope) is None
        assert rate_limit_key(scope) == "unknown"

    def test_wsgi_environ(self):
        environ = {"REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_FOR": "203.0.113.7"}
        assert client_ip_from_request(environ) == "203.0.113.7"

    def test_werkzeug_proxy_fix_is_not_applied_twice(self):
        # ProxyFix already rewrote REMOTE_ADDR to the client. A private
        # client must not have the header walked a second time.
        environ = {
            "REMOTE_ADDR": "10.1.1.1",
            "HTTP_X_FORWARDED_FOR": "6.6.6.6, 10.1.1.1",
            "werkzeug.proxy_fix.orig": {"REMOTE_ADDR": "127.0.0.1"},
        }
        assert client_ip_from_request(environ) == "10.1.1.1"

    def test_werkzeug_proxy_fix_end_to_end(self):
        flask = pytest.importorskip("flask")
        from werkzeug.middleware.proxy_fix import ProxyFix

        app = flask.Flask(__name__)

        @app.route("/")
        def index():
            return client_ip_from_request(flask.request) or "none"

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
        client = app.test_client()
        resp = client.get(
            "/",
            headers={"X-Forwarded-For": "6.6.6.6, 10.1.1.1"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert resp.get_data(as_text=True) == "10.1.1.1"

    def test_ipv6_clients_share_a_56_key(self):
        a = {"REMOTE_ADDR": "2001:db8:1234:5601::1"}
        b = {"REMOTE_ADDR": "2001:db8:1234:56ff::2"}
        assert rate_limit_key(a) == rate_limit_key(b) == "2001:db8:1234:5600::/56"
        assert rate_limit_key(a, ipv6_subnet=False) == "2001:db8:1234:5601::1"
