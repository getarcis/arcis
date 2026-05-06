"""
SafeCors tests — covers origin validation, null blocking, credentials, preflight.
"""

import re
from arcis.middleware.cors import SafeCors, create_cors, _is_origin_allowed


class TestIsOriginAllowed:
    """Test the origin validation function."""

    def test_exact_string_match(self):
        assert _is_origin_allowed("https://app.com", "https://app.com")
        assert not _is_origin_allowed("https://evil.com", "https://app.com")

    def test_list_whitelist(self):
        allowed = ["https://app.com", "https://admin.app.com"]
        assert _is_origin_allowed("https://app.com", allowed)
        assert _is_origin_allowed("https://admin.app.com", allowed)
        assert not _is_origin_allowed("https://evil.com", allowed)

    def test_regex_match(self):
        pattern = re.compile(r"^https://.*\.example\.com$")
        assert _is_origin_allowed("https://app.example.com", pattern)
        assert not _is_origin_allowed("https://evil.com", pattern)

    def test_callable(self):
        fn = lambda o: o.endswith(".myapp.com")
        assert _is_origin_allowed("https://api.myapp.com", fn)
        assert not _is_origin_allowed("https://evil.com", fn)

    def test_true_reflects(self):
        assert _is_origin_allowed("https://anything.com", True)

    def test_null_origin_always_blocked(self):
        assert not _is_origin_allowed("null", True)
        assert not _is_origin_allowed("null", ["null", "https://app.com"])
        assert not _is_origin_allowed("null", "null")
        assert not _is_origin_allowed("null", lambda o: True)


class TestSafeCors:
    """Test SafeCors.get_headers()."""

    def test_allowed_origin(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com")
        assert headers["Access-Control-Allow-Origin"] == "https://app.com"

    def test_rejected_origin(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://evil.com")
        assert "Access-Control-Allow-Origin" not in headers

    def test_no_origin_header(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers(None)
        assert "Access-Control-Allow-Origin" not in headers
        assert headers["Vary"] == "Origin"

    def test_vary_always_set(self):
        cors = SafeCors(origin="https://app.com")
        assert cors.get_headers("https://app.com")["Vary"] == "Origin"
        assert cors.get_headers("https://evil.com")["Vary"] == "Origin"
        assert cors.get_headers(None)["Vary"] == "Origin"

    def test_credentials(self):
        cors = SafeCors(origin="https://app.com", credentials=True)
        headers = cors.get_headers("https://app.com")
        assert headers["Access-Control-Allow-Credentials"] == "true"

    def test_no_credentials_by_default(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com")
        assert "Access-Control-Allow-Credentials" not in headers

    def test_preflight_methods(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com", method="OPTIONS")
        assert "Access-Control-Allow-Methods" in headers
        assert "GET" in headers["Access-Control-Allow-Methods"]

    def test_custom_methods(self):
        cors = SafeCors(origin="https://app.com", methods=["GET", "POST"])
        headers = cors.get_headers("https://app.com", method="OPTIONS")
        assert headers["Access-Control-Allow-Methods"] == "GET, POST"

    def test_preflight_headers(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com", method="OPTIONS")
        assert "Content-Type" in headers["Access-Control-Allow-Headers"]
        assert "Authorization" in headers["Access-Control-Allow-Headers"]

    def test_custom_allowed_headers(self):
        cors = SafeCors(origin="https://app.com", allowed_headers=["X-Custom"])
        headers = cors.get_headers("https://app.com", method="OPTIONS")
        assert headers["Access-Control-Allow-Headers"] == "X-Custom"

    def test_max_age(self):
        cors = SafeCors(origin="https://app.com", max_age=3600)
        headers = cors.get_headers("https://app.com", method="OPTIONS")
        assert headers["Access-Control-Max-Age"] == "3600"

    def test_default_max_age(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com", method="OPTIONS")
        assert headers["Access-Control-Max-Age"] == "600"

    def test_exposed_headers(self):
        cors = SafeCors(origin="https://app.com", exposed_headers=["X-Request-Id"])
        headers = cors.get_headers("https://app.com")
        assert headers["Access-Control-Expose-Headers"] == "X-Request-Id"

    def test_no_exposed_headers_by_default(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com")
        assert "Access-Control-Expose-Headers" not in headers

    def test_null_origin_blocked(self):
        cors = SafeCors(origin=True)
        headers = cors.get_headers("null")
        assert "Access-Control-Allow-Origin" not in headers

    def test_no_preflight_headers_on_regular_request(self):
        cors = SafeCors(origin="https://app.com")
        headers = cors.get_headers("https://app.com", method="GET")
        assert "Access-Control-Allow-Methods" not in headers
        assert "Access-Control-Allow-Headers" not in headers
        assert "Access-Control-Max-Age" not in headers


class TestCreateCors:
    """Test factory function."""

    def test_returns_safe_cors(self):
        cors = create_cors(origin="https://app.com")
        assert isinstance(cors, SafeCors)

    def test_passes_options(self):
        cors = create_cors(
            origin=["https://a.com", "https://b.com"],
            credentials=True,
            max_age=1800,
        )
        assert cors.credentials is True
        assert cors.max_age == 1800
