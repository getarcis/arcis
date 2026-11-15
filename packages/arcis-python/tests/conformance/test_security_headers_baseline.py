"""
Security headers, baseline profile: shared wire fixtures.

Loads spec/TEST_VECTORS.json -> security_headers.baseline and checks that the
Python SDK emits the same headers as the Node SDK (and Helmet 8.3.0 for the
cases marked helmet_compatible). Fixture options use the Node camelCase
names; they are translated to the Python snake_case spelling here.
"""

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import pytest

from arcis import DANGEROUSLY_DISABLE_DEFAULT_SRC, SecurityHeaders
from arcis.middleware.headers import build_security_headers

def _spec_path() -> Path:
    """Walk up from this file to the repository's spec/TEST_VECTORS.json."""
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "spec" / "TEST_VECTORS.json"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("Could not locate spec/TEST_VECTORS.json")


BASELINE = json.loads(_spec_path().read_text(encoding="utf-8"))["security_headers"]["baseline"]

# Options whose keys are user data (directive, feature and endpoint names),
# not option names, so their keys keep the fixture spelling.
_VERBATIM_KEYS = {"directives", "permissionsPolicy", "reportingEndpoints"}


def _snake(name: str) -> str:
    return re.sub(r"[A-Z]", lambda match: "_" + match.group(0).lower(), name)


def to_python_options(options: Dict[str, Any]) -> Dict[str, Any]:
    """Translate fixture options (Node spelling) to SecurityHeaders keywords."""
    translated: Dict[str, Any] = {}
    for name, value in options.items():
        if isinstance(value, dict) and name not in _VERBATIM_KEYS:
            value = {
                key if key in _VERBATIM_KEYS else _snake(key): inner
                for key, inner in value.items()
            }
        translated[_snake(name)] = value
    return translated


def to_python_message(text: str) -> str:
    """Map camelCase identifiers in an expected error fragment to snake_case."""
    return re.sub(r"\b[a-z]+(?:[A-Z][a-z0-9]*)+\b", lambda match: _snake(match.group(0)), text)


def baseline(**options: Any) -> SecurityHeaders:
    return SecurityHeaders(profile="baseline", **options)


def as_dict(headers: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    return {name.lower(): value for name, value in headers}


def csp_directives(value: str) -> Dict[str, str]:
    return {part.split(" ", 1)[0]: part for part in value.split(";")}


DEFAULTS_CASE = next(case for case in BASELINE["cases"] if case["name"] == "defaults")
DEFAULT_HEADERS = {name.lower(): value for name, value in DEFAULTS_CASE["expected_headers"].items()}


# ─── Shared fixtures ────────────────────────────────────────────────────

class TestFixtureTranslation:
    """The camelCase to snake_case mapping used by this module."""

    def test_option_names(self):
        options = to_python_options({
            "strictTransportSecurity": {"maxAge": 1, "includeSubDomains": False},
            "contentSecurityPolicy": {"useDefaults": False, "directives": {"scriptSrc": []}},
            "permissionsPolicy": {"Camera": []},
        })
        assert options == {
            "strict_transport_security": {"max_age": 1, "include_sub_domains": False},
            "content_security_policy": {"use_defaults": False, "directives": {"scriptSrc": []}},
            "permissions_policy": {"Camera": []},
        }

    def test_error_fragments(self):
        assert to_python_message("not a valid value for maxAge") == "not a valid value for max_age"
        assert to_python_message("includeSubDomains") == "include_sub_domains"
        assert to_python_message("maxage") == "maxage"
        assert to_python_message("needs a default-src") == "needs a default-src"


@pytest.mark.parametrize("case", BASELINE["cases"], ids=lambda case: case["name"])
def test_baseline_case(case):
    plan = baseline(**to_python_options(case["options"])).plan()
    headers = as_dict(plan.headers)

    assert headers == {name.lower(): value for name, value in case["expected_headers"].items()}
    for name in case["expected_absent"]:
        assert name.lower() not in headers
    assert ("X-Powered-By" in plan.remove) is case["removes_x_powered_by"]


@pytest.mark.parametrize("case", BASELINE["invalid"], ids=lambda case: case["name"])
def test_baseline_invalid(case):
    with pytest.raises(ValueError) as excinfo:
        baseline(**to_python_options(case["options"]))
    assert to_python_message(case["error_contains"]) in str(excinfo.value)


def test_route_header_wins():
    starlette_responses = pytest.importorskip("starlette.responses")
    fixture = BASELINE["route_header_wins"]
    response = starlette_responses.Response(
        "ok", headers={**fixture["route_sets"], "X-Powered-By": "app"}
    )

    baseline(**to_python_options(fixture["options"])).apply(response)

    for name, value in fixture["expected_headers"].items():
        assert response.headers[name] == value
    assert response.headers["referrer-policy"] == DEFAULT_HEADERS["referrer-policy"]
    assert "x-powered-by" not in response.headers


# ─── Nonce extension ────────────────────────────────────────────────────

class TestNonce:
    fixture = BASELINE["nonce"]
    script_src = re.compile(fixture["script_src_pattern"])

    def policy(self) -> SecurityHeaders:
        return baseline(**to_python_options(self.fixture["options"]))

    def test_script_src_carries_the_plan_nonce(self):
        plan = self.policy().plan()
        script_src = csp_directives(as_dict(plan.headers)["content-security-policy"])["script-src"]

        match = self.script_src.match(script_src)
        assert match is not None
        assert match.group(1) == plan.nonce

    def test_fresh_nonce_per_response(self):
        policy = self.policy()
        nonces = {policy.plan().nonce for _ in range(50)}
        assert len(nonces) == 50

    def test_new_nonce_is_16_random_bytes_base64(self):
        policy = self.policy()
        nonce = policy.new_nonce()
        assert nonce is not None
        assert len(base64.b64decode(nonce, validate=True)) == 16
        assert nonce != policy.new_nonce()

    def test_supplied_nonce_is_used(self):
        nonce = self.policy().new_nonce()
        plan = self.policy().plan(nonce=nonce)
        assert plan.nonce == nonce
        assert f"'nonce-{nonce}'" in as_dict(plan.headers)["content-security-policy"]

    def test_only_script_src_receives_the_nonce(self):
        csp = as_dict(self.policy().plan().headers)["content-security-policy"]
        assert csp.count("'nonce-") == 1
        assert csp_directives(csp)["style-src"] == "style-src 'self' https: 'unsafe-inline'"

    def test_everything_else_equals_the_defaults(self):
        headers = as_dict(self.policy().plan().headers)
        csp = csp_directives(headers.pop("content-security-policy"))
        defaults = dict(DEFAULT_HEADERS)
        default_csp = csp_directives(defaults.pop("content-security-policy"))

        assert headers == defaults
        assert list(csp) == list(default_csp)
        csp.pop("script-src")
        default_csp.pop("script-src")
        assert csp == default_csp

    def test_no_nonce_without_the_extension(self):
        policy = baseline()
        assert policy.uses_nonce is False
        assert policy.new_nonce() is None
        plan = policy.plan(nonce="ignored")
        assert plan.nonce is None
        assert as_dict(plan.headers) == DEFAULT_HEADERS

    def test_legacy_profile_has_no_nonce(self):
        assert SecurityHeaders().uses_nonce is False
        assert SecurityHeaders().new_nonce() is None


# ─── CSP directive values ───────────────────────────────────────────────

class TestCspValues:
    def test_callable_runs_per_response_with_the_request(self):
        seen = []

        def api_source(request):
            seen.append(request)
            return f"https://{request['host']}"

        policy = baseline(
            content_security_policy={"directives": {"connect-src": ["'self'", api_source]}}
        )
        first = as_dict(policy.plan({"host": "a.example.com"}).headers)
        second = as_dict(policy.plan({"host": "b.example.com"}).headers)

        assert first["content-security-policy"].endswith(";connect-src 'self' https://a.example.com")
        assert second["content-security-policy"].endswith(";connect-src 'self' https://b.example.com")
        assert seen == [{"host": "a.example.com"}, {"host": "b.example.com"}]

    @pytest.mark.parametrize(
        "result",
        ["self", "nonce-abc", "'self'; object-src *", "'self'\r\nX-Injected: 1", 42],
    )
    def test_invalid_callable_result_fails_that_response(self, result):
        policy = baseline(
            content_security_policy={"directives": {"script-src": [lambda request: result]}}
        )
        with pytest.raises(ValueError, match="received an invalid directive value"):
            policy.plan()

    def test_dangerously_disable_default_src(self):
        policy = baseline(
            content_security_policy={"directives": {"defaultSrc": DANGEROUSLY_DISABLE_DEFAULT_SRC}}
        )
        csp = as_dict(policy.plan().headers)["content-security-policy"]
        assert csp.startswith("base-uri 'self';")
        assert "default-src" not in csp

    def test_disable_marker_only_applies_to_default_src(self):
        with pytest.raises(ValueError, match="tried to disable"):
            baseline(
                content_security_policy={"directives": {"script-src": DANGEROUSLY_DISABLE_DEFAULT_SRC}}
            )

    def test_tuple_values(self):
        policy = baseline(content_security_policy={"directives": {"img-src": ("'self'", "data:")}})
        assert "img-src 'self' data:" in as_dict(policy.plan().headers)["content-security-policy"]

    @pytest.mark.parametrize("value", [True, 5, {"a": 1}, [5]])
    def test_non_string_values_are_rejected(self, value):
        with pytest.raises(ValueError, match="invalid directive value"):
            baseline(content_security_policy={"directives": {"img-src": value}})


# ─── Options ────────────────────────────────────────────────────────────

ALIASES = [
    ("strict_transport_security", "hsts", "strict-transport-security"),
    ("x_content_type_options", "no_sniff", "x-content-type-options"),
    ("x_dns_prefetch_control", "dns_prefetch_control", "x-dns-prefetch-control"),
    ("x_download_options", "ie_no_open", "x-download-options"),
    ("x_frame_options", "frameguard", "x-frame-options"),
    (
        "x_permitted_cross_domain_policies",
        "permitted_cross_domain_policies",
        "x-permitted-cross-domain-policies",
    ),
    ("x_xss_protection", "xss_filter", "x-xss-protection"),
]


class TestOptions:
    @pytest.mark.parametrize("option, alias, header", ALIASES)
    def test_alias_alone_configures_the_header(self, option, alias, header):
        assert header not in as_dict(baseline(**{alias: False}).plan().headers)

    @pytest.mark.parametrize("option, alias, header", ALIASES)
    def test_option_and_alias_together_raise(self, option, alias, header):
        with pytest.raises(ValueError, match=f"specified twice. Remove the `{alias}` option"):
            baseline(**{option: True, alias: True})

    def test_hide_powered_by_alias(self):
        assert baseline(hide_powered_by=False).plan().remove == ()
        with pytest.raises(ValueError, match="specified twice"):
            baseline(x_powered_by=False, hide_powered_by=False)

    def test_none_means_default(self):
        policy = baseline(content_security_policy=None, strict_transport_security=None)
        assert as_dict(policy.plan().headers) == DEFAULT_HEADERS

    def test_unknown_option_names_are_ignored(self):
        assert as_dict(baseline(not_an_option=True).plan().headers) == DEFAULT_HEADERS

    def test_wrong_option_type_is_rejected(self):
        with pytest.raises(ValueError, match="x_frame_options option must be"):
            baseline(x_frame_options="DENY")

    def test_hsts_max_age_must_be_a_number(self):
        with pytest.raises(ValueError, match="not a valid value for max_age"):
            baseline(strict_transport_security={"max_age": "100"})

    @pytest.mark.parametrize(
        "origin",
        [
            "https://maps.example.com/",
            "https://maps.example.com:443",
            "HTTPS://maps.example.com",
            "https://user@maps.example.com",
            'https://maps.example.com"',
            "https://maps example.com",
            "ftp://maps.example.com",
            "self ",
        ],
    )
    def test_permissions_policy_rejects_non_origins(self, origin):
        with pytest.raises(ValueError, match="invalid origin"):
            baseline(permissions_policy={"geolocation": [origin]})

    def test_permissions_policy_origin_with_port(self):
        policy = baseline(permissions_policy={"geolocation": ["https://maps.example.com:8443"]})
        assert as_dict(policy.plan().headers)["permissions-policy"] == (
            'geolocation=("https://maps.example.com:8443")'
        )

    @pytest.mark.parametrize(
        "url", ['https://reports.example.com/"x', "https://reports.example.com/a b"]
    )
    def test_reporting_endpoint_rejects_unsafe_characters(self, url):
        with pytest.raises(ValueError, match="requires an https URL"):
            baseline(reporting_endpoints={"csp": url})


# ─── Profiles and adapter configuration ─────────────────────────────────

class TestProfiles:
    def test_legacy_is_the_default_profile(self):
        assert SecurityHeaders().profile == "legacy"
        assert SecurityHeaders().get_headers() == SecurityHeaders(profile="legacy").get_headers()

    def test_legacy_positional_argument_still_works(self):
        headers = SecurityHeaders("default-src 'none'").get_headers()
        assert headers["Content-Security-Policy"] == "default-src 'none'"

    def test_legacy_apply_overwrites_route_headers(self):
        starlette_responses = pytest.importorskip("starlette.responses")
        response = starlette_responses.Response("ok", headers={"X-Frame-Options": "SAMEORIGIN"})
        SecurityHeaders().apply(response)
        assert response.headers["x-frame-options"] == "DENY"

    def test_legacy_plan(self):
        plan = SecurityHeaders().plan()
        assert dict(plan.headers) == SecurityHeaders().get_headers()
        assert plan.remove == ()
        assert plan.nonce is None

    def test_unknown_profile(self):
        with pytest.raises(ValueError, match="unknown profile"):
            SecurityHeaders(profile="strict")

    def test_baseline_takes_keywords_only(self):
        with pytest.raises(TypeError):
            SecurityHeaders("default-src 'none'", profile="baseline")

    def test_baseline_get_headers(self):
        assert {k.lower(): v for k, v in baseline().get_headers().items()} == DEFAULT_HEADERS


class TestBuildSecurityHeaders:
    def test_true_is_legacy_with_csp(self):
        headers = build_security_headers(True, "default-src 'none'")
        assert headers is not None and headers.profile == "legacy"
        assert headers.get_headers()["Content-Security-Policy"] == "default-src 'none'"

    def test_false_disables(self):
        assert build_security_headers(False) is None

    def test_dict_builds_security_headers(self):
        headers = build_security_headers({"profile": "baseline", "x_frame_options": {"action": "deny"}})
        assert headers is not None and headers.profile == "baseline"
        assert headers.get_headers()["X-Frame-Options"] == "DENY"

    def test_instance_is_used_as_is(self):
        instance = baseline()
        assert build_security_headers(instance) is instance

    @pytest.mark.parametrize("headers", [{"profile": "baseline"}, SecurityHeaders()])
    def test_csp_string_cannot_be_combined_with_options(self, headers):
        with pytest.raises(ValueError, match="csp is only used with headers=True"):
            build_security_headers(headers, "default-src 'none'")

    def test_invalid_baseline_options_fail_at_construction(self):
        with pytest.raises(ValueError, match="should be quoted"):
            build_security_headers(
                {"profile": "baseline", "content_security_policy": {"directives": {"script-src": ["self"]}}}
            )
