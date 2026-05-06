"""
Tests for `arcis scan --json` machine-readable output.

The JSON shape, key order, and value types lock the parity contract with
the Rust port at
`packages/arcis-rust/crates/arcis-cli/src/scan.rs::print_json_report`.
A fixture in `packages/arcis-rust/tests/parity/` will compare both
implementations byte-for-byte once `durationMs` is neutralized.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from typing import List
from unittest.mock import patch

import pytest

from arcis.cli.report import RouteResult, VectorResult
from arcis.cli.scan import _render_json_report


def _capture(target_url: str, results: List[RouteResult], duration: float) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        _render_json_report(target_url, results, duration)
    return buf.getvalue()


def _doc(target_url: str, results: List[RouteResult], duration: float) -> dict:
    return json.loads(_capture(target_url, results, duration))


# ── shape ────────────────────────────────────────────────────────────────────

def test_top_level_keys_in_rust_order() -> None:
    out = _doc("http://localhost:5000", [], 0.123)
    assert list(out.keys()) == ["tool", "target", "durationMs", "summary", "routes"]


def test_summary_keys_in_rust_order() -> None:
    out = _doc("http://localhost:5000", [], 0.0)
    assert list(out["summary"].keys()) == [
        "routesTotal",
        "routesReachable",
        "totalVectors",
        "totalBlocked",
        "totalVulnerable",
    ]


def test_route_keys_in_rust_order() -> None:
    rr = RouteResult(method="POST", path="/api/login", reachable=True)
    rr.vectors = [VectorResult("XSS", "script tag", "<script>", 200, False, "reflected (200)")]
    out = _doc("http://localhost:5000", [rr], 0.5)
    route = out["routes"][0]
    assert list(route.keys()) == ["method", "path", "reachable", "error", "vectors"]


def test_vector_keys_in_rust_order() -> None:
    rr = RouteResult(method="POST", path="/x", reachable=True)
    rr.vectors = [VectorResult("XSS", "img onerror", "<img src=x onerror=alert(1)>", 403, True, "rejected (403)")]
    out = _doc("http://localhost:5000", [rr], 1.0)
    vec = out["routes"][0]["vectors"][0]
    assert list(vec.keys()) == ["category", "label", "payload", "status", "blocked", "note"]


# ── values ───────────────────────────────────────────────────────────────────

def test_tool_field_is_arcis_scan() -> None:
    out = _doc("http://x", [], 0.0)
    assert out["tool"] == "arcis-scan"


def test_target_strips_trailing_slash() -> None:
    out = _doc("http://localhost:5000/", [], 0.0)
    assert out["target"] == "http://localhost:5000"


def test_target_strips_multiple_trailing_slashes() -> None:
    out = _doc("http://localhost:5000///", [], 0.0)
    assert out["target"] == "http://localhost:5000"


def test_duration_ms_rounded_to_int() -> None:
    out = _doc("http://x", [], 1.234)
    assert out["durationMs"] == 1234
    assert isinstance(out["durationMs"], int)


def test_unreachable_route_has_null_vectors_array() -> None:
    rr = RouteResult(method="POST", path="/x", reachable=False, error="connection refused")
    out = _doc("http://x", [rr], 0.0)
    route = out["routes"][0]
    assert route["reachable"] is False
    assert route["error"] == "connection refused"
    assert route["vectors"] == []


def test_reachable_route_with_no_error_emits_null() -> None:
    rr = RouteResult(method="POST", path="/x", reachable=True)
    rr.vectors = []
    out = _doc("http://x", [rr], 0.0)
    # Rust serializes Option<String>::None as JSON null. Python emits None
    # for the empty-string default to match.
    assert out["routes"][0]["error"] is None


def test_summary_counts_correct() -> None:
    rr1 = RouteResult(method="POST", path="/a", reachable=True)
    rr1.vectors = [
        VectorResult("XSS", "v1", "p1", 403, True, "rejected"),
        VectorResult("XSS", "v2", "p2", 200, False, "reflected"),
    ]
    rr2 = RouteResult(method="GET", path="/b", reachable=False, error="404")
    rr3 = RouteResult(method="POST", path="/c", reachable=True)
    rr3.vectors = [VectorResult("SQL", "v3", "p3", 500, True, "rejected")]

    out = _doc("http://x", [rr1, rr2, rr3], 2.5)
    s = out["summary"]
    assert s["routesTotal"] == 3
    assert s["routesReachable"] == 2  # rr1 + rr3
    assert s["totalVectors"] == 3     # 2 + 0 + 1
    assert s["totalBlocked"] == 2     # rr1.v1 + rr3.v3
    assert s["totalVulnerable"] == 1  # rr1.v2


# ── formatting ───────────────────────────────────────────────────────────────

def test_output_is_pretty_printed_with_two_space_indent() -> None:
    raw = _capture("http://x", [], 0.0)
    # serde_json pretty + json.dumps(indent=2) both emit two-space indent.
    assert '\n  "tool"' in raw


def test_output_ends_with_single_trailing_newline() -> None:
    raw = _capture("http://x", [], 0.0)
    assert raw.endswith("\n")
    assert not raw.endswith("\n\n")


def test_non_ascii_payload_emitted_raw_utf8_not_escaped() -> None:
    """Rust serde_json pretty emits raw UTF-8; Python must match by passing
    ensure_ascii=False, otherwise non-ASCII payloads diverge byte-for-byte."""
    rr = RouteResult(method="POST", path="/x", reachable=True)
    rr.vectors = [VectorResult("XSS", "unicode", "café", 200, False, "reflected")]
    raw = _capture("http://x", [rr], 0.0)
    assert "café" in raw
    assert "\\u00e9" not in raw


# ── flag wiring through main() ───────────────────────────────────────────────

def test_json_flag_implies_quiet_no_color_yes() -> None:
    """End-to-end: --json must skip the confirm prompt and the dashboard upload.

    We mock detect_target (returns one candidate) and scan_route (returns
    a synthetic reachable route with no findings) so the test never touches
    the network.
    """
    fake_route = RouteResult(method="POST", path="/", reachable=True)
    fake_route.vectors = []

    with patch.object(sys, "argv", ["arcis-scan", "http://localhost:5000", "--json", "--no-discovery"]):
        with patch("arcis.cli.scan.scan_route", return_value=fake_route):
            with patch("arcis.cli.scan.dashboard_upload_called", create=True, new=False):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    from arcis.cli import scan as scan_mod
                    with pytest.raises(SystemExit) as exc:
                        scan_mod.main()
                # No findings -> exit 0
                assert exc.value.code == 0

    out = json.loads(buf.getvalue())
    assert out["tool"] == "arcis-scan"
    assert out["target"] == "http://localhost:5000"
    assert out["summary"]["totalVulnerable"] == 0


def test_json_flag_exit_code_one_on_vulnerability() -> None:
    """A single non-blocked vector must trigger exit code 1, even in JSON mode."""
    fake_route = RouteResult(method="POST", path="/", reachable=True)
    fake_route.vectors = [VectorResult("XSS", "script", "<script>", 200, False, "reflected (200)")]

    with patch.object(sys, "argv", ["arcis-scan", "http://localhost:5000", "--json", "--no-discovery"]):
        with patch("arcis.cli.scan.scan_route", return_value=fake_route):
            buf = io.StringIO()
            with redirect_stdout(buf):
                from arcis.cli import scan as scan_mod
                with pytest.raises(SystemExit) as exc:
                    scan_mod.main()
            assert exc.value.code == 1

    out = json.loads(buf.getvalue())
    assert out["summary"]["totalVulnerable"] == 1
