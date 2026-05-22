"""Stateful per-IP correlation window (improvements.md §1.3).

The window is a building block: callers feed it events and pull
detection booleans. These tests pin the contract.
"""
import pytest

from arcis.middleware.correlation import (
    CorrelationDetections,
    CorrelationWindow,
)


# ---------------------------------------------------------------- recording


def test_record_returns_detections_dataclass():
    w = CorrelationWindow()
    out = w.record("1.1.1.1", "xss", "/api", "POST")
    assert isinstance(out, CorrelationDetections)
    assert out.requests_in_window == 1
    assert out.distinct_vectors == 1
    assert out.scanner is False


def test_empty_ip_is_a_no_op():
    w = CorrelationWindow()
    out = w.record("", "xss", "/api")
    assert out.requests_in_window == 0
    assert w.stats()["tracked_ips"] == 0


def test_record_with_explicit_now_is_used():
    w = CorrelationWindow(window_seconds=60)
    w.record("a", "xss", "/x", now=1000.0)
    w.record("a", "sql", "/x", now=1001.0)
    out = w.record("a", "path", "/x", now=1002.0)
    assert out.distinct_vectors == 3
    assert out.requests_in_window == 3


# ----------------------------------------------------------- scanner detect


def test_scanner_threshold_requires_distinct_vectors_and_requests():
    w = CorrelationWindow(
        scanner_distinct_vectors=3, scanner_min_requests=10, window_seconds=60
    )
    # 10 hits on one vector = not a scanner.
    for i in range(10):
        out = w.record("a", "xss", "/x", now=1000.0 + i)
    assert out.scanner is False

    # Add 3 distinct vectors over 20+ requests = scanner.
    w2 = CorrelationWindow(
        scanner_distinct_vectors=3, scanner_min_requests=10, window_seconds=60
    )
    vectors = ["xss", "sql", "path", "command"]
    for i in range(20):
        out = w2.record("a", vectors[i % len(vectors)], "/x", now=1000.0 + i)
    assert out.scanner is True
    assert out.distinct_vectors >= 3


def test_scanner_resets_when_window_expires():
    w = CorrelationWindow(
        scanner_distinct_vectors=2, scanner_min_requests=3, window_seconds=10
    )
    # Build scanner state at t=1000.
    w.record("a", "xss", "/x", now=1000.0)
    w.record("a", "sql", "/x", now=1000.5)
    out = w.record("a", "path", "/x", now=1001.0)
    assert out.scanner is True
    # Wait past the window; new lone request should NOT register as scanner.
    out = w.record("a", "xss", "/x", now=1100.0)
    assert out.scanner is False


# ----------------------------------------------------- credential stuffing


def test_credential_stuffing_counts_distinct_usernames_per_route():
    w = CorrelationWindow(credential_stuffing_distinct_values=5, window_seconds=60)
    for i in range(4):
        out = w.record(
            "a", "login", "/login", "POST", distinct_value=f"user{i}@x.com", now=1000.0 + i
        )
    assert out.credential_stuffing is False
    # Fifth distinct value crosses the threshold.
    out = w.record(
        "a", "login", "/login", "POST", distinct_value="user4@x.com", now=1005.0
    )
    assert out.credential_stuffing is True


def test_credential_stuffing_does_not_cross_routes():
    w = CorrelationWindow(credential_stuffing_distinct_values=3, window_seconds=60)
    # Mix of usernames across two different routes.
    w.record("a", "login", "/login", "POST", distinct_value="x@y.com", now=1000)
    w.record("a", "login", "/login", "POST", distinct_value="y@y.com", now=1001)
    out = w.record(
        "a", "login", "/admin/login", "POST", distinct_value="z@y.com", now=1002
    )
    assert out.credential_stuffing is False


def test_credential_stuffing_repeat_value_does_not_count():
    w = CorrelationWindow(credential_stuffing_distinct_values=3, window_seconds=60)
    for i in range(10):
        out = w.record(
            "a", "login", "/login", "POST", distinct_value="same@x.com", now=1000 + i
        )
    assert out.credential_stuffing is False


# -------------------------------------------------------------- race window


def test_race_window_pair_detected_within_threshold():
    w = CorrelationWindow(
        window_seconds=60,
        race_window_ms=200,
        race_pairs=[("/transfer", "/balance")],
    )
    w.record("a", "request", "/transfer", "POST", now=1000.000)
    out = w.record("a", "request", "/balance", "GET", now=1000.150)
    assert out.race_window is True


def test_race_window_pair_outside_threshold_is_not_a_race():
    w = CorrelationWindow(
        window_seconds=60,
        race_window_ms=200,
        race_pairs=[("/transfer", "/balance")],
    )
    w.record("a", "request", "/transfer", "POST", now=1000.000)
    out = w.record("a", "request", "/balance", "GET", now=1000.500)
    assert out.race_window is False


def test_race_window_ad_hoc_check_works_without_preregistration():
    w = CorrelationWindow(window_seconds=60, race_window_ms=200)
    w.record("a", "request", "/foo", "POST", now=1000.0)
    w.record("a", "request", "/bar", "GET", now=1000.05)
    # No pair pre-registered, but explicit detect_race_window call still
    # answers correctly.
    assert w.detect_race_window("a", ("/foo", "/bar"), now=1000.06) is True
    assert w.detect_race_window("a", ("/foo", "/baz"), now=1000.06) is False


# ------------------------------------------------ eviction + memory bounds


def test_oldest_ip_evicted_when_max_ips_exceeded():
    w = CorrelationWindow(max_ips=3)
    w.record("a", "xss", "/x")
    w.record("b", "xss", "/x")
    w.record("c", "xss", "/x")
    w.record("d", "xss", "/x")  # forces eviction of "a"
    s = w.stats()
    assert s["tracked_ips"] == 3
    assert w.detect_scanner("a") is False  # a was evicted -> no state


def test_per_ip_event_cap_enforced():
    w = CorrelationWindow(max_events_per_ip=5, window_seconds=3600)
    for i in range(20):
        w.record("a", "xss", "/x", now=1000.0 + i)
    s = w.stats()
    # Only 5 events kept per IP.
    assert s["events_in_window"] == 5


def test_stale_events_outside_window_are_dropped():
    w = CorrelationWindow(window_seconds=10)
    w.record("a", "xss", "/x", now=1000.0)
    w.record("a", "sql", "/x", now=1003.0)
    out = w.record("a", "path", "/x", now=1009.0)
    # All three events fall inside the 10s window.
    assert out.requests_in_window == 3
    assert out.distinct_vectors == 3
    # Fast-forward 100s; one fresh event = 1 in window, two prior dropped.
    out = w.record("a", "command", "/x", now=1109.0)
    assert out.requests_in_window == 1
    assert out.distinct_vectors == 1


# --------------------------------------------------- reset + read-only API


def test_reset_clears_single_ip():
    w = CorrelationWindow()
    w.record("a", "xss", "/x")
    w.record("b", "xss", "/x")
    w.reset("a")
    assert w.detect_scanner("a") is False
    assert w.stats()["tracked_ips"] == 1


def test_reset_all_clears_every_ip():
    w = CorrelationWindow()
    w.record("a", "xss", "/x")
    w.record("b", "xss", "/x")
    w.reset()
    assert w.stats()["tracked_ips"] == 0


def test_detect_scanner_does_not_mutate_state():
    w = CorrelationWindow(scanner_distinct_vectors=2, scanner_min_requests=3)
    for v in ["xss", "sql", "path"]:
        w.record("a", v, "/x", now=1000.0)
    before = w.stats()["events_in_window"]
    w.detect_scanner("a", now=1001.0)
    after = w.stats()["events_in_window"]
    assert before == after


# -------------------------------------------------- constructor validation


@pytest.mark.parametrize("kw", [{"window_seconds": 0}, {"max_ips": 0}, {"max_events_per_ip": 0}])
def test_constructor_rejects_invalid_bounds(kw):
    with pytest.raises(ValueError):
        CorrelationWindow(**kw)


def test_distinct_values_only_count_for_current_route():
    w = CorrelationWindow(window_seconds=60)
    w.record("a", "login", "/login", "POST", distinct_value="x@y.com", now=1000.0)
    w.record(
        "a", "login", "/admin/login", "POST", distinct_value="y@y.com", now=1001.0
    )
    out = w.record(
        "a", "login", "/login", "POST", distinct_value="z@y.com", now=1002.0
    )
    # Two of the three events targeted /login with distinct values.
    assert out.distinct_values == 2
