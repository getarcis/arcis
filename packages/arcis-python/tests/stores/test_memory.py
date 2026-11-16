"""
InMemoryStore tests: atomic increment contract, decrement, reset, and the
size-cap eviction that keeps limiting new keys.
"""

import threading
import time

import pytest

from arcis.core import InMemoryStore


class TestInMemoryStore:
    """Test in-memory rate limit store."""

    def test_increment_creates_counter_with_expiry(self):
        store = InMemoryStore()
        before = time.time()
        hits, reset_time = store.increment("k", 60_000)
        assert hits == 1
        assert before + 60 <= reset_time <= time.time() + 60

    def test_increment_counts_within_window(self):
        store = InMemoryStore()
        _, first_reset = store.increment("k", 60_000)
        hits, reset_time = store.increment("k", 60_000)
        assert hits == 2
        assert reset_time == first_reset

    def test_window_restarts_after_expiry(self):
        store = InMemoryStore()
        store.increment("k", 20)
        store.increment("k", 20)
        time.sleep(0.05)
        hits, _ = store.increment("k", 20)
        assert hits == 1

    def test_get_returns_copy_or_none(self):
        store = InMemoryStore()
        assert store.get("k") is None
        store.increment("k", 60_000)
        entry = store.get("k")
        assert entry is not None and entry.count == 1
        entry.count = 99
        assert store.get("k").count == 1

    def test_expired_entries_removed_on_get(self):
        store = InMemoryStore()
        store.increment("k", 1)
        time.sleep(0.01)
        assert store.get("k") is None

    def test_decrement_floors_at_zero(self):
        store = InMemoryStore()
        store.increment("k", 60_000)
        store.decrement("k")
        store.decrement("k")
        assert store.get("k").count == 0
        store.decrement("missing")

    def test_reset_key(self):
        store = InMemoryStore()
        store.increment("k", 60_000)
        store.reset_key("k")
        assert store.get("k") is None

    def test_cleanup(self):
        store = InMemoryStore()
        store.increment("expired", 1)
        store.increment("valid", 60_000)
        time.sleep(0.01)
        store.cleanup()
        assert store.get("expired") is None
        assert store.get("valid") is not None

    def test_increment_is_atomic_across_threads(self):
        store = InMemoryStore()
        barrier = threading.Barrier(20)
        results = []

        def worker():
            barrier.wait()
            for _ in range(50):
                results.append(store.increment("shared", 60_000)[0])

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == list(range(1, 1001))

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5])
    def test_invalid_max_size(self, bad):
        with pytest.raises(ValueError):
            InMemoryStore(max_size=bad)


class TestInMemoryStoreCap:
    """At the size cap the store evicts and keeps limiting (never fails open)."""

    def test_new_key_is_still_counted_when_full_of_live_keys(self):
        store = InMemoryStore(max_size=3)
        for key in ("a", "b", "c"):
            store.increment(key, 60_000)
        assert store.increment("new", 60_000)[0] == 1
        assert store.increment("new", 60_000)[0] == 2
        assert store.increment("new", 60_000)[0] == 3

    def test_evicts_least_recently_used(self):
        store = InMemoryStore(max_size=3)
        for key in ("a", "b", "c"):
            store.increment(key, 60_000)
        store.increment("a", 60_000)  # "b" is now least recently used
        store.increment("d", 60_000)
        assert store.get("b") is None
        assert store.get("a").count == 2
        assert store.get("c") is not None
        assert store.get("d") is not None

    def test_evicts_expired_before_live(self):
        store = InMemoryStore(max_size=3)
        store.increment("live-old", 60_000)
        store.increment("expired", 1)
        store.increment("live-new", 60_000)
        time.sleep(0.01)
        store.increment("incoming", 60_000)
        assert store.get("live-old") is not None
        assert store.get("live-new") is not None
        assert store.get("incoming") is not None
