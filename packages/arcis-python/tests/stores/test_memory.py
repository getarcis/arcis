"""
InMemoryStore tests — extracted from tests/test_core.py.
"""

import time
from arcis.core import InMemoryStore


class TestInMemoryStore:
    """Test in-memory rate limit store."""

    def test_set_and_get(self):
        """Should store and retrieve values."""
        store = InMemoryStore()
        store.set("test_key", 5, time.time() + 60)

        entry = store.get("test_key")
        assert entry is not None
        assert entry.count == 5

    def test_increment(self):
        """Should increment count."""
        store = InMemoryStore()
        store.set("test_key", 1, time.time() + 60)

        new_count = store.increment("test_key")
        assert new_count == 2

    def test_expired_entries_removed(self):
        """Expired entries should be removed on get."""
        store = InMemoryStore()
        store.set("test_key", 1, time.time() - 1)  # Already expired

        entry = store.get("test_key")
        assert entry is None

    def test_cleanup(self):
        """Cleanup should remove expired entries."""
        store = InMemoryStore()
        store.set("expired", 1, time.time() - 1)
        store.set("valid", 1, time.time() + 60)

        store.cleanup()

        assert store.get("expired") is None
        assert store.get("valid") is not None
