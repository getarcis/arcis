"""
Redis store tests.

Contract and multi-instance tests run against a real Redis at ``REDIS_URL``
(CI starts a redis:7 service). Keys use the ``arcis-py-test:`` prefix plus a
per-test id and are deleted afterwards; the database is never flushed.
Error-path tests need only the ``redis`` package (they point at a closed
port).
"""

import asyncio
import logging
import os
import threading
import time
import uuid

import pytest

redis = pytest.importorskip("redis", reason="redis extra not installed (pip install arcis[redis])")
import redis.asyncio as redis_asyncio  # noqa: E402

from arcis.async_rate_limit import AsyncRateLimiter, AsyncRateLimitExceeded  # noqa: E402
from arcis.middleware import rate_limit as rate_limit_module  # noqa: E402
from arcis.middleware.rate_limit import RateLimiter, RateLimitExceeded  # noqa: E402
from arcis.stores.redis import AsyncRedisRateLimitStore, RedisRateLimitStore  # noqa: E402

REDIS_URL = os.environ.get("REDIS_URL")
needs_redis = pytest.mark.skipif(
    not REDIS_URL, reason="REDIS_URL is not set; start Redis and export REDIS_URL to run"
)
UNREACHABLE_URL = "redis://127.0.0.1:1/0"


async def _aclose(client) -> None:
    # redis-py 5 renamed the async client's close() to aclose().
    await getattr(client, "aclose", client.close)()


class _Req:
    def __init__(self, ip: str = "192.0.2.10") -> None:
        self.remote_addr = ip


@pytest.fixture
def prefix():
    """Unique key prefix; deletes only this test's keys afterwards."""
    value = f"arcis-py-test:{uuid.uuid4().hex}:"
    yield value
    if REDIS_URL:
        client = redis.Redis.from_url(REDIS_URL)
        try:
            keys = list(client.scan_iter(match=f"{value}*"))
            if keys:
                client.delete(*keys)
        finally:
            client.close()


@pytest.fixture
def sync_client():
    client = redis.Redis.from_url(REDIS_URL)
    yield client
    client.close()


# ─── Store contract ─────────────────────────────────────────────────────────


@needs_redis
class TestRedisStoreContract:
    def test_increment_sets_expiry_on_first_hit(self, sync_client, prefix):
        store = RedisRateLimitStore(sync_client, key_prefix=prefix)
        before = time.time()
        hits, reset_time = store.increment("k", 5_000)
        assert hits == 1
        assert before < reset_time <= time.time() + 5.0
        ttl = sync_client.pttl(f"{prefix}k")
        assert 0 < ttl <= 5_000

    def test_window_is_fixed_from_first_hit(self, sync_client, prefix):
        store = RedisRateLimitStore(sync_client, key_prefix=prefix)
        _, first_reset = store.increment("k", 5_000)
        time.sleep(0.05)
        hits, reset_time = store.increment("k", 5_000)
        assert hits == 2
        assert abs(reset_time - first_reset) < 0.05

    def test_counter_expires_with_window(self, sync_client, prefix):
        store = RedisRateLimitStore(sync_client, key_prefix=prefix)
        store.increment("k", 100)
        store.increment("k", 100)
        time.sleep(0.25)
        assert store.increment("k", 100)[0] == 1

    def test_decrement_get_and_reset(self, sync_client, prefix):
        store = RedisRateLimitStore(sync_client, key_prefix=prefix)
        assert store.get("k") is None
        store.increment("k", 60_000)
        store.increment("k", 60_000)
        store.decrement("k")
        assert store.get("k").count == 1
        store.decrement("k")
        store.decrement("k")
        assert store.get("k").count == 0
        store.reset_key("k")
        assert store.get("k") is None

    def test_old_hash_entry_is_replaced(self, sync_client, prefix):
        sync_client.hset(f"{prefix}k", mapping={"count": 7, "reset_time": 1})
        store = RedisRateLimitStore(sync_client, key_prefix=prefix)
        assert store.increment("k", 60_000)[0] == 1

    def test_async_store_contract(self, prefix):
        async def run():
            client = redis_asyncio.Redis.from_url(REDIS_URL)
            try:
                store = AsyncRedisRateLimitStore(client, key_prefix=prefix)
                assert (await store.increment("k", 60_000))[0] == 1
                assert (await store.increment("k", 60_000))[0] == 2
                await store.decrement("k")
                assert (await store.get("k")).count == 1
                await store.reset_key("k")
                assert await store.get("k") is None
            finally:
                await _aclose(client)

        asyncio.run(run())


# ─── Multi-instance concurrency ─────────────────────────────────────────────


@needs_redis
class TestRedisConcurrency:
    INSTANCES = 5
    REQUESTS = 50
    MAX = 5

    def test_sync_limiters_in_threads_admit_exactly_max(self, prefix):
        clients = [redis.Redis.from_url(REDIS_URL) for _ in range(self.INSTANCES)]
        limiters = [
            RateLimiter(
                max_requests=self.MAX,
                window_ms=60_000,
                store=RedisRateLimitStore(client, key_prefix=prefix),
            )
            for client in clients
        ]
        barrier = threading.Barrier(self.REQUESTS)
        allowed = []
        lock = threading.Lock()

        def one(index: int) -> None:
            limiter = limiters[index % self.INSTANCES]
            barrier.wait()
            try:
                limiter.check(_Req())
                result = True
            except RateLimitExceeded:
                result = False
            with lock:
                allowed.append(result)

        threads = [threading.Thread(target=one, args=(i,)) for i in range(self.REQUESTS)]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            for limiter in limiters:
                limiter.close()
            for client in clients:
                client.close()
        assert len(allowed) == self.REQUESTS
        assert sum(allowed) == self.MAX

    def test_async_limiters_with_gather_admit_exactly_max(self, prefix):
        async def run():
            clients = [redis_asyncio.Redis.from_url(REDIS_URL) for _ in range(self.INSTANCES)]
            limiters = [
                AsyncRateLimiter(
                    max_requests=self.MAX,
                    window_ms=60_000,
                    store=AsyncRedisRateLimitStore(client, key_prefix=prefix),
                )
                for client in clients
            ]

            async def one(index: int) -> bool:
                try:
                    await limiters[index % self.INSTANCES].check(_Req())
                    return True
                except AsyncRateLimitExceeded:
                    return False

            try:
                return await asyncio.gather(*[one(i) for i in range(self.REQUESTS)])
            finally:
                for limiter in limiters:
                    await limiter.close()
                for client in clients:
                    await _aclose(client)

        results = asyncio.run(run())
        assert len(results) == self.REQUESTS
        assert sum(results) == self.MAX


# ─── Store errors reach the limiter ─────────────────────────────────────────


def _error_records(caplog):
    return [r for r in caplog.records if "store error" in r.getMessage()]


class TestRedisStoreErrors:
    def test_store_raises_instead_of_swallowing(self):
        client = redis.Redis.from_url(UNREACHABLE_URL, socket_connect_timeout=0.2)
        store = RedisRateLimitStore(client)
        # Refused on Linux, a connect timeout on some Windows hosts.
        with pytest.raises(redis.exceptions.RedisError):
            store.increment("k", 60_000)

    def test_sync_limiter_falls_back_to_memory_and_reports_once(self, caplog):
        client = redis.Redis.from_url(UNREACHABLE_URL, socket_connect_timeout=0.2)
        limiter = RateLimiter(max_requests=1, window_ms=60_000, store=RedisRateLimitStore(client))
        try:
            with caplog.at_level(logging.ERROR, logger=rate_limit_module.__name__):
                assert limiter.check(_Req("192.0.2.20"))["allowed"] is True
                # Before the fix the Redis store swallowed the error and
                # returned 1, so this second request was allowed too.
                with pytest.raises(RateLimitExceeded):
                    limiter.check(_Req("192.0.2.20"))
            assert len(_error_records(caplog)) == 1
        finally:
            limiter.close()

    def test_async_limiter_fails_open_and_reports_once(self, caplog):
        async def run():
            client = redis_asyncio.Redis.from_url(UNREACHABLE_URL, socket_connect_timeout=0.2)
            limiter = AsyncRateLimiter(
                max_requests=1, window_ms=60_000, store=AsyncRedisRateLimitStore(client)
            )
            try:
                return [(await limiter.check(_Req()))["allowed"] for _ in range(3)]
            finally:
                await limiter.close()
                await _aclose(client)

        with caplog.at_level(logging.ERROR, logger=rate_limit_module.__name__):
            assert asyncio.run(run()) == [True, True, True]
        assert len(_error_records(caplog)) == 1
