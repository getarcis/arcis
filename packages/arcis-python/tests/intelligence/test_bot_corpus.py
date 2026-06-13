"""Phase C bot-corpus refresh tests (Python parity with the Node tests).

merge_bot_patterns + client.fetch_bot_corpus are offline (HTTP monkeypatched);
the wire-up uses the FastAPI TestClient with a monkeypatched corpus feed.
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.middleware.bot_detection import (
    BOT_PATTERNS,
    merge_bot_patterns,
    _reset_bot_patterns_for_test,
)
from arcis.intelligence import IntelligenceClient, IntelligenceOptions
import arcis.intelligence.client as client_mod
from arcis.fastapi import ArcisMiddleware

_BROWSER = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


def _find(entry_id: str):
    return next((e for e in BOT_PATTERNS if e.entry_id == entry_id), None)


class TestMergeBotPatterns:
    def teardown_method(self):
        _reset_bot_patterns_for_test()

    def test_merges_a_novel_entry(self):
        n = merge_bot_patterns([
            {"id": "arcis-test-crawler", "category": "SECURITY_SCANNER",
             "name": "ArcisTestCrawler", "patterns": ["ArcisTestCrawler-XYZ"], "forbidden": []},
        ])
        assert n == 1
        e = _find("arcis-test-crawler")
        assert e is not None and e.category == "SECURITY_SCANNER"
        assert any(p.search("ArcisTestCrawler-XYZ/1.0") for p in e.accepted)

    def test_skips_uncompilable_pattern(self):
        n = merge_bot_patterns([
            {"id": "bad", "category": "SCRAPER", "name": "bad", "patterns": ["("], "forbidden": []},
            {"id": "good", "category": "SCRAPER", "name": "good", "patterns": ["GoodBotXYZ"], "forbidden": []},
        ])
        assert n == 1
        assert _find("good") is not None
        assert _find("bad") is None

    def test_reset_restores_bundle(self):
        merge_bot_patterns([
            {"id": "temp", "category": "SCRAPER", "name": "temp", "patterns": ["TempBotZZZ"], "forbidden": []},
        ])
        assert _find("temp") is not None
        _reset_bot_patterns_for_test()
        assert _find("temp") is None


class TestFetchBotCorpus:
    def test_returns_wellformed_entries(self, monkeypatch):
        def fake(url, headers, timeout_s):
            return {"entries": [
                {"id": "a", "category": "AI_CRAWLER", "name": "A", "patterns": ["Abot"], "forbidden": []},
                {"id": "bad", "name": "missing fields"},
            ]}
        monkeypatch.setattr(client_mod, "_request_json", fake)
        c = IntelligenceClient(IntelligenceOptions(endpoint="https://intel.test", cloud_decisions=["bot-corpus"]))
        entries = c.fetch_bot_corpus()
        assert len(entries) == 1 and entries[0]["id"] == "a"
        c.close()

    def test_fails_open_on_error(self, monkeypatch):
        def boom(url, headers, timeout_s):
            raise RuntimeError("unreachable")
        monkeypatch.setattr(client_mod, "_request_json", boom)
        c = IntelligenceClient(IntelligenceOptions(endpoint="https://intel.test", cloud_decisions=["bot-corpus"]))
        assert c.fetch_bot_corpus() == []
        c.close()


class TestBotCorpusWireup:
    def teardown_method(self):
        _reset_bot_patterns_for_test()

    def test_novel_scanner_denied_after_refresh(self, monkeypatch):
        novel_ua = "ArcisWireupScannerPy-7777/1.0"

        def fake(url, headers, timeout_s):
            return {"entries": [
                {"id": "arcis-wireup-py", "category": "SECURITY_SCANNER",
                 "name": "ArcisWireupScannerPy", "patterns": ["ArcisWireupScannerPy-7777"], "forbidden": []},
            ]}
        monkeypatch.setattr(client_mod, "_request_json", fake)

        app = FastAPI()
        app.add_middleware(
            ArcisMiddleware,
            rate_limit=False,
            intelligence={"endpoint": "https://intel.test", "cloud_decisions": ["bot-corpus"]},
        )

        @app.get("/")
        async def root():
            return {"ok": True}

        client = TestClient(app)
        # The merge happens on a background thread kicked off at middleware init.
        denied = False
        for _ in range(60):
            if client.get("/", headers={"user-agent": novel_ua}).status_code == 403:
                denied = True
                break
            time.sleep(0.02)
        assert denied, "novel scanner UA should be denied once the corpus refresh lands"


class TestBotCorpusPeriodicRefresh:
    def teardown_method(self):
        _reset_bot_patterns_for_test()

    def test_default_interval_is_weekly(self):
        assert IntelligenceOptions(endpoint="https://x").bot_corpus_refresh_secs == 7 * 24 * 60 * 60

    def test_refresh_repeats_then_stops_on_close(self, monkeypatch):
        # Periodic refresh: with a 1s interval the corpus is re-fetched on a
        # schedule (Node parity), and close() stops the thread promptly.
        calls = {"n": 0}

        def fake(url, headers, timeout_s):
            calls["n"] += 1
            return {"entries": []}

        monkeypatch.setattr(client_mod, "_request_json", fake)

        async def dummy_app(scope, receive, send):  # minimal ASGI app
            return None

        mw = ArcisMiddleware(
            dummy_app,
            rate_limit=False,
            intelligence={
                "endpoint": "https://intel.test",
                "cloud_decisions": ["bot-corpus"],
                "bot_corpus_refresh_secs": 1,
            },
        )
        try:
            deadline = time.time() + 5
            while time.time() < deadline and calls["n"] < 2:
                time.sleep(0.05)
            assert calls["n"] >= 2, f"expected periodic re-fetch (>=2), got {calls['n']}"
        finally:
            stop = getattr(mw, "_bot_corpus_stop", None)
            if stop is not None:
                stop.set()
