"""Phase 3 Optimization Tests — Object freeze and early-exit log levels."""

import logging
import types
import pytest
from arcis.sanitizers.sanitize import Sanitizer
from arcis.logging.safe_logger import SafeLogger


# ─── Object freeze (MappingProxyType) ────────────────────────────────────────


class TestFreeze:
    def test_no_freeze_by_default(self):
        s = Sanitizer()
        result = s.sanitize_dict({"name": "John"})
        assert isinstance(result, dict)
        result["name"] = "Jane"  # should work
        assert result["name"] == "Jane"

    def test_freeze_returns_mapping_proxy(self):
        s = Sanitizer(freeze=True)
        result = s.sanitize_dict({"name": "John"})
        assert isinstance(result, types.MappingProxyType)

    def test_frozen_dict_is_immutable(self):
        s = Sanitizer(freeze=True)
        result = s.sanitize_dict({"name": "John", "age": 30})
        with pytest.raises(TypeError):
            result["name"] = "Jane"

    def test_freeze_with_stripped_keys(self):
        s = Sanitizer(freeze=True)
        result = s.sanitize_dict({"name": "John", "__proto__": {"admin": True}})
        assert isinstance(result, types.MappingProxyType)
        assert "name" in result
        assert "__proto__" not in result

    def test_freeze_with_string_input(self):
        s = Sanitizer(freeze=True)
        result = s.sanitize_dict("hello")
        assert result == "hello"  # strings aren't frozen

    def test_no_freeze_on_nested_recursion(self):
        """Only top-level dict should be frozen, not intermediate recursion."""
        s = Sanitizer(freeze=True)
        result = s.sanitize_dict({"user": {"name": "John"}})
        assert isinstance(result, types.MappingProxyType)
        # Nested dict is a regular dict (frozen by proxy wrapper)
        assert result["user"]["name"] == "John"


# ─── Early-exit log levels ───────────────────────────────────────────────────


class TestEarlyExitLogLevels:
    def test_debug_skipped_when_level_is_info(self):
        """Early exit should prevent redaction work for skipped levels."""
        logger = SafeLogger(name="test_skip_info")
        logger.logger.setLevel(logging.INFO)

        # Mock _redact to track if it gets called
        call_count = 0
        original_redact = logger._redact
        def counting_redact(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return original_redact(*args, **kwargs)
        logger._redact = counting_redact

        logger.debug("should be skipped")
        assert call_count == 0, "Redaction should not run for skipped debug level"

        logger.info("should run")
        assert call_count > 0, "Redaction should run for info level"

    def test_debug_and_info_skipped_when_level_is_warning(self):
        """Levels below warning should skip redaction entirely."""
        logger = SafeLogger(name="test_skip_warn")
        logger.logger.setLevel(logging.WARNING)

        call_count = 0
        original_redact = logger._redact
        def counting_redact(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return original_redact(*args, **kwargs)
        logger._redact = counting_redact

        logger.debug("skip")
        logger.info("skip")
        assert call_count == 0

        logger.warning("should run")
        assert call_count > 0

    def test_early_exit_performance(self):
        """Skipped log calls should be very fast (no redaction work)."""
        import time

        logger = SafeLogger(name="test_perf")
        logger.logger.setLevel(logging.ERROR)

        start = time.perf_counter()
        for _ in range(10000):
            logger.debug("password=secret", {"password": "secret123", "token": "abc"})
        elapsed = time.perf_counter() - start

        # 10k skipped calls should be < 50ms
        assert elapsed < 0.05, f"Early exit took {elapsed:.3f}s, expected < 0.05s"

    def test_all_levels_logged_at_debug(self, caplog):
        logger = SafeLogger(name="test_all")
        logger.logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.DEBUG, logger="test_all"):
            logger.debug("d")
            logger.info("i")
            logger.warning("w")
            logger.error("e")

        assert len(caplog.records) == 4
