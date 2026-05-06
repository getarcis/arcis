"""
Duration parsing and formatting tests.
Tests for arcis/utils/duration.py
"""

import pytest
from arcis.utils.duration import parse_duration, format_duration, MAX_DURATION_MS


class TestParseDurationStrings:
    """Test parsing duration strings into milliseconds."""

    def test_milliseconds(self):
        assert parse_duration('500ms') == 500

    def test_seconds(self):
        assert parse_duration('30s') == 30_000

    def test_minutes(self):
        assert parse_duration('5m') == 300_000

    def test_hours(self):
        assert parse_duration('2h') == 7_200_000

    def test_days(self):
        assert parse_duration('1d') == 86_400_000

    def test_case_insensitive(self):
        assert parse_duration('5M') == 300_000
        assert parse_duration('2H') == 7_200_000
        assert parse_duration('1D') == 86_400_000
        assert parse_duration('30S') == 30_000
        assert parse_duration('100MS') == 100

    def test_decimal_values(self):
        assert parse_duration('1.5s') == 1_500
        assert parse_duration('2.5m') == 150_000
        assert parse_duration('0.5h') == 1_800_000

    def test_strips_whitespace(self):
        assert parse_duration('  5m  ') == 300_000

    def test_zero_value(self):
        assert parse_duration('0s') == 0
        assert parse_duration('0ms') == 0


class TestParseDurationNumbers:
    """Test passthrough for numeric values."""

    def test_integer_passthrough(self):
        assert parse_duration(60000) == 60000

    def test_float_passthrough(self):
        assert parse_duration(1500.7) == 1500

    def test_zero(self):
        assert parse_duration(0) == 0

    def test_large_number_clamped(self):
        """Numbers exceeding MAX_DURATION_MS should be clamped."""
        assert parse_duration(MAX_DURATION_MS + 1000) == MAX_DURATION_MS

    def test_max_duration_exact(self):
        assert parse_duration(MAX_DURATION_MS) == MAX_DURATION_MS


class TestParseDurationErrors:
    """Test invalid inputs raise ValueError."""

    def test_empty_string(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration('')

    def test_whitespace_only(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration('   ')

    def test_no_unit(self):
        with pytest.raises(ValueError, match="Expected format"):
            parse_duration('500')

    def test_invalid_unit(self):
        with pytest.raises(ValueError, match="Expected format"):
            parse_duration('5x')

    def test_negative_number(self):
        with pytest.raises(ValueError, match="non-negative"):
            parse_duration(-1000)

    def test_nan(self):
        with pytest.raises(ValueError, match="non-negative finite"):
            parse_duration(float('nan'))

    def test_infinity(self):
        with pytest.raises(ValueError, match="non-negative finite"):
            parse_duration(float('inf'))

    def test_negative_infinity(self):
        with pytest.raises(ValueError, match="non-negative finite"):
            parse_duration(float('-inf'))

    def test_none_raises(self):
        with pytest.raises(ValueError):
            parse_duration(None)

    def test_boolean_treated_as_int(self):
        # bool is a subclass of int in Python
        assert parse_duration(True) == 1
        assert parse_duration(False) == 0

    def test_string_overflow(self):
        """String duration exceeding max should raise."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            parse_duration('100d')

    def test_letters_only(self):
        with pytest.raises(ValueError, match="Expected format"):
            parse_duration('abc')

    def test_negative_string(self):
        with pytest.raises(ValueError, match="Expected format"):
            parse_duration('-5m')


class TestFormatDuration:
    """Test formatting milliseconds into human-readable strings."""

    def test_sub_second(self):
        assert format_duration(500) == '500ms'

    def test_zero(self):
        assert format_duration(0) == '0ms'

    def test_negative(self):
        assert format_duration(-100) == '0ms'

    def test_seconds(self):
        assert format_duration(5_000) == '5s'

    def test_minutes(self):
        assert format_duration(300_000) == '5m'

    def test_hours(self):
        assert format_duration(7_200_000) == '2h'

    def test_days(self):
        assert format_duration(86_400_000) == '1d'

    def test_combined(self):
        ms = 86_400_000 + 7_200_000 + 300_000 + 5_000  # 1d 2h 5m 5s
        assert format_duration(ms) == '1d 2h 5m 5s'

    def test_hours_and_minutes(self):
        assert format_duration(5_400_000) == '1h 30m'

    def test_exact_second_boundary(self):
        assert format_duration(1_000) == '1s'

    def test_drops_zero_components(self):
        """Should not include '0h' or '0m' etc."""
        result = format_duration(86_400_000 + 5_000)  # 1d 5s
        assert result == '1d 5s'
        assert '0h' not in result
        assert '0m' not in result
