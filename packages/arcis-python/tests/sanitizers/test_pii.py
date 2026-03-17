"""Tests for arcis.sanitizers.pii — PII detection and redaction."""

import pytest
from arcis.sanitizers.pii import (
    scan_pii,
    detect_pii,
    redact_pii,
    scan_object_pii,
    redact_object_pii,
)


# ─── scan_pii ─────────────────────────────────────────────────────────────────


class TestScanPiiEmail:
    def test_detect_standard_email(self):
        matches = scan_pii("Contact john@example.com for info")
        assert len(matches) == 1
        assert matches[0].type == "email"
        assert matches[0].value == "john@example.com"

    def test_detect_multiple_emails(self):
        matches = scan_pii("From alice@test.com to bob@corp.org")
        assert len(matches) == 2
        assert matches[0].value == "alice@test.com"
        assert matches[1].value == "bob@corp.org"

    def test_detect_email_with_dots_and_plus(self):
        matches = scan_pii("Email: first.last+tag@sub.domain.co.uk")
        assert len(matches) == 1
        assert matches[0].value == "first.last+tag@sub.domain.co.uk"

    def test_no_match_partial_email(self):
        matches = scan_pii("user@ or @domain.com", types=["email"])
        assert len(matches) == 0


class TestScanPiiPhone:
    def test_detect_phone_with_dashes(self):
        matches = scan_pii("Call 555-123-4567", types=["phone"])
        assert len(matches) == 1
        assert matches[0].value == "555-123-4567"

    def test_detect_phone_with_parens(self):
        matches = scan_pii("Phone: (555) 123-4567", types=["phone"])
        assert len(matches) == 1
        assert matches[0].value == "(555) 123-4567"

    def test_detect_phone_with_dots(self):
        matches = scan_pii("Call 555.123.4567", types=["phone"])
        assert len(matches) == 1
        assert matches[0].value == "555.123.4567"

    def test_detect_phone_with_country_code(self):
        matches = scan_pii("Call +1-555-123-4567", types=["phone"])
        assert len(matches) == 1
        assert matches[0].value == "+1-555-123-4567"

    def test_reject_invalid_area_code(self):
        matches = scan_pii("ID: 012-345-6789", types=["phone"])
        assert len(matches) == 0


class TestScanPiiCreditCard:
    def test_detect_visa(self):
        matches = scan_pii("Card: 4111111111111111", types=["credit_card"])
        assert len(matches) == 1
        assert matches[0].type == "credit_card"

    def test_detect_card_with_spaces(self):
        matches = scan_pii("Card: 4111 1111 1111 1111", types=["credit_card"])
        assert len(matches) == 1

    def test_detect_card_with_dashes(self):
        matches = scan_pii("Card: 4111-1111-1111-1111", types=["credit_card"])
        assert len(matches) == 1

    def test_reject_invalid_luhn(self):
        matches = scan_pii("Not a card: 1234567890123456", types=["credit_card"])
        assert len(matches) == 0

    def test_detect_mastercard(self):
        matches = scan_pii("MC: 5500000000000004", types=["credit_card"])
        assert len(matches) == 1

    def test_detect_amex(self):
        matches = scan_pii("Amex: 378282246310005", types=["credit_card"])
        assert len(matches) == 1


class TestScanPiiSsn:
    def test_detect_ssn_with_dashes(self):
        matches = scan_pii("SSN: 123-45-6789", types=["ssn"])
        assert len(matches) == 1
        assert matches[0].value == "123-45-6789"

    def test_detect_ssn_with_spaces(self):
        matches = scan_pii("SSN: 123 45 6789", types=["ssn"])
        assert len(matches) == 1

    def test_reject_ssn_starting_000(self):
        matches = scan_pii("Invalid: 000-12-3456", types=["ssn"])
        assert len(matches) == 0

    def test_reject_ssn_starting_666(self):
        matches = scan_pii("Invalid: 666-12-3456", types=["ssn"])
        assert len(matches) == 0

    def test_reject_ssn_starting_900_plus(self):
        matches = scan_pii("Invalid: 900-12-3456", types=["ssn"])
        assert len(matches) == 0


class TestScanPiiIp:
    def test_detect_ipv4(self):
        matches = scan_pii("Server at 192.168.1.100", types=["ip_address"])
        assert len(matches) == 1
        assert matches[0].value == "192.168.1.100"

    def test_detect_multiple_ips(self):
        matches = scan_pii("From 10.0.0.1 to 172.16.0.1", types=["ip_address"])
        assert len(matches) == 2

    def test_reject_invalid_octets(self):
        matches = scan_pii("Not IP: 999.999.999.999", types=["ip_address"])
        assert len(matches) == 0


class TestScanPiiMixed:
    def test_detect_multiple_types(self):
        input_str = "Email john@test.com, call 555-123-4567, SSN 123-45-6789"
        matches = scan_pii(input_str)
        types = [m.type for m in matches]
        assert "email" in types
        assert "phone" in types
        assert "ssn" in types

    def test_matches_sorted_by_position(self):
        matches = scan_pii("SSN: 123-45-6789, email: z@test.com")
        for i in range(1, len(matches)):
            assert matches[i].start >= matches[i - 1].start

    def test_filter_by_type(self):
        input_str = "Email john@test.com, SSN 123-45-6789"
        matches = scan_pii(input_str, types=["email"])
        assert len(matches) == 1
        assert matches[0].type == "email"


class TestScanPiiEdgeCases:
    def test_empty_string(self):
        assert scan_pii("") == []

    def test_none_input(self):
        assert scan_pii(None) == []

    def test_non_string_input(self):
        assert scan_pii(123) == []

    def test_clean_text(self):
        assert scan_pii("Hello world, this is clean text.") == []

    def test_position_accuracy(self):
        input_str = "SSN: 123-45-6789"
        matches = scan_pii(input_str, types=["ssn"])
        assert matches[0].start == 5
        assert matches[0].end == 16
        assert input_str[matches[0].start:matches[0].end] == "123-45-6789"


# ─── detect_pii ───────────────────────────────────────────────────────────────


class TestDetectPii:
    def test_true_when_pii_found(self):
        assert detect_pii("john@example.com") is True

    def test_false_when_no_pii(self):
        assert detect_pii("Hello world") is False

    def test_respects_type_filter(self):
        assert detect_pii("john@example.com", types=["ssn"]) is False
        assert detect_pii("john@example.com", types=["email"]) is True


# ─── redact_pii ───────────────────────────────────────────────────────────────


class TestRedactPii:
    def test_redact_email_default(self):
        assert redact_pii("Contact john@example.com") == "Contact [REDACTED]"

    def test_redact_multiple(self):
        result = redact_pii("Email: a@b.com, SSN: 123-45-6789")
        assert result == "Email: [REDACTED], SSN: [REDACTED]"

    def test_custom_replacement(self):
        assert redact_pii("Email: a@b.com", replacement="***") == "Email: ***"

    def test_type_labels(self):
        result = redact_pii("Email: a@b.com, SSN: 123-45-6789", type_labels=True)
        assert result == "Email: [EMAIL], SSN: [SSN]"

    def test_no_pii_returns_original(self):
        assert redact_pii("Hello world") == "Hello world"

    def test_empty_input(self):
        assert redact_pii("") == ""

    def test_none_input(self):
        assert redact_pii(None) is None

    def test_only_redact_specified_types(self):
        input_str = "Email: a@b.com, SSN: 123-45-6789"
        result = redact_pii(input_str, types=["ssn"])
        assert "a@b.com" in result
        assert "[REDACTED]" in result
        assert "123-45-6789" not in result


# ─── scan_object_pii ──────────────────────────────────────────────────────────


class TestScanObjectPii:
    def test_flat_object(self):
        results = scan_object_pii({"name": "John", "email": "john@example.com"})
        assert len(results) == 1
        assert results[0].field == "email"
        assert results[0].type == "email"

    def test_nested_object(self):
        results = scan_object_pii({
            "user": {"contact": {"email": "john@example.com"}},
        })
        assert len(results) == 1
        assert results[0].field == "user.contact.email"

    def test_arrays(self):
        results = scan_object_pii({"emails": ["a@b.com", "c@d.com"]})
        assert len(results) == 2
        assert results[0].field == "emails[0]"
        assert results[1].field == "emails[1]"

    def test_objects_in_arrays(self):
        results = scan_object_pii({
            "users": [{"email": "a@b.com"}, {"email": "c@d.com"}],
        })
        assert len(results) == 2
        assert results[0].field == "users[0].email"

    def test_no_pii(self):
        assert scan_object_pii({"name": "John", "age": 30}) == []

    def test_none_input(self):
        assert scan_object_pii(None) == []


# ─── redact_object_pii ────────────────────────────────────────────────────────


class TestRedactObjectPii:
    def test_flat_object(self):
        result = redact_object_pii({"name": "John", "email": "john@example.com"})
        assert result["name"] == "John"
        assert result["email"] == "[REDACTED]"

    def test_nested_object(self):
        result = redact_object_pii({
            "user": {"contact": {"email": "john@example.com", "name": "John"}},
        })
        assert result["user"]["contact"]["email"] == "[REDACTED]"
        assert result["user"]["contact"]["name"] == "John"

    def test_arrays(self):
        result = redact_object_pii({
            "emails": ["a@b.com", "safe text", "c@d.com"],
        })
        assert result["emails"] == ["[REDACTED]", "safe text", "[REDACTED]"]

    def test_preserve_non_strings(self):
        result = redact_object_pii({"count": 42, "active": True, "email": "a@b.com"})
        assert result["count"] == 42
        assert result["active"] is True
        assert result["email"] == "[REDACTED]"

    def test_type_labels(self):
        result = redact_object_pii(
            {"email": "a@b.com", "ssn": "123-45-6789"},
            type_labels=True,
        )
        assert result["email"] == "[EMAIL]"
        assert result["ssn"] == "[SSN]"
