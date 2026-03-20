"""
Arcis Sanitizers - PII Detection and Redaction

Detects and redacts Personally Identifiable Information:
- Email addresses
- Phone numbers (US formats)
- Credit card numbers (with Luhn validation)
- Social Security Numbers
- IP addresses (IPv4)
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

PiiType = str  # 'email' | 'phone' | 'credit_card' | 'ssn' | 'ip_address'

ALL_TYPES: Tuple[str, ...] = ("email", "phone", "credit_card", "ssn", "ip_address")

TYPE_LABELS: Dict[str, str] = {
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "credit_card": "[CREDIT_CARD]",
    "ssn": "[SSN]",
    "ip_address": "[IP_ADDRESS]",
}

# ─── Patterns ─────────────────────────────────────────────────────────────────

# Email: simplified RFC 5322
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+"
)

# US phone: (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx, +1xxxxxxxxxx
_PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
)

# Credit cards: 13-19 digits with optional spaces/dashes
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# SSN: XXX-XX-XXXX or XXX XX XXXX
_SSN_RE = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")

# IPv4
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# IPv6 (simplified)
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)

_PATTERN_MAP: Dict[str, List[re.Pattern]] = {
    "email": [_EMAIL_RE],
    "phone": [_PHONE_RE],
    "credit_card": [_CREDIT_CARD_RE],
    "ssn": [_SSN_RE],
    "ip_address": [_IPV4_RE, _IPV6_RE],
}


# ─── Types ────────────────────────────────────────────────────────────────────

@dataclass
class PiiMatch:
    """A single PII match found in text."""
    type: str
    value: str
    start: int
    end: int


@dataclass
class PiiObjectMatch(PiiMatch):
    """A PII match with the object field path."""
    field: str = ""


# ─── Luhn Check ───────────────────────────────────────────────────────────────

def _luhn_check(value: str) -> bool:
    """Validate a number using the Luhn algorithm."""
    digits = re.sub(r"[\s-]", "", value)
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False

    total = 0
    alternate = False
    for i in range(len(digits) - 1, -1, -1):
        n = int(digits[i])
        if alternate:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alternate = not alternate
    return total % 10 == 0


# ─── Core Functions ──────────────────────────────────────────────────────────

def scan_pii(
    input_str: str,
    types: Optional[Sequence[str]] = None,
) -> List[PiiMatch]:
    """
    Scan a string for PII and return all matches.

    Args:
        input_str: String to scan
        types: PII types to scan for. Default: all types

    Returns:
        List of PiiMatch objects sorted by position

    Example:
        scan_pii('Call 555-123-4567 or email john@example.com')
        # [PiiMatch(type='phone', ...), PiiMatch(type='email', ...)]
    """
    if not input_str or not isinstance(input_str, str):
        return []

    scan_types = types or ALL_TYPES
    matches: List[PiiMatch] = []

    for pii_type in scan_types:
        patterns = _PATTERN_MAP.get(pii_type)
        if not patterns:
            continue

        for pattern in patterns:
            for m in pattern.finditer(input_str):
                value = m.group(0)

                # Credit card: Luhn validation
                if pii_type == "credit_card" and not _luhn_check(value):
                    continue

                # SSN: reject invalid area numbers
                if pii_type == "ssn":
                    area = int(value[:3])
                    if area == 0 or area == 666 or area >= 900:
                        continue

                matches.append(PiiMatch(
                    type=pii_type,
                    value=value,
                    start=m.start(),
                    end=m.end(),
                ))

    matches.sort(key=lambda x: x.start)
    return matches


def detect_pii(
    input_str: str,
    types: Optional[Sequence[str]] = None,
) -> bool:
    """
    Check if a string contains any PII.

    Args:
        input_str: String to check
        types: PII types to check for

    Returns:
        True if PII is detected
    """
    return len(scan_pii(input_str, types)) > 0


def redact_pii(
    input_str: str,
    types: Optional[Sequence[str]] = None,
    replacement: str = "[REDACTED]",
    type_labels: bool = False,
) -> str:
    """
    Redact PII from a string.

    Args:
        input_str: String to redact
        types: PII types to redact
        replacement: Replacement text. Default: '[REDACTED]'
        type_labels: Use type-specific labels like [EMAIL]. Default: False

    Returns:
        String with PII replaced

    Example:
        redact_pii('Email: john@example.com, SSN: 123-45-6789')
        # 'Email: [REDACTED], SSN: [REDACTED]'
    """
    if not input_str or not isinstance(input_str, str):
        return input_str

    matches = scan_pii(input_str, types)
    if not matches:
        return input_str

    # Replace from end to preserve positions
    result = input_str
    for m in reversed(matches):
        label = TYPE_LABELS.get(m.type, replacement) if type_labels else replacement
        result = result[:m.start] + label + result[m.end:]

    return result


def scan_object_pii(
    obj: Any,
    types: Optional[Sequence[str]] = None,
    path: str = "",
) -> List[PiiObjectMatch]:
    """
    Scan an object's string values for PII recursively.

    Args:
        obj: Dict to scan
        types: PII types to scan for
        path: Internal — current field path

    Returns:
        List of PiiObjectMatch with field paths
    """
    results: List[PiiObjectMatch] = []
    if not obj or not isinstance(obj, dict):
        return results

    for key, value in obj.items():
        field_path = f"{path}.{key}" if path else key

        if isinstance(value, str):
            for m in scan_pii(value, types):
                results.append(PiiObjectMatch(
                    type=m.type,
                    value=m.value,
                    start=m.start,
                    end=m.end,
                    field=field_path,
                ))
        elif isinstance(value, dict):
            results.extend(scan_object_pii(value, types, field_path))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                item_path = f"{field_path}[{i}]"
                if isinstance(item, str):
                    for m in scan_pii(item, types):
                        results.append(PiiObjectMatch(
                            type=m.type,
                            value=m.value,
                            start=m.start,
                            end=m.end,
                            field=item_path,
                        ))
                elif isinstance(item, dict):
                    results.extend(scan_object_pii(item, types, item_path))

    return results


def redact_object_pii(
    obj: Any,
    types: Optional[Sequence[str]] = None,
    replacement: str = "[REDACTED]",
    type_labels: bool = False,
) -> Any:
    """
    Redact PII from all string values in a dict recursively.

    Args:
        obj: Dict to redact
        types: PII types to redact
        replacement: Replacement text
        type_labels: Use type-specific labels

    Returns:
        New dict with PII redacted
    """
    if not obj or not isinstance(obj, dict):
        return obj

    result = {}
    for key, value in obj.items():
        if isinstance(value, str):
            result[key] = redact_pii(value, types, replacement, type_labels)
        elif isinstance(value, dict):
            result[key] = redact_object_pii(value, types, replacement, type_labels)
        elif isinstance(value, list):
            result[key] = [
                redact_pii(item, types, replacement, type_labels) if isinstance(item, str)
                else redact_object_pii(item, types, replacement, type_labels) if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            result[key] = value

    return result
