"""Host-header validation (V41 — Host-header poisoning / subdomain takeover).

Apps that reflect the ``Host`` header into password-reset links, absolute
redirects, share URLs, or cache keys are vulnerable when an attacker sends
``Host: attacker.com``. This validator checks the Host against an allowlist.

Default-deny by construction: an empty allowlist rejects everything, so this is
OPT-IN. Multi-tenant apps either don't use it or list their tenant hosts, which
avoids false positives.

Usage::

    from arcis import validate_host, is_host_allowed

    if not is_host_allowed(request.headers.get("host", ""), allowlist=["myapp.com"]):
        raise BadRequest("untrusted Host header")
"""

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ValidateHostResult:
    """Result of :func:`validate_host`."""

    safe: bool
    reason: Optional[str] = None


def _normalize_host(host: str) -> str:
    # Strip a trailing :port and lowercase. IPv6 literals are expected in
    # bracket form ([::1]), which this leaves intact.
    return re.sub(r":\d+$", "", host.strip().lower())


def validate_host(host: str, allowlist: List[str]) -> ValidateHostResult:
    """Validate a Host header against an allowlist. Case-insensitive,
    port-stripped. Supports a single-level leading ``*.`` wildcard
    (``*.example.com`` matches ``a.example.com`` but not ``example.com`` or
    ``a.b.example.com``). Empty allowlist = default-deny.
    """
    if not isinstance(host, str) or not host.strip():
        return ValidateHostResult(safe=False, reason="missing Host header")
    if not allowlist:
        return ValidateHostResult(
            safe=False, reason="no Host allowlist configured (default-deny)"
        )
    h = _normalize_host(host)
    for entry in allowlist:
        a = str(entry).strip().lower()
        if not a:
            continue
        if a.startswith("*."):
            suffix = a[1:]  # ".example.com"
            if h.endswith(suffix):
                label = h[: len(h) - len(suffix)]
                if label and "." not in label:
                    return ValidateHostResult(safe=True)
        elif h == a:
            return ValidateHostResult(safe=True)
    return ValidateHostResult(safe=False, reason=f"Host not in allowlist: {h}")


def is_host_allowed(host: str, allowlist: List[str]) -> bool:
    """Boolean convenience wrapper around :func:`validate_host`."""
    return validate_host(host, allowlist).safe
