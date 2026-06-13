"""
Cross-SDK detection-parity conformance tests for Python.

Loads ``spec/TEST_VECTORS.json`` and asserts every payload in the
``detect_parity`` block classifies under the right vector when fed
through Python's ``detect_xss / detect_sql / detect_path_traversal /
detect_command_injection / detect_ssti / detect_xxe``.

The same test vectors are run by the Node and Go SDKs (see their
respective conformance tests). If a payload is caught by Python but
missed by Node — or vice versa — that's a Pattern 7 (Cross-SDK Parity
Contract) violation and the failing assertion points at the SDK that
diverged.

Why this matters: Node uses hardcoded ``XSS_PATTERNS`` and
``XSS_REMOVE_PATTERNS`` arrays; Python loads from
``packages/core/patterns.json``; Go has its own list. Without a shared
parity test the three lists drift and an attack payload can be caught
by one SDK while missed by another. This test is the contract.
"""

import json
from pathlib import Path

import pytest

from arcis.sanitizers import (
    detect_xss,
    detect_sql,
    detect_path_traversal,
    detect_command_injection,
    detect_ssti,
    detect_xxe,
    detect_nosql,
)
from arcis.sanitizers.prompt_injection import detect_prompt_injection
from arcis.sanitizers.deserialization import detect_deserialization


def _spec_path() -> Path:
    """Resolve spec/TEST_VECTORS.json from this test file's location.
    Walks up until a `spec/` sibling is found so the test works whether
    invoked from the package root or the repo root."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "spec" / "TEST_VECTORS.json"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Could not locate spec/TEST_VECTORS.json starting from {here}"
    )


@pytest.fixture(scope="module")
def parity_block() -> dict:
    with open(_spec_path(), "r", encoding="utf-8") as f:
        spec = json.load(f)
    block = spec.get("detect_parity")
    if not block:
        pytest.skip("detect_parity block missing from TEST_VECTORS.json")
    return block


# Each detector and the parity sub-keys (positive + negative cases) it
# is responsible for. Adding a new vector here is a 1-line change.
_DETECTOR_MAP = {
    "xss": (detect_xss, "xss_positive", "xss_negative"),
    "sql": (detect_sql, "sql_positive", "sql_negative"),
    "path": (detect_path_traversal, "path_positive", "path_negative"),
    "command": (detect_command_injection, "command_positive", "command_negative"),
    "ssti": (detect_ssti, "ssti_positive", "ssti_negative"),
    "xxe": (detect_xxe, "xxe_positive", "xxe_negative"),
    "nosql": (detect_nosql, "nosql_positive", "nosql_negative"),
    "prompt_injection": (
        lambda s: detect_prompt_injection(s).detected,
        "prompt_injection_positive",
        "prompt_injection_negative",
    ),
    "deserialization": (
        lambda s: detect_deserialization(s) is not None,
        "deserialization_positive",
        "deserialization_negative",
    ),
}


def _params(block: dict, vector: str) -> list:
    """Flatten positive + negative case lists into pytest parameters."""
    detector, pos_key, neg_key = _DETECTOR_MAP[vector]
    out = []
    for entry in block.get(pos_key, []):
        out.append(("positive", entry["input"], True))
    for entry in block.get(neg_key, []):
        out.append(("negative", entry["input"], False))
    return out


@pytest.mark.parametrize("vector", list(_DETECTOR_MAP.keys()))
def test_detector_parity(vector: str, parity_block: dict):
    """Exercise one detector against every parity-block case for that
    vector. Failures print the case kind (positive/negative), the input,
    and the actual detector output so the diff is one-line readable."""
    detector, _pos, _neg = _DETECTOR_MAP[vector]
    cases = _params(parity_block, vector)
    if not cases:
        pytest.skip(f"no parity cases for vector={vector}")

    failures = []
    for kind, payload, expected in cases:
        actual = detector(payload)
        if actual != expected:
            failures.append(
                f"  [{kind}] expected={expected} actual={actual} input={payload!r}"
            )

    if failures:
        pytest.fail(
            f"detect_{vector} parity violations ({len(failures)}/{len(cases)}):\n"
            + "\n".join(failures)
        )
