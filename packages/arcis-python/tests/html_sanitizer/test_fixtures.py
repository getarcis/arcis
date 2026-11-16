"""Shared HTML sanitizer fixtures (spec/html-sanitizer-vectors.json).

Every case's expected output and removal list come from DOMPurify 3.4.18 on
jsdom 31.0.1. The Python sanitizer must produce exactly the expected html,
and the same removal list once DOMPurify's html/head/body entries are
dropped (spec/API_SPEC.md section 11).

Known exceptions: none. A parser difference may only be listed here when the
Python output removes strictly more than DOMPurify, with the case id and the
reason.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("justhtml")

from arcis.html import sanitize_html, sanitize_html_detailed

_VECTORS_PATH = Path(__file__).parents[4] / "spec" / "html-sanitizer-vectors.json"
_CASES: list[dict[str, Any]] = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))["cases"]

# Cases whose expected output DOMPurify itself changes on a second pass, so
# idempotence is not asserted for them. Found by running DOMPurify 3.4.18 on
# each case's expected output with the case config.
DOMPURIFY_NOT_IDEMPOTENT = {
    "dompurify-040": "a leading <template> is parsed into <head>, outside the output",
    "dompurify-206": "the nested <form> is ignored when the output is parsed again",
    "dompurify-209": "the nested <form> is ignored when the output is parsed again",
    "dompurify-211": "the parser closes <h1> at the nested <h6>",
    "dompurify-214": "the parser closes the outer <option> at the nested one",
    "config-safe_for_templates": "the scrubbed title value ' ' is trimmed on the second pass",
    "fuzz-044": "a leading <title> is parsed into <head>, outside the output",
    "fuzz-261": "a leading <template> is parsed into <head>, outside the output",
    "fuzz-331": "a leading <title> is parsed into <head>, outside the output",
    "fuzz-374": "a leading <template> and <title> are parsed into <head>",
}


def _regex(spec: dict[str, str]) -> re.Pattern[str]:
    """Translate the fixtures' {source, flags} form of a JavaScript RegExp."""
    flags = 0
    for flag in spec["flags"]:
        if flag == "i":
            flags |= re.IGNORECASE
        elif flag == "m":
            flags |= re.MULTILINE
        elif flag == "s":
            flags |= re.DOTALL
        else:
            raise AssertionError(f"unsupported RegExp flag in fixtures: {flag}")
    return re.compile(spec["source"], flags)


def _config(case: dict[str, Any]) -> dict[str, Any]:
    """DOMPurify's UPPER_CASE option names to this SDK's lowercase keys."""
    config = {}
    for key, value in case["config"].items():
        if key == "ALLOWED_URI_REGEXP":
            value = _regex(value)
        config[key.lower()] = value
    return config


def _without_root_entries(removed: list[dict[str, str]]) -> list[dict[str, str]]:
    return [entry for entry in removed if entry.get("element") not in ("html", "head", "body")]


def test_fixture_file_has_every_case() -> None:
    assert len(_CASES) == 668


@pytest.mark.parametrize("case", _CASES, ids=[case["id"] for case in _CASES])
def test_html_matches_dompurify(case: dict[str, Any]) -> None:
    assert sanitize_html(case["input"], **_config(case)) == case["expected"]


@pytest.mark.parametrize("case", _CASES, ids=[case["id"] for case in _CASES])
def test_removed_matches_dompurify(case: dict[str, Any]) -> None:
    result = sanitize_html_detailed(case["input"], **_config(case))
    assert result["removed"] == _without_root_entries(case["removed"])


def test_sanitizing_twice_changes_nothing() -> None:
    changed = [
        case["id"]
        for case in _CASES
        if case["id"] not in DOMPURIFY_NOT_IDEMPOTENT
        and sanitize_html(case["expected"], **_config(case)) != case["expected"]
    ]
    assert changed == []


def test_cases_dompurify_cannot_resanitize_stably_are_still_present() -> None:
    # Keeps the exemption list honest: each entry must name a real case
    # whose output changes on a second pass.
    by_id = {case["id"]: case for case in _CASES}
    for case_id in DOMPURIFY_NOT_IDEMPOTENT:
        case = by_id[case_id]
        assert sanitize_html(case["expected"], **_config(case)) != case["expected"], case_id
