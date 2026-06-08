"""V33 — Modern deserialization marker detection (improvements.md §1.2).

Detect input that LOOKS like serialized-object payloads for languages
where deserialization equals code execution. Each runtime has a
characteristic byte signature at the start of a serialized blob:

* **Python pickle** — protocol 4 marker ``\\x80\\x04`` or protocol 5
  ``\\x80\\x05`` at position 0. Reaching ``pickle.loads()`` on this
  with untrusted data = RCE.

* **Java FastJSON** — embedded ``"@type":"com.<class>"`` autotype
  marker that Java FastJSON uses to instantiate arbitrary classes
  during deserialization. Public CVE corpus from 2017-2024 has dozens
  of FastJSON gadget-chains.

* **PHP unserialize** — ``O:N:"ClassName":M:{...}`` shape (where N
  is the class-name length). Targets PHP apps that call
  ``unserialize()`` on user input.

* **Ruby Marshal** — magic bytes ``\\x04\\x08`` at position 0.
  ``Marshal.load`` on untrusted data = RCE.

* **.NET BinaryFormatter** — magic byte sequence
  ``\\x00\\x01\\x00\\x00\\x00`` at position 0. ``BinaryFormatter``
  is deprecated in .NET 5+ specifically because it's unsafe; many
  legacy apps still call it.

# API shape

Detection-only helper. Returns the runtime that the marker indicates,
or None if no marker matches. Caller decides what to do with that
signal - typically: refuse the request, log a security event, route
to a sandboxed handler.

This is NOT wired into ``sanitize_string`` because the right response
is "refuse" not "strip the magic bytes and pass through" (the
remaining bytes might still deserialize to something dangerous on
a forgiving parser).
"""
from __future__ import annotations

import re
from typing import Literal, Optional

DeserializeRuntime = Literal[
    "python_pickle",
    "java_fastjson",
    "php_unserialize",
    "ruby_marshal",
    "dotnet_binary_formatter",
]


# Python pickle: \x80 followed by version byte 0x02-0x05 (oldest
# supported protocol is 2 since Python 3.0; newest is 5 since
# Python 3.8). Match at string start to avoid false positives.
_PICKLE_HEAD = re.compile(r"^\x80[\x02-\x05]")

# Base64-encoded pickle. Attackers ship pickle over JSON/text as base64,
# so the raw head-byte check never sees \x80. A string that is valid
# base64 and decodes to a pickle head byte is the signal. The base64 of
# \x80\x02..\x05 always begins "gA" + one of a known set of chars, so we
# pre-filter cheaply before decoding. Benchmark deser-python-pickle-marker.
_PICKLE_B64_PREFIX = re.compile(r"^gA[I-Z]")
_B64_SHAPE = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")

# Ruby Marshal magic: \x04\x08 at start (Ruby 1.9+).
_RUBY_MARSHAL_HEAD = re.compile(r"^\x04\x08")

# .NET BinaryFormatter: 5-byte serialization-header.
_DOTNET_BINFMT_HEAD = re.compile(r"^\x00\x01\x00\x00\x00")

# Java FastJSON: embedded `"@type":"<class>"`. Match anywhere.
_FASTJSON_AUTOTYPE = re.compile(
    r'"@type"\s*:\s*"[a-zA-Z_$][\w$.]*"',
)

# PHP unserialize: `O:<len>:"<ClassName>":<count>:{` shape.
_PHP_UNSERIALIZE = re.compile(
    r'O:\d+:"[a-zA-Z_\\][\w\\]*":\d+:\{',
)


def detect_deserialization(payload: str) -> Optional[DeserializeRuntime]:
    """Detect a serialized-object marker for any known runtime.

    Returns the runtime tag if a marker matches, or None if the input
    looks safe. Precedence: head-byte markers (pickle / Ruby / .NET)
    before embedded markers (FastJSON / PHP) because head-byte
    matches are byte-precise.

    Examples:
        >>> detect_deserialization("\\x80\\x04...")
        'python_pickle'
        >>> detect_deserialization('{"@type":"com.evil.Gadget", "x": 1}')
        'java_fastjson'
        >>> detect_deserialization("hello world")
        # None
    """
    if not isinstance(payload, str):
        return None
    if not payload:
        return None
    if _PICKLE_HEAD.search(payload):
        return "python_pickle"
    # Base64-encoded pickle: cheap prefix pre-filter, then validate by
    # decoding and re-checking the pickle head byte (\x80 + proto 2-5).
    if _PICKLE_B64_PREFIX.search(payload) and _B64_SHAPE.match(payload):
        try:
            import base64
            decoded = base64.b64decode(payload, validate=True)
            if decoded[:1] == b"\x80" and decoded[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
                return "python_pickle"
        except Exception:
            pass
    if _RUBY_MARSHAL_HEAD.search(payload):
        return "ruby_marshal"
    if _DOTNET_BINFMT_HEAD.search(payload):
        return "dotnet_binary_formatter"
    if _FASTJSON_AUTOTYPE.search(payload):
        return "java_fastjson"
    if _PHP_UNSERIALIZE.search(payload):
        return "php_unserialize"
    return None


def is_serialized_payload(payload: str) -> bool:
    """Convenience boolean wrapper around :func:`detect_deserialization`."""
    return detect_deserialization(payload) is not None
