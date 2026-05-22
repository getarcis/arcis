"""V33 — Modern deserialization markers (improvements.md §1.2)."""
from arcis.sanitizers.deserialization import (
    detect_deserialization,
    is_serialized_payload,
)


def test_python_pickle_protocol_4():
    assert detect_deserialization("\x80\x04anything") == "python_pickle"


def test_python_pickle_protocol_5():
    assert detect_deserialization("\x80\x05anything") == "python_pickle"


def test_python_pickle_protocol_2():
    # Protocol 2 is the OLDEST shipped in Python 3.0+.
    assert detect_deserialization("\x80\x02anything") == "python_pickle"


def test_pickle_only_matches_at_string_start():
    # \x80\x04 mid-string should NOT trigger (it's likely random binary
    # data, not a pickle blob).
    assert detect_deserialization("hello\x80\x04world") is None


def test_ruby_marshal():
    assert detect_deserialization("\x04\x08[\x06o:\x0bObject\x00") == "ruby_marshal"


def test_dotnet_binary_formatter():
    assert (
        detect_deserialization("\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00")
        == "dotnet_binary_formatter"
    )


def test_java_fastjson_autotype():
    payload = '{"@type":"com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "rmi://x/Exploit"}'
    assert detect_deserialization(payload) == "java_fastjson"


def test_java_fastjson_with_whitespace():
    payload = '{ "@type" : "com.evil.Gadget" }'
    assert detect_deserialization(payload) == "java_fastjson"


def test_php_unserialize():
    payload = 'O:8:"stdClass":1:{s:4:"user";s:5:"admin";}'
    assert detect_deserialization(payload) == "php_unserialize"


def test_php_unserialize_with_namespace():
    payload = 'O:18:"App\\\\User\\\\Profile":0:{}'
    assert detect_deserialization(payload) == "php_unserialize"


def test_safe_string_returns_none():
    assert detect_deserialization("hello world") is None
    assert detect_deserialization('{"name": "alice", "age": 30}') is None
    assert detect_deserialization("") is None


def test_empty_input_returns_none():
    assert detect_deserialization("") is None


def test_non_string_input_returns_none():
    # The signature is `str`, but real callers might pass bytes etc.
    # The function must not raise on the wrong type.
    assert detect_deserialization(None) is None  # type: ignore[arg-type]
    assert detect_deserialization(123) is None  # type: ignore[arg-type]


def test_is_serialized_payload_boolean_wrapper():
    assert is_serialized_payload("\x80\x04x") is True
    assert is_serialized_payload("hello") is False


def test_at_type_in_plain_english_does_not_false_positive():
    # Pattern requires the `:` separator and quoted class name. Plain
    # English mentioning "@type" should not trigger.
    assert detect_deserialization("the @type field describes the kind") is None


def test_php_shape_inside_already_decoded_payload_triggers():
    # When the framework has already JSON-decoded the request body,
    # the inner string `O:5:"User":2:{...}` (no backslash escapes)
    # is what reaches downstream code. The pattern must match THAT
    # form. Callers checking a raw JSON-string body BEFORE decoding
    # need to decode first or live with false negatives — same
    # constraint as the multi-decode chain in §1.1.b.
    payload = 'O:5:"User":2:{s:2:"id";i:1;}'
    assert detect_deserialization(payload) == "php_unserialize"
