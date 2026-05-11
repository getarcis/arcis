"""
Sanitizer middleware integration tests — extracted from tests/test_core.py.
"""

from arcis.core import Sanitizer


class TestSanitizerCallable:
    """Test Sanitizer as a callable (middleware-style)."""

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
