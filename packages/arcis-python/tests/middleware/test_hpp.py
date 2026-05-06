"""
HPP (HTTP Parameter Pollution) Protection tests.
Tests for arcis/middleware/hpp.py
"""

from arcis.middleware.hpp import HppProtection, create_hpp


class TestNormalizeBasic:
    """Test core normalize() method."""

    def setup_method(self):
        self.hpp = HppProtection()

    def test_single_values_unchanged(self):
        clean, polluted = self.hpp.normalize({"role": ["user"], "name": ["alice"]})
        assert clean == {"role": "user", "name": "alice"}
        assert polluted == {}

    def test_duplicate_param_last_wins(self):
        clean, polluted = self.hpp.normalize({"role": ["user", "admin"]})
        assert clean["role"] == "admin"
        assert polluted["role"] == ["user", "admin"]

    def test_multiple_duplicates(self):
        clean, polluted = self.hpp.normalize({
            "role": ["user", "mod", "admin"],
            "sort": ["asc", "desc"],
        })
        assert clean["role"] == "admin"
        assert clean["sort"] == "desc"
        assert "role" in polluted
        assert "sort" in polluted

    def test_empty_values_list(self):
        clean, polluted = self.hpp.normalize({"empty": []})
        assert clean["empty"] == ""
        assert polluted == {}

    def test_no_params(self):
        clean, polluted = self.hpp.normalize({})
        assert clean == {}
        assert polluted == {}


class TestWhitelist:
    """Test whitelist behaviour."""

    def test_whitelisted_param_kept_as_list(self):
        hpp = HppProtection(whitelist=["tags"])
        clean, polluted = hpp.normalize({"tags": ["python", "security"], "role": ["user", "admin"]})
        assert clean["tags"] == ["python", "security"]
        assert clean["role"] == "admin"
        assert "role" in polluted
        assert "tags" not in polluted

    def test_whitelist_single_value_unchanged(self):
        hpp = HppProtection(whitelist=["tags"])
        clean, polluted = hpp.normalize({"tags": ["python"]})
        assert clean["tags"] == "python"
        assert polluted == {}

    def test_multiple_whitelisted_params(self):
        hpp = HppProtection(whitelist=["tags", "ids"])
        clean, polluted = hpp.normalize({
            "tags": ["a", "b"],
            "ids": ["1", "2", "3"],
            "role": ["user", "admin"],
        })
        assert isinstance(clean["tags"], list)
        assert isinstance(clean["ids"], list)
        assert isinstance(clean["role"], str)


class TestCheckFlags:
    """Test check_query and check_body flags — only normalize() is tested here."""

    def test_check_query_false_skips_query(self):
        hpp = HppProtection(check_query=False)
        # normalize() itself doesn't respect check_query — that's a flask hook concern
        # but we verify the instance stores the flag correctly
        assert hpp.check_query is False

    def test_check_body_false_stored(self):
        hpp = HppProtection(check_body=False)
        assert hpp.check_body is False

    def test_defaults_check_both(self):
        hpp = HppProtection()
        assert hpp.check_query is True
        assert hpp.check_body is True


class TestOnPollutionCallback:
    """Test the on_pollution callback."""

    def test_callback_called_when_duplicates_found(self):
        seen = []
        hpp = HppProtection(on_pollution=lambda p: seen.append(p))

        # The flask_before_request calls on_pollution — test via normalize + manual call
        clean, polluted = hpp.normalize({"role": ["user", "admin"]})
        if polluted and hpp.on_pollution:
            hpp.on_pollution(polluted)

        assert len(seen) == 1
        assert "role" in seen[0]

    def test_callback_not_called_when_clean(self):
        seen = []
        hpp = HppProtection(on_pollution=lambda p: seen.append(p))

        clean, polluted = hpp.normalize({"role": ["user"]})
        if polluted and hpp.on_pollution:
            hpp.on_pollution(polluted)

        assert len(seen) == 0

    def test_no_callback_no_error(self):
        hpp = HppProtection()
        clean, polluted = hpp.normalize({"role": ["user", "admin"]})
        # Should not raise even without a callback
        assert clean["role"] == "admin"


class TestCreateHpp:
    """Test factory function."""

    def test_returns_hpp_protection(self):
        hpp = create_hpp()
        assert isinstance(hpp, HppProtection)

    def test_passes_whitelist(self):
        hpp = create_hpp(whitelist=["tags"])
        assert "tags" in hpp.whitelist

    def test_passes_check_flags(self):
        hpp = create_hpp(check_query=False, check_body=False)
        assert hpp.check_query is False
        assert hpp.check_body is False

    def test_passes_on_pollution(self):
        cb = lambda p: None
        hpp = create_hpp(on_pollution=cb)
        assert hpp.on_pollution is cb


class TestNormalizePollutedOutput:
    """Verify polluted dict accuracy."""

    def test_polluted_contains_original_list(self):
        hpp = HppProtection()
        _, polluted = hpp.normalize({"x": ["a", "b", "c"]})
        assert polluted["x"] == ["a", "b", "c"]

    def test_clean_does_not_contain_list_for_non_whitelisted(self):
        hpp = HppProtection()
        clean, _ = hpp.normalize({"x": ["a", "b"]})
        assert not isinstance(clean["x"], list)
        assert clean["x"] == "b"
