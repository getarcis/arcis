"""
Email validation tests.
Tests for arcis/validation/email.py
"""

import pytest
from arcis.validation.email import (
    validate_email_address,
    is_valid_email_syntax,
    verify_email_mx,
    EmailValidationResult,
    MAX_EMAIL_LENGTH,
    MAX_LOCAL_LENGTH,
    DISPOSABLE_DOMAINS,
    FREE_PROVIDERS,
    DOMAIN_TYPOS,
)


class TestValidEmailAddresses:
    """Test valid email addresses pass validation."""

    def test_simple_email(self):
        result = validate_email_address('user@example.com')
        assert result.valid is True
        assert result.reason == 'valid'

    def test_email_with_dots(self):
        result = validate_email_address('first.last@example.com')
        assert result.valid is True

    def test_email_with_plus(self):
        result = validate_email_address('user+tag@example.com')
        assert result.valid is True

    def test_email_with_numbers(self):
        result = validate_email_address('user123@example456.com')
        assert result.valid is True

    def test_email_with_hyphens_in_domain(self):
        result = validate_email_address('user@my-domain.example.com')
        assert result.valid is True

    def test_normalized_is_lowercase(self):
        result = validate_email_address('User@EXAMPLE.COM')
        assert result.normalized == 'user@example.com'

    def test_strips_whitespace(self):
        result = validate_email_address('  user@example.com  ')
        assert result.valid is True
        assert result.normalized == 'user@example.com'

    def test_subdomain(self):
        result = validate_email_address('user@mail.example.co.uk')
        assert result.valid is True


class TestInvalidEmailSyntax:
    """Test invalid email syntax is rejected."""

    def test_empty_string(self):
        result = validate_email_address('')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_whitespace_only(self):
        result = validate_email_address('   ')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_no_at_sign(self):
        result = validate_email_address('userexample.com')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_multiple_at_signs(self):
        result = validate_email_address('user@@example.com')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_no_domain(self):
        result = validate_email_address('user@')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_no_local_part(self):
        result = validate_email_address('@example.com')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_no_tld(self):
        result = validate_email_address('user@example')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_consecutive_dots_in_local(self):
        result = validate_email_address('user..name@example.com')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_leading_dot_in_local(self):
        result = validate_email_address('.user@example.com')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_trailing_dot_in_local(self):
        result = validate_email_address('user.@example.com')
        assert result.valid is False
        assert result.reason == 'invalid_syntax'

    def test_exceeds_max_length(self):
        local = 'a' * 64
        domain = 'b' * 63 + '.com'
        email = f'{local}@{domain}'
        # Should be over 254 chars total
        if len(email) <= MAX_EMAIL_LENGTH:
            # Make it longer
            email = 'a' * 200 + '@' + 'b' * 60 + '.com'
        result = validate_email_address(email)
        assert result.valid is False

    def test_local_part_too_long(self):
        local = 'a' * 65
        result = validate_email_address(f'{local}@example.com')
        assert result.valid is False

    def test_space_in_email(self):
        result = validate_email_address('user name@example.com')
        assert result.valid is False


class TestDisposableDetection:
    """Test disposable email domain blocking."""

    def test_blocks_disposable_by_default(self):
        result = validate_email_address('user@mailinator.com')
        assert result.valid is False
        assert result.reason == 'disposable'
        assert result.is_disposable is True

    def test_blocks_guerrillamail(self):
        result = validate_email_address('test@guerrillamail.com')
        assert result.valid is False
        assert result.reason == 'disposable'

    def test_blocks_tempmail(self):
        result = validate_email_address('test@tempmail.com')
        assert result.valid is False
        assert result.reason == 'disposable'

    def test_blocks_yopmail(self):
        result = validate_email_address('test@yopmail.com')
        assert result.valid is False
        assert result.reason == 'disposable'

    def test_disable_disposable_check(self):
        result = validate_email_address('user@mailinator.com', check_disposable=False)
        assert result.valid is True

    def test_disposable_set_not_empty(self):
        assert len(DISPOSABLE_DOMAINS) > 50


class TestFreeProviderDetection:
    """Test free email provider flagging."""

    def test_gmail_flagged_as_free(self):
        result = validate_email_address('user@gmail.com')
        assert result.valid is True
        assert result.is_free is True

    def test_yahoo_flagged_as_free(self):
        result = validate_email_address('user@yahoo.com')
        assert result.valid is True
        assert result.is_free is True

    def test_custom_domain_not_free(self):
        result = validate_email_address('user@company.com')
        assert result.valid is True
        assert result.is_free is False

    def test_free_providers_set(self):
        assert 'gmail.com' in FREE_PROVIDERS
        assert 'outlook.com' in FREE_PROVIDERS
        assert 'protonmail.com' in FREE_PROVIDERS


class TestTypoSuggestions:
    """Test domain typo detection and correction."""

    def test_gmial_suggests_gmail(self):
        result = validate_email_address('user@gmial.com')
        assert result.valid is True
        assert result.reason == 'typo'
        assert result.suggestion == 'user@gmail.com'

    def test_hotmial_suggests_hotmail(self):
        result = validate_email_address('user@hotmial.com')
        assert result.valid is True
        assert result.reason == 'typo'
        assert result.suggestion == 'user@hotmail.com'

    def test_yahooo_suggests_yahoo(self):
        result = validate_email_address('user@yahooo.com')
        assert result.valid is True
        assert result.reason == 'typo'
        assert result.suggestion == 'user@yahoo.com'

    def test_gmail_con_suggests_gmail_com(self):
        result = validate_email_address('user@gmail.con')
        assert result.valid is True
        assert result.reason == 'typo'
        assert result.suggestion == 'user@gmail.com'

    def test_disable_typo_suggestions(self):
        result = validate_email_address('user@gmial.com', suggest_typo_fix=False)
        assert result.suggestion is None

    def test_typo_map_not_empty(self):
        assert len(DOMAIN_TYPOS) > 20

    def test_typo_suggestion_preserves_local_part(self):
        result = validate_email_address('complex+tag@gmial.com')
        assert result.suggestion == 'complex+tag@gmail.com'


class TestBlockedDomains:
    """Test custom blocked domain list."""

    def test_blocks_custom_domain(self):
        result = validate_email_address(
            'user@evil.com', blocked_domains=['evil.com']
        )
        assert result.valid is False
        assert result.reason == 'blocked'

    def test_blocked_domains_case_insensitive(self):
        result = validate_email_address(
            'user@EVIL.COM', blocked_domains=['evil.com']
        )
        assert result.valid is False
        assert result.reason == 'blocked'

    def test_non_blocked_domain_passes(self):
        result = validate_email_address(
            'user@good.com', blocked_domains=['evil.com']
        )
        assert result.valid is True


class TestAllowedDomains:
    """Test custom allowed domain list (bypass disposable check)."""

    def test_allowed_domain_bypasses_disposable(self):
        result = validate_email_address(
            'user@mailinator.com',
            allowed_domains=['mailinator.com'],
        )
        assert result.valid is True
        assert result.reason == 'valid'

    def test_allowed_domains_case_insensitive(self):
        result = validate_email_address(
            'user@MAILINATOR.COM',
            allowed_domains=['mailinator.com'],
        )
        assert result.valid is True


class TestIsValidEmailSyntax:
    """Test quick syntax-only validation."""

    def test_valid_email(self):
        assert is_valid_email_syntax('user@example.com') is True

    def test_invalid_email(self):
        assert is_valid_email_syntax('not-an-email') is False

    def test_empty_string(self):
        assert is_valid_email_syntax('') is False

    def test_consecutive_dots(self):
        assert is_valid_email_syntax('user..name@example.com') is False

    def test_leading_dot(self):
        assert is_valid_email_syntax('.user@example.com') is False

    def test_trailing_dot(self):
        assert is_valid_email_syntax('user.@example.com') is False

    def test_strips_whitespace(self):
        assert is_valid_email_syntax('  user@example.com  ') is True

    def test_too_long(self):
        email = 'a' * 200 + '@' + 'b' * 60 + '.com'
        assert is_valid_email_syntax(email) is False


class TestVerifyEmailMX:
    """Test MX verification (DNS lookup)."""

    def test_no_at_sign(self):
        assert verify_email_mx('noemail') is False

    def test_empty_domain(self):
        assert verify_email_mx('user@') is False


class TestEmailValidationResult:
    """Test the result dataclass."""

    def test_default_values(self):
        result = EmailValidationResult(valid=True, reason='valid')
        assert result.suggestion is None
        assert result.is_free is False
        assert result.is_disposable is False
        assert result.normalized == ''

    def test_all_fields(self):
        result = EmailValidationResult(
            valid=True,
            reason='typo',
            suggestion='user@gmail.com',
            is_free=True,
            is_disposable=False,
            normalized='user@gmial.com',
        )
        assert result.valid is True
        assert result.reason == 'typo'
        assert result.suggestion == 'user@gmail.com'
