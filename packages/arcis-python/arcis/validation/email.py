"""
Arcis Validation - Email Validation

Advanced email validation with disposable detection and typo suggestions.

Three levels:
1. Syntax — RFC-compliant format checking
2. Domain intelligence — disposable/free provider detection, typo correction
3. MX verification — DNS MX record lookup (optional)

Examples:
    >>> validate_email_address('user@tempmail.com')
    EmailValidationResult(valid=False, reason='disposable')

    >>> validate_email_address('user@gmial.com')
    EmailValidationResult(valid=True, reason='typo', suggestion='user@gmail.com')
"""

import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional

# RFC 5321 limits
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 255

_EMAIL_SYNTAX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
)

FREE_PROVIDERS = frozenset([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'protonmail.com', 'proton.me', 'icloud.com', 'mail.com', 'zoho.com',
    'yandex.com', 'gmx.com', 'gmx.net', 'live.com', 'msn.com',
    'me.com', 'mac.com', 'fastmail.com', 'tutanota.com', 'hey.com',
])

DISPOSABLE_DOMAINS = frozenset([
    'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
    'tempmail.com', 'temp-mail.org', 'temp-mail.io',
    'throwaway.email', 'throwaway.com',
    'mailinator.com', 'mailinator.net',
    'yopmail.com', 'yopmail.fr', 'yopmail.net',
    'sharklasers.com', 'grr.la', 'guerrillamail.info',
    'guerrillamail.biz', 'guerrillamail.de',
    'trashmail.com', 'trashmail.me', 'trashmail.net',
    'dispostable.com', 'maildrop.cc',
    'mailnesia.com', 'tempail.com',
    'mohmal.com', 'getnada.com',
    'emailondeck.com', 'discard.email',
    'fakeinbox.com', 'mailcatch.com',
    'mintemail.com', 'tempr.email',
    'tempinbox.com', 'burnermail.io',
    'mailsac.com', 'harakirimail.com',
    'tempmailo.com', 'emailfake.com',
    'crazymailing.com', 'armyspy.com',
    'dayrep.com', 'einrot.com',
    'fleckens.hu', 'gustr.com',
    'jourrapide.com', 'rhyta.com',
    'superrito.com', 'teleworm.us',
    '10minutemail.com', '10minutemail.net',
    'minutemail.com', 'tempsky.com',
    'spamgourmet.com', 'mytrashmail.com',
    'mailexpire.com', 'safetymail.info',
    'filzmail.com', 'trashymail.com',
    'sharkmail.com', 'jetable.org',
    'nospam.ze.tc', 'trash-me.com',
    'dodgit.com', 'mailmoat.com',
    'spamfree24.org', 'incognitomail.org',
    'tempomail.fr', 'ephemail.net',
    'hidemail.de', 'spaml.de',
    'uggsrock.com', 'binkmail.com',
    'suremail.info', 'bugmenot.com',
])

DOMAIN_TYPOS = {
    'gmial.com': 'gmail.com',
    'gmaill.com': 'gmail.com',
    'gmai.com': 'gmail.com',
    'gamil.com': 'gmail.com',
    'gnail.com': 'gmail.com',
    'gmal.com': 'gmail.com',
    'gmil.com': 'gmail.com',
    'gmail.co': 'gmail.com',
    'gmail.cm': 'gmail.com',
    'gmail.om': 'gmail.com',
    'gmail.con': 'gmail.com',
    'gmail.cim': 'gmail.com',
    'gmail.comm': 'gmail.com',
    'yahooo.com': 'yahoo.com',
    'yaho.com': 'yahoo.com',
    'yahoo.co': 'yahoo.com',
    'yahoo.cm': 'yahoo.com',
    'yahoo.con': 'yahoo.com',
    'yahho.com': 'yahoo.com',
    'hotmial.com': 'hotmail.com',
    'hotmal.com': 'hotmail.com',
    'hotmai.com': 'hotmail.com',
    'hotmil.com': 'hotmail.com',
    'hotmail.co': 'hotmail.com',
    'hotmail.cm': 'hotmail.com',
    'hotmail.con': 'hotmail.com',
    'outlok.com': 'outlook.com',
    'outloo.com': 'outlook.com',
    'outlook.co': 'outlook.com',
    'outlook.cm': 'outlook.com',
    'protonmal.com': 'protonmail.com',
    'protonmail.co': 'protonmail.com',
    'icloud.co': 'icloud.com',
    'icloud.cm': 'icloud.com',
    'icoud.com': 'icloud.com',
}


@dataclass
class EmailValidationResult:
    """Result of email validation."""
    valid: bool
    reason: str  # 'valid', 'invalid_syntax', 'disposable', 'no_mx', 'blocked', 'typo'
    suggestion: Optional[str] = None
    is_free: bool = False
    is_disposable: bool = False
    normalized: str = ''


def validate_email_address(
    email: str,
    *,
    check_disposable: bool = True,
    suggest_typo_fix: bool = True,
    blocked_domains: Optional[List[str]] = None,
    allowed_domains: Optional[List[str]] = None,
) -> EmailValidationResult:
    """
    Validate an email address with syntax checking, disposable detection,
    and typo suggestions.

    Args:
        email: Email address to validate.
        check_disposable: Block disposable email providers. Default: True.
        check_free: Flag free email providers. Default: False.
        suggest_typo_fix: Suggest corrections for domain typos. Default: True.
        blocked_domains: Additional domains to block.
        allowed_domains: Domains that bypass disposable check.

    Returns:
        EmailValidationResult with validation details.

    Examples:
        >>> validate_email_address('user@gmail.com')
        EmailValidationResult(valid=True, reason='valid', is_free=True)

        >>> validate_email_address('user@tempmail.com')
        EmailValidationResult(valid=False, reason='disposable')
    """
    normalized = email.strip().lower()

    # Basic length check
    if not normalized or len(normalized) > MAX_EMAIL_LENGTH:
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)

    at_index = normalized.rfind('@')
    if at_index == -1:
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)

    local_part = normalized[:at_index]
    domain = normalized[at_index + 1:]

    # Length checks
    if not local_part or len(local_part) > MAX_LOCAL_LENGTH:
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)

    # Consecutive dots
    if '..' in local_part:
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)

    # Leading/trailing dots
    if local_part.startswith('.') or local_part.endswith('.'):
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)

    # Full regex
    if not _EMAIL_SYNTAX.match(normalized):
        return EmailValidationResult(valid=False, reason='invalid_syntax', normalized=normalized)

    # Allowed domains bypass
    allowed_set = set(d.lower() for d in (allowed_domains or []))
    if domain in allowed_set:
        return EmailValidationResult(
            valid=True, reason='valid', is_free=domain in FREE_PROVIDERS,
            is_disposable=False, normalized=normalized,
        )

    # Blocked domains
    blocked_set = set(d.lower() for d in (blocked_domains or []))
    if domain in blocked_set:
        return EmailValidationResult(valid=False, reason='blocked', normalized=normalized)

    # Disposable check
    is_disposable = domain in DISPOSABLE_DOMAINS
    if check_disposable and is_disposable:
        return EmailValidationResult(
            valid=False, reason='disposable', is_disposable=True, normalized=normalized,
        )

    # Typo check
    is_free = domain in FREE_PROVIDERS
    if suggest_typo_fix and domain in DOMAIN_TYPOS:
        corrected = f'{local_part}@{DOMAIN_TYPOS[domain]}'
        return EmailValidationResult(
            valid=True, reason='typo', suggestion=corrected,
            is_free=DOMAIN_TYPOS[domain] in FREE_PROVIDERS,
            is_disposable=False, normalized=normalized,
        )

    return EmailValidationResult(
        valid=True, reason='valid', is_free=is_free,
        is_disposable=is_disposable, normalized=normalized,
    )


def verify_email_mx(email: str) -> bool:
    """
    Verify that the email domain has MX records (can receive email).

    Performs a DNS lookup — requires network access.

    Args:
        email: Email address to verify.

    Returns:
        True if the domain has MX records.
    """
    if not is_valid_email_syntax(email):
        return False

    at_index = email.rfind('@')
    domain = email[at_index + 1:].strip().lower()
    if not domain:
        return False

    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except ImportError:
        # Fallback: try socket
        try:
            socket.getaddrinfo(domain, 25)
            return True
        except socket.gaierror:
            return False
    except Exception:
        return False


def is_valid_email_syntax(email: str) -> bool:
    """
    Quick check if an email address has valid syntax.
    Faster than validate_email_address() — just syntax, no domain intelligence.
    """
    normalized = email.strip().lower()
    if not normalized or len(normalized) > MAX_EMAIL_LENGTH:
        return False

    at_index = normalized.rfind('@')
    if at_index == -1:
        return False

    local_part = normalized[:at_index]
    if '..' in local_part or local_part.startswith('.') or local_part.endswith('.'):
        return False

    return bool(_EMAIL_SYNTAX.match(normalized))
