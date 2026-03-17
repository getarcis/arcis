"""
Request fingerprinting tests.
Tests for arcis/utils/fingerprint.py
"""

import hashlib
import pytest
from arcis.utils.fingerprint import fingerprint


class MockRequest:
    """Mock request with headers and remote_addr."""
    def __init__(self, headers=None, remote_addr='127.0.0.1'):
        self.headers = headers or {}
        self.remote_addr = remote_addr


class TestFingerprintDeterministic:
    """Test that fingerprints are deterministic and stable."""

    def test_same_request_same_fingerprint(self):
        req = MockRequest(
            headers={'user-agent': 'Mozilla/5.0', 'accept': 'text/html'},
            remote_addr='10.0.0.1',
        )
        fp1 = fingerprint(req, platform='generic')
        fp2 = fingerprint(req, platform='generic')
        assert fp1 == fp2

    def test_returns_64_char_hex(self):
        req = MockRequest(remote_addr='10.0.0.1')
        fp = fingerprint(req, platform='generic')
        assert len(fp) == 64
        assert all(c in '0123456789abcdef' for c in fp)

    def test_different_ips_different_fingerprints(self):
        req1 = MockRequest(remote_addr='10.0.0.1')
        req2 = MockRequest(remote_addr='10.0.0.2')
        assert fingerprint(req1, platform='generic') != fingerprint(req2, platform='generic')

    def test_different_user_agents_different_fingerprints(self):
        req1 = MockRequest(headers={'user-agent': 'Chrome'}, remote_addr='10.0.0.1')
        req2 = MockRequest(headers={'user-agent': 'Firefox'}, remote_addr='10.0.0.1')
        assert fingerprint(req1, platform='generic') != fingerprint(req2, platform='generic')


class TestFingerprintOptions:
    """Test toggling individual fingerprint components."""

    def test_ip_disabled(self):
        req1 = MockRequest(remote_addr='10.0.0.1')
        req2 = MockRequest(remote_addr='10.0.0.2')
        fp1 = fingerprint(req1, ip=False, user_agent=False, accept=False,
                          accept_language=False, accept_encoding=False, platform='generic')
        fp2 = fingerprint(req2, ip=False, user_agent=False, accept=False,
                          accept_language=False, accept_encoding=False, platform='generic')
        assert fp1 == fp2

    def test_user_agent_disabled(self):
        req1 = MockRequest(headers={'user-agent': 'A'}, remote_addr='10.0.0.1')
        req2 = MockRequest(headers={'user-agent': 'B'}, remote_addr='10.0.0.1')
        fp1 = fingerprint(req1, user_agent=False, platform='generic')
        fp2 = fingerprint(req2, user_agent=False, platform='generic')
        assert fp1 == fp2

    def test_all_disabled_produces_hash_of_empty(self):
        req = MockRequest(remote_addr='1.2.3.4')
        fp = fingerprint(
            req, ip=False, user_agent=False, accept=False,
            accept_language=False, accept_encoding=False, platform='generic',
        )
        expected = hashlib.sha256(''.encode('utf-8')).hexdigest()
        assert fp == expected


class TestFingerprintCustomComponents:
    """Test custom additional components."""

    def test_custom_component(self):
        req = MockRequest(remote_addr='10.0.0.1')
        fp1 = fingerprint(req, custom=['user_123'], platform='generic')
        fp2 = fingerprint(req, custom=['user_456'], platform='generic')
        assert fp1 != fp2

    def test_custom_none_values_ignored(self):
        req = MockRequest(remote_addr='10.0.0.1')
        fp1 = fingerprint(req, custom=['a', None, 'b'], platform='generic')
        fp2 = fingerprint(req, custom=['a', 'b'], platform='generic')
        assert fp1 == fp2

    def test_multiple_custom_components(self):
        req = MockRequest(remote_addr='10.0.0.1')
        fp1 = fingerprint(req, custom=['session_abc', 'tenant_xyz'], platform='generic')
        fp2 = fingerprint(req, custom=['session_abc'], platform='generic')
        assert fp1 != fp2

    def test_empty_custom_list(self):
        req = MockRequest(remote_addr='10.0.0.1')
        fp1 = fingerprint(req, custom=[], platform='generic')
        fp2 = fingerprint(req, platform='generic')
        assert fp1 == fp2


class TestFingerprintDjangoRequest:
    """Test fingerprint with Django-style META dict."""

    def test_django_request(self):
        class DjangoReq:
            META = {
                'HTTP_USER_AGENT': 'Mozilla/5.0',
                'HTTP_ACCEPT': 'text/html',
                'HTTP_ACCEPT_LANGUAGE': 'en-US',
                'HTTP_ACCEPT_ENCODING': 'gzip',
                'REMOTE_ADDR': '10.0.0.1',
            }

        req = DjangoReq()
        fp = fingerprint(req, platform='generic')
        assert len(fp) == 64

    def test_django_deterministic(self):
        class DjangoReq:
            META = {
                'HTTP_USER_AGENT': 'test',
                'REMOTE_ADDR': '1.2.3.4',
            }

        fp1 = fingerprint(DjangoReq(), platform='generic')
        fp2 = fingerprint(DjangoReq(), platform='generic')
        assert fp1 == fp2
