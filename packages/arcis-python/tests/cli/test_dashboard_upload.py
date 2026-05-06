"""
Tests for the CLI -> dashboard upload helper (`arcis.cli.dashboard.upload`).

Covers:
- silent skip when ARCIS_ENDPOINT is unset (zero-config local CLI usage)
- successful POST returns the new run id
- network failure returns None and never raises
- /v1/events suffix is stripped from ARCIS_ENDPOINT (telemetry vars reused)
- workspace + api-key headers are sent when env vars are set
"""

from unittest.mock import MagicMock, patch


from arcis.cli.dashboard import upload, _read_endpoint


class TestReadEndpoint:
    def test_returns_none_when_unset(self, monkeypatch):
        monkeypatch.delenv("ARCIS_ENDPOINT", raising=False)
        assert _read_endpoint() is None

    def test_returns_base_url(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://localhost:3333")
        assert _read_endpoint() == "http://localhost:3333"

    def test_strips_v1_events_suffix(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://localhost:3333/v1/events")
        assert _read_endpoint() == "http://localhost:3333"

    def test_strips_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://localhost:3333/")
        assert _read_endpoint() == "http://localhost:3333"


class TestUpload:
    def test_skips_when_endpoint_unset(self, monkeypatch):
        monkeypatch.delenv("ARCIS_ENDPOINT", raising=False)
        result = upload(kind="audits", body={"language": "python", "target": "."}, quiet=True)
        assert result is None

    def test_returns_id_on_success(self, monkeypatch, capsys):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://example.test")

        # Mock urlopen to return a fake response with a JSON body.
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": "audit_123_abc", "inserted": true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("arcis.cli.dashboard.urllib.request.urlopen", return_value=mock_resp):
            result = upload(
                kind="audits",
                body={"language": "python", "target": "."},
                quiet=True,
            )
        assert result == "audit_123_abc"

    def test_returns_none_on_network_failure(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://example.test")
        from urllib.error import URLError
        with patch(
            "arcis.cli.dashboard.urllib.request.urlopen",
            side_effect=URLError("Connection refused"),
        ):
            result = upload(
                kind="audits",
                body={"language": "python", "target": "."},
                quiet=True,
            )
        assert result is None

    def test_returns_none_on_http_error(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://example.test")
        from urllib.error import HTTPError
        with patch(
            "arcis.cli.dashboard.urllib.request.urlopen",
            side_effect=HTTPError("url", 500, "Server Error", {}, None),
        ):
            result = upload(kind="audits", body={"language": "python", "target": "."}, quiet=True)
        assert result is None

    def test_sends_workspace_and_auth_headers(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://example.test")
        monkeypatch.setenv("ARCIS_WORKSPACE_ID", "ws_test")
        monkeypatch.setenv("ARCIS_KEY", "secret-key")

        captured = {}
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": "x"}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            captured["body"] = req.data
            return mock_resp

        with patch("arcis.cli.dashboard.urllib.request.urlopen", side_effect=fake_urlopen):
            upload(kind="audits", body={"language": "python", "target": "."}, quiet=True)

        assert captured["url"] == "http://example.test/v1/audits"
        assert captured["headers"]["x-workspace-id"] == "ws_test"
        assert captured["headers"]["authorization"] == "Bearer secret-key"

    def test_routes_to_correct_kind(self, monkeypatch):
        monkeypatch.setenv("ARCIS_ENDPOINT", "http://example.test")
        captured_url = {}
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": "x"}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        def fake_urlopen(req, timeout=None):
            captured_url["url"] = req.full_url
            return mock_resp

        with patch("arcis.cli.dashboard.urllib.request.urlopen", side_effect=fake_urlopen):
            upload(kind="scans", body={"language": "endpoint-scan", "target": "x"}, quiet=True)
        assert captured_url["url"] == "http://example.test/v1/scans"
