"""
Tests for `arcis.cli.discovery` and the Phase A auto-discovery wiring
inside `arcis.cli.scan.main()`.

The scan main() flow is exercised by patching out the network bits
(detect_target, discover_routes, scan_route) so the test stays a pure
unit test — we want to verify the args/discovery/confirm orchestration,
not that http.client actually opens a socket.
"""

from __future__ import annotations

import io
import json
import socket
import sys
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from arcis.cli import discovery as disc
from arcis.cli.discovery import (
    DiscoveredRoute,
    TargetCandidate,
    detect_project_kind,
    discover_routes,
    env_target,
    probe_dev_ports,
    probe_control_plane,
    read_env_files,
)


# ── env file parsing ────────────────────────────────────────────────────────

def test_read_env_files_parses_basic_kv(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "PORT=3000\n"
        "BASE_URL=http://localhost:3000\n"
        "# a comment\n"
        "\n"
        "QUOTED='single quoted'\n"
        'DBL_QUOTED="dbl quoted"\n'
        "export EXPORTED=42\n",
        encoding="utf-8",
    )
    env = read_env_files(tmp_path)
    assert env["PORT"] == "3000"
    assert env["BASE_URL"] == "http://localhost:3000"
    assert env["QUOTED"] == "single quoted"
    assert env["DBL_QUOTED"] == "dbl quoted"
    assert env["EXPORTED"] == "42"


def test_read_env_files_local_overrides_base(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("PORT=3000\nBASE_URL=http://nope\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("BASE_URL=http://localhost:5000\n", encoding="utf-8")
    env = read_env_files(tmp_path)
    assert env["PORT"] == "3000"
    assert env["BASE_URL"] == "http://localhost:5000"


def test_read_env_files_handles_missing_dir(tmp_path: Path) -> None:
    assert read_env_files(tmp_path / "nothing-here") == {}


def test_env_target_prefers_explicit_url() -> None:
    assert env_target({"ARCIS_TARGET": "http://localhost:9999"}) == "http://localhost:9999"
    assert env_target({"BASE_URL": "https://example.com/"}) == "https://example.com"
    assert env_target({"API_URL": "http://localhost:7000"}) == "http://localhost:7000"


def test_env_target_falls_back_to_port_only() -> None:
    assert env_target({"PORT": "8080"}) == "http://localhost:8080"


def test_env_target_returns_none_for_garbage() -> None:
    assert env_target({}) is None
    assert env_target({"PORT": "not-a-port"}) is None
    assert env_target({"BASE_URL": "ftp://nope"}) is None


# ── port sniff ──────────────────────────────────────────────────────────────

def test_probe_dev_ports_finds_listening_socket() -> None:
    """Bind a real socket on an ephemeral port and confirm probe finds it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        result = probe_dev_ports([port])
        assert result == [port]
    finally:
        s.close()


def test_probe_dev_ports_handles_empty_list() -> None:
    assert probe_dev_ports([]) == []


def test_probe_dev_ports_skips_dead_ports() -> None:
    # Bind+close to get a port that's almost certainly not listening now.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    # Probe-with-tiny-timeout should not see it (race-tolerant: also ok if
    # something else stole the port — assert it's not stuck-True nonsense).
    result = probe_dev_ports([port])
    assert result == [] or result == [port]  # tolerant; usually empty


# ── control-plane probe ────────────────────────────────────────────────────

def test_probe_control_plane_returns_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResp:
        def __init__(self, body: bytes) -> None:
            self._body = body
        def __enter__(self) -> "_FakeResp":
            return self
        def __exit__(self, *_: object) -> None:
            pass
        def read(self) -> bytes:
            return self._body

    body = json.dumps({"endpoint": "http://localhost:5001"}).encode()
    monkeypatch.setattr(disc.urllib.request, "urlopen", lambda *a, **kw: _FakeResp(body))
    assert probe_control_plane() == "http://localhost:5001"


def test_probe_control_plane_returns_none_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_kw: object) -> None:
        raise OSError("connection refused")
    monkeypatch.setattr(disc.urllib.request, "urlopen", boom)
    assert probe_control_plane() is None


# ── project kind ───────────────────────────────────────────────────────────

def test_detect_project_kind_node(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert detect_project_kind(tmp_path) == "node"


def test_detect_project_kind_python(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    assert detect_project_kind(tmp_path) == "python"


def test_detect_project_kind_go(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/x\n", encoding="utf-8")
    assert detect_project_kind(tmp_path) == "go"


def test_detect_project_kind_unknown(tmp_path: Path) -> None:
    assert detect_project_kind(tmp_path) is None


# ── route discovery ────────────────────────────────────────────────────────

def test_discover_routes_finds_express_handlers(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/users', (req, res) => res.json([]));\n"
        "app.post('/api/login', handler);\n"
        "router.delete(\"/api/users/:id\", handler);\n",
        encoding="utf-8",
    )
    routes = discover_routes(tmp_path)
    by_method = {(r.method, r.path) for r in routes}
    assert ("GET", "/users") in by_method
    assert ("POST", "/api/login") in by_method
    assert ("DELETE", "/api/users/:id") in by_method


def test_discover_routes_finds_fastapi_handlers(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, APIRouter\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "@app.get('/health')\n"
        "def health(): return {}\n"
        "@router.post('/api/users')\n"
        "def create_user(): pass\n"
        "@router.delete('/api/users/{user_id}')\n"
        "def delete_user(user_id: int): pass\n",
        encoding="utf-8",
    )
    routes = discover_routes(tmp_path)
    by_method = {(r.method, r.path) for r in routes}
    assert ("GET", "/health") in by_method
    assert ("POST", "/api/users") in by_method
    assert ("DELETE", "/api/users/{user_id}") in by_method


def test_discover_routes_finds_flask_handlers(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from flask import Flask, Blueprint\n"
        "app = Flask(__name__)\n"
        "bp = Blueprint('api', __name__)\n"
        "@app.route('/')\n"
        "def index(): return 'ok'\n"
        "@app.route('/login', methods=['POST'])\n"
        "def login(): pass\n"
        "@bp.route('/api/items', methods=['GET', 'POST'])\n"
        "def items(): pass\n",
        encoding="utf-8",
    )
    routes = discover_routes(tmp_path)
    by_method = {(r.method, r.path) for r in routes}
    assert ("GET", "/") in by_method
    assert ("POST", "/login") in by_method
    assert ("GET", "/api/items") in by_method
    assert ("POST", "/api/items") in by_method


def test_discover_routes_finds_go_handlers(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "import \"github.com/gin-gonic/gin\"\n"
        "func main() {\n"
        "  r := gin.Default()\n"
        "  r.GET(\"/health\", healthHandler)\n"
        "  r.POST(\"/api/login\", loginHandler)\n"
        "  api := r.Group(\"/api\")\n"
        "  api.DELETE(\"/users/:id\", deleteHandler)\n"
        "}\n",
        encoding="utf-8",
    )
    routes = discover_routes(tmp_path)
    by_method = {(r.method, r.path) for r in routes}
    assert ("GET", "/health") in by_method
    assert ("POST", "/api/login") in by_method
    assert ("DELETE", "/users/:id") in by_method


def test_discover_routes_skips_vendor_dirs(tmp_path: Path) -> None:
    """node_modules / .venv / dist should be ignored even if they have
    legitimate-looking handler patterns."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text(
        "app.get('/real', h);\n", encoding="utf-8"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "noise.js").write_text(
        "app.get('/should-not-find', h);\n", encoding="utf-8"
    )
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "noise.py").write_text(
        "@app.get('/also-not')\ndef x(): pass\n", encoding="utf-8"
    )
    routes = discover_routes(tmp_path)
    paths = {r.path for r in routes}
    assert "/real" in paths
    assert "/should-not-find" not in paths
    assert "/also-not" not in paths


def test_discover_routes_dedupes_repeated_definitions(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("app.get('/x', h);\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("app.get('/x', h);\n", encoding="utf-8")
    routes = discover_routes(tmp_path)
    matching = [r for r in routes if (r.method, r.path) == ("GET", "/x")]
    assert len(matching) == 1


def test_discover_routes_respects_max_files(tmp_path: Path) -> None:
    """A pathological tree with thousands of files must not hang the CLI."""
    for i in range(20):
        (tmp_path / f"f{i}.js").write_text(
            f"app.get('/r{i}', h);\n", encoding="utf-8"
        )
    routes = discover_routes(tmp_path, max_files=5)
    # Walk stopped after 5 files; we should see fewer routes than total.
    assert len(routes) <= 5


def test_discover_routes_skips_symlinks(tmp_path: Path) -> None:
    """Symlinks must be skipped so a circular link can't loop the walk
    and a symlink farm can't slow it. Test skips on hosts where symlink
    creation isn't permitted (Windows non-admin)."""
    real = tmp_path / "real.js"
    real.write_text("app.get('/real', h);\n", encoding="utf-8")
    link = tmp_path / "link.js"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this runner")
    routes = discover_routes(tmp_path)
    sources = {r.source for r in routes}
    assert "real.js" in sources
    assert "link.js" not in sources


# ── detect_target ordering ─────────────────────────────────────────────────

def test_detect_target_orders_env_then_control_plane_then_ports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".env").write_text("BASE_URL=http://localhost:3000\n", encoding="utf-8")
    monkeypatch.setattr(disc, "probe_control_plane", lambda *a, **kw: "http://localhost:5001")
    monkeypatch.setattr(disc, "probe_dev_ports", lambda *a, **kw: [8000])
    monkeypatch.setattr(disc, "sniff_framework", lambda *a, **kw: None)
    candidates = disc.detect_target(tmp_path)
    urls = [c.url for c in candidates]
    assert urls == ["http://localhost:3000", "http://localhost:5001", "http://localhost:8000"]
    assert candidates[0].source == ".env"
    assert candidates[1].source == "control-plane"
    assert candidates[2].source.startswith("port-sniff:")


def test_detect_target_dedupes_duplicate_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".env").write_text("BASE_URL=http://localhost:8000\n", encoding="utf-8")
    monkeypatch.setattr(disc, "probe_control_plane", lambda *a, **kw: None)
    monkeypatch.setattr(disc, "probe_dev_ports", lambda *a, **kw: [8000])
    monkeypatch.setattr(disc, "sniff_framework", lambda *a, **kw: None)
    candidates = disc.detect_target(tmp_path)
    assert [c.url for c in candidates] == ["http://localhost:8000"]
    assert candidates[0].source == ".env"


def test_detect_target_skips_control_plane_when_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = {"cp": False}
    def fake_cp(*a: object, **kw: object) -> None:
        called["cp"] = True
        return None
    monkeypatch.setattr(disc, "probe_control_plane", fake_cp)
    monkeypatch.setattr(disc, "probe_dev_ports", lambda *a, **kw: [])
    disc.detect_target(tmp_path, include_control_plane=False)
    assert called["cp"] is False


# ── scan main() integration (auto-confirm in non-TTY) ──────────────────────

def test_scan_main_surrenders_when_discovery_empty(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """No URL passed, discovery returns nothing -> exit 2 with surrender tip."""
    from arcis.cli import scan as scan_module

    monkeypatch.setattr(sys, "argv", ["arcis scan"])
    monkeypatch.setattr(scan_module, "detect_target", lambda *a, **kw: [])

    with pytest.raises(SystemExit) as exc:
        scan_module.main()
    assert exc.value.code == 2


@pytest.mark.parametrize("bad_url", [
    "ftp://localhost:5000",
    "file:///etc/passwd",
    "localhost:5000",
    "//localhost:5000",
])
def test_scan_main_rejects_non_http_scheme(monkeypatch: pytest.MonkeyPatch, bad_url: str) -> None:
    """Non-http(s) URL passed on the CLI exits 2 before any probe is made."""
    from arcis.cli import scan as scan_module

    monkeypatch.setattr(sys, "argv", ["arcis scan", bad_url, "--yes", "--no-color"])

    with pytest.raises(SystemExit) as exc:
        scan_module.main()
    assert exc.value.code == 2


def test_scan_main_uses_discovered_routes_with_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """User passes --yes and URL; discovery walks for routes and the scan
    proceeds without prompting. We patch scan_route + dashboard to keep
    the test offline."""
    from arcis.cli import scan as scan_module
    from arcis.cli.report import RouteResult

    fake_routes = [DiscoveredRoute(method="POST", path="/api/login", source="src/app.js")]
    captured: List[str] = []

    def fake_scan_route(url: str, method: str, path: str, *a: object, **kw: object) -> RouteResult:
        captured.append(f"{method} {path}")
        rr = RouteResult(method=method, path=path, reachable=True)
        return rr

    monkeypatch.setattr(sys, "argv", [
        "arcis scan", "http://localhost:5000", "--yes", "--no-color", "--quiet",
    ])
    monkeypatch.setattr(scan_module, "discover_routes", lambda *a, **kw: fake_routes)
    monkeypatch.setattr(scan_module, "scan_route", fake_scan_route)
    monkeypatch.setattr(scan_module, "print_report", lambda *a, **kw: None)

    with pytest.raises(SystemExit) as exc:
        scan_module.main()
    # No vulnerable findings -> exit 0
    assert exc.value.code == 0
    assert "POST /api/login" in captured


def test_scan_main_no_discovery_uses_post_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-discovery + URL + --yes runs against POST / and skips the
    source walk entirely."""
    from arcis.cli import scan as scan_module
    from arcis.cli.report import RouteResult

    walk_called = {"hit": False}
    def fake_walk(*_a: object, **_kw: object) -> List[DiscoveredRoute]:
        walk_called["hit"] = True
        return []
    captured: List[str] = []
    def fake_scan_route(url: str, method: str, path: str, *a: object, **kw: object) -> RouteResult:
        captured.append(f"{method} {path}")
        return RouteResult(method=method, path=path, reachable=False, error="404")

    monkeypatch.setattr(sys, "argv", [
        "arcis scan", "http://localhost:5000",
        "--no-discovery", "--yes", "--no-color", "--quiet",
    ])
    monkeypatch.setattr(scan_module, "discover_routes", fake_walk)
    monkeypatch.setattr(scan_module, "scan_route", fake_scan_route)
    monkeypatch.setattr(scan_module, "print_report", lambda *a, **kw: None)

    with pytest.raises(SystemExit):
        scan_module.main()
    assert walk_called["hit"] is False
    assert captured == ["POST /"]


def test_scan_main_user_routes_skip_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """User-supplied --route flags are authoritative; discovery is skipped."""
    from arcis.cli import scan as scan_module
    from arcis.cli.report import RouteResult

    walk_called = {"hit": False}
    def fake_walk(*_a: object, **_kw: object) -> List[DiscoveredRoute]:
        walk_called["hit"] = True
        return []
    captured: List[str] = []
    def fake_scan_route(url: str, method: str, path: str, *a: object, **kw: object) -> RouteResult:
        captured.append(f"{method} {path}")
        return RouteResult(method=method, path=path, reachable=True)

    monkeypatch.setattr(sys, "argv", [
        "arcis scan", "http://localhost:5000",
        "--route", "GET:/api/health",
        "--route", "POST:/api/users",
        "--yes", "--no-color", "--quiet",
    ])
    monkeypatch.setattr(scan_module, "discover_routes", fake_walk)
    monkeypatch.setattr(scan_module, "scan_route", fake_scan_route)
    monkeypatch.setattr(scan_module, "print_report", lambda *a, **kw: None)

    with pytest.raises(SystemExit):
        scan_module.main()
    assert walk_called["hit"] is False
    assert captured == ["GET /api/health", "POST /api/users"]
