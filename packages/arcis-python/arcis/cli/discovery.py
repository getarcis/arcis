"""
arcis scan auto-discovery — server target + source-aware route walk.

Phase A of cli-scan.md. The user types `arcis scan` with no args; we
discover the running server and the routes their app actually exposes.
Both pieces are best-effort: clear surrender path when discovery fails.

Discovery surfaces (in order of preference):

Target:
  1. Env vars in .env / .env.local: ARCIS_TARGET, BASE_URL, API_URL, PORT.
  2. Active workspace endpoint from the local control-plane at
     localhost:4000/v1/workspace/active (telemetry handoff: SDK has
     already phoned home with its host:port on startup).
  3. Localhost port sniff against the standard dev ports.

Routes:
  Walk CWD for handler patterns in JS/TS/Python/Go source. Vendor /
  build / cache dirs are skipped so a 50k-file monorepo doesn't hang.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple


# ── Constants ────────────────────────────────────────────────────────────────

DEV_PORTS: Tuple[int, ...] = (3000, 5000, 5001, 8000, 8080, 4000, 8888)

CONTROL_PLANE_URL = "http://localhost:4000/v1/workspace/active"

ENV_TARGET_KEYS: Tuple[str, ...] = ("ARCIS_TARGET", "BASE_URL", "API_URL")

SKIP_DIRS = frozenset({
    "node_modules", ".venv", "venv", ".git", "dist", "build",
    "__pycache__", ".next", "coverage", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "target", "vendor", ".tox", "out", ".cache",
    ".idea", ".vscode", ".turbo", ".parcel-cache", "site-packages",
})

SOURCE_EXTENSIONS: Tuple[str, ...] = (
    ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".go",
)

# Express / Fastify / Koa: app.METHOD("/...") or router.METHOD("/...").
# Captures method (group 1) and path string (group 2). Excludes `.use()`
# since middleware mounts aren't routes we can scan directly.
JS_ROUTE_RE = re.compile(
    r"""(?:app|router|api|server|route)\s*\.\s*(get|post|put|delete|patch|all|options)\s*\(\s*['"`]([^'"`\n]+?)['"`]""",
    re.IGNORECASE,
)

# FastAPI / Starlette: @app.method("/...") or @router.method("/...").
PY_FASTAPI_RE = re.compile(
    r"""@\s*(?:app|router|api)\s*\.\s*(get|post|put|delete|patch|options)\s*\(\s*['"]([^'"\n]+?)['"]""",
    re.IGNORECASE,
)

# Flask: @app.route("/x", methods=["POST"]) or @bp.route("/y").
PY_FLASK_RE = re.compile(
    r"""@\s*(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*['"]([^'"\n]+?)['"]([^)]*)\)""",
    re.IGNORECASE | re.DOTALL,
)

# Go (Gin / Echo / chi / net/http mux variants): r.GET("/x", ...) etc.
GO_ROUTE_RE = re.compile(
    r'(?:r|router|e|api|app|server|mux|g)\s*\.\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"\n]+?)"',
)


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class TargetCandidate:
    url: str
    source: str
    framework: Optional[str] = None


@dataclass
class DiscoveredRoute:
    method: str
    path: str
    source: str = ""


@dataclass
class DiscoveryReport:
    target: Optional[TargetCandidate]
    candidates: List[TargetCandidate] = field(default_factory=list)
    routes: List[DiscoveredRoute] = field(default_factory=list)
    project_kind: Optional[str] = None  # "node" / "python" / "go" / None


# ── Env file parsing ─────────────────────────────────────────────────────────

def read_env_files(cwd: Path) -> Dict[str, str]:
    """Read .env and .env.local in cwd; return merged env (.env.local wins)."""
    result: Dict[str, str] = {}
    for name in (".env", ".env.local"):
        path = cwd / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            if key:
                result[key] = value
    return result


def env_target(env: Dict[str, str]) -> Optional[str]:
    """Pull a usable target URL out of an env dict, or None."""
    for key in ENV_TARGET_KEYS:
        v = env.get(key, "").strip()
        if v.startswith(("http://", "https://")):
            return v.rstrip("/")
    port = env.get("PORT", "").strip()
    if port.isdigit():
        return f"http://localhost:{port}"
    return None


# ── Port + control-plane probes ──────────────────────────────────────────────

def _probe_port(port: int, timeout: float = 0.3) -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def probe_dev_ports(ports: Sequence[int] = DEV_PORTS) -> List[int]:
    """Return the subset of dev ports that have something listening.

    Order is preserved from the input sequence so callers see the
    canonical priority (Express :3000 first, etc.).
    """
    open_ports: List[int] = []
    if not ports:
        return open_ports
    with ThreadPoolExecutor(max_workers=len(ports)) as ex:
        future_to_port = {ex.submit(_probe_port, p): p for p in ports}
        for fut in as_completed(future_to_port):
            try:
                if fut.result():
                    open_ports.append(future_to_port[fut])
            except Exception:
                continue
    order = {p: i for i, p in enumerate(ports)}
    return sorted(open_ports, key=lambda p: order.get(p, 999))


def probe_control_plane(url: str = CONTROL_PLANE_URL, timeout: float = 0.5) -> Optional[str]:
    """Ask the local control-plane for the active workspace's endpoint."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if not isinstance(data, dict):
            return None
        for key in ("endpoint", "target", "url"):
            v = (data.get(key) or "").strip()
            if v.startswith(("http://", "https://")):
                return v.rstrip("/")
    except Exception:
        pass
    return None


def sniff_framework(port: int, timeout: float = 0.4) -> Optional[str]:
    """Send a HEAD / and inspect headers for a framework hint. Best-effort."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v.lower() for k, v in resp.getheaders()}
        try:
            resp.read()
        except Exception:
            pass
        conn.close()
    except Exception:
        return None
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    blob = f"{server} {powered}"
    if "uvicorn" in blob or "starlette" in blob:
        return "FastAPI"
    if "werkzeug" in blob or "flask" in blob:
        return "Flask"
    if "gunicorn" in blob:
        return "Python (gunicorn)"
    if "express" in blob:
        return "Express"
    if "fastify" in blob:
        return "Fastify"
    if "next" in blob:
        return "Next.js"
    if "fiber" in blob or "echo" in blob or "gin" in blob:
        return "Go"
    return None


# ── Project kind detection ───────────────────────────────────────────────────

def detect_project_kind(cwd: Path) -> Optional[str]:
    if (cwd / "package.json").is_file():
        return "node"
    if (cwd / "pyproject.toml").is_file() or (cwd / "requirements.txt").is_file():
        return "python"
    if (cwd / "go.mod").is_file():
        return "go"
    return None


# ── Source-aware route discovery ─────────────────────────────────────────────

def _iter_files(
    root: Path,
    exts: Tuple[str, ...],
    max_files: int,
) -> Iterator[Path]:
    """DFS over root, yielding files with the given extensions. Skips
    vendor / build / cache directories. Bounded by max_files so a giant
    repo doesn't hang the CLI."""
    count = 0
    stack: List[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                is_dir = entry.is_dir()
            except OSError:
                continue
            if is_dir:
                name = entry.name
                if name in SKIP_DIRS:
                    continue
                if name.startswith(".") and name not in {".", ".."}:
                    continue
                stack.append(entry)
                continue
            try:
                is_file = entry.is_file()
            except OSError:
                continue
            if is_file and entry.suffix.lower() in exts:
                count += 1
                yield entry
                if count >= max_files:
                    return


def _extract_flask_methods(suffix: str) -> List[str]:
    """Pull methods=[...] out of a Flask @route decorator suffix."""
    m = re.search(r"methods\s*=\s*\[([^\]]+)\]", suffix, re.IGNORECASE | re.DOTALL)
    if not m:
        return ["GET"]
    methods = re.findall(r"['\"]([A-Za-z]+)['\"]", m.group(1))
    return [m.upper() for m in methods] if methods else ["GET"]


def discover_routes(cwd: Path, max_files: int = 1500) -> List[DiscoveredRoute]:
    """Walk cwd for HTTP handler declarations across JS/TS/Python/Go.

    Returns a deduped list ordered by first-seen. Method is uppercased,
    path begins with `/`. Routes parameterised with framework path-params
    (`/users/:id`, `/users/{id}`) are kept verbatim since the scanner
    treats path strings as targets (placeholder substitution is Phase B).
    """
    routes: List[DiscoveredRoute] = []
    seen: set = set()

    for path in _iter_files(cwd, SOURCE_EXTENSIONS, max_files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        ext = path.suffix.lower()
        rel_source = _safe_relpath(path, cwd)

        if ext in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
            for m in JS_ROUTE_RE.finditer(text):
                method = m.group(1).upper()
                if method == "ALL":
                    method = "POST"
                _add_route(routes, seen, method, m.group(2), rel_source)
        elif ext == ".py":
            for m in PY_FASTAPI_RE.finditer(text):
                _add_route(routes, seen, m.group(1).upper(), m.group(2), rel_source)
            for m in PY_FLASK_RE.finditer(text):
                path_str = m.group(1)
                methods = _extract_flask_methods(m.group(2) or "")
                for method in methods:
                    _add_route(routes, seen, method, path_str, rel_source)
        elif ext == ".go":
            for m in GO_ROUTE_RE.finditer(text):
                _add_route(routes, seen, m.group(1).upper(), m.group(2), rel_source)

    return routes


def _add_route(
    out: List[DiscoveredRoute],
    seen: set,
    method: str,
    path_str: str,
    source: str,
) -> None:
    if not path_str.startswith("/"):
        return
    key = (method, path_str)
    if key in seen:
        return
    seen.add(key)
    out.append(DiscoveredRoute(method=method, path=path_str, source=source))


def _safe_relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


# ── Top-level discovery driver ───────────────────────────────────────────────

def detect_target(
    cwd: Path,
    *,
    include_control_plane: bool = True,
    ports: Sequence[int] = DEV_PORTS,
) -> List[TargetCandidate]:
    """Run every detection surface and return all candidate targets.

    Caller decides what to do with multiple candidates (auto-pick first,
    interactive prompt, etc.). Order: env > control-plane > port sniff.
    Duplicates by URL are collapsed; the first source wins.
    """
    candidates: List[TargetCandidate] = []
    seen_urls: set = set()

    def push(url: str, source: str, framework: Optional[str] = None) -> None:
        if not url or url in seen_urls:
            return
        seen_urls.add(url)
        candidates.append(TargetCandidate(url=url, source=source, framework=framework))

    env = read_env_files(cwd)
    env_url = env_target(env)
    if env_url:
        push(env_url, ".env")

    if include_control_plane:
        cp_url = probe_control_plane()
        if cp_url:
            push(cp_url, "control-plane")

    for port in probe_dev_ports(ports):
        framework = sniff_framework(port)
        push(f"http://localhost:{port}", f"port-sniff:{port}", framework)

    return candidates


def discover(cwd: Path) -> DiscoveryReport:
    """Convenience: run target detection + project-kind detection + route walk."""
    candidates = detect_target(cwd)
    target = candidates[0] if candidates else None
    project_kind = detect_project_kind(cwd)
    routes = discover_routes(cwd)
    return DiscoveryReport(
        target=target,
        candidates=candidates,
        routes=routes,
        project_kind=project_kind,
    )


__all__ = [
    "DEV_PORTS",
    "CONTROL_PLANE_URL",
    "ENV_TARGET_KEYS",
    "TargetCandidate",
    "DiscoveredRoute",
    "DiscoveryReport",
    "read_env_files",
    "env_target",
    "probe_dev_ports",
    "probe_control_plane",
    "sniff_framework",
    "detect_project_kind",
    "discover_routes",
    "detect_target",
    "discover",
]
