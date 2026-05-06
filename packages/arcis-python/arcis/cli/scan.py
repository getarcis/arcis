"""
arcis scan — HTTP security vulnerability scanner.

Usage:
    arcis scan                                 # auto-discover server + routes
    arcis scan http://localhost:5000
    arcis scan http://localhost:3000 --route POST:/api/users --route GET:/search
    arcis scan http://localhost:8080 --route /api/login --field username --field password
    arcis scan http://localhost:5000 --categories xss sql nosql
    arcis scan --yes                           # skip the confirm prompt (CI)
    arcis scan --no-discovery http://localhost:5000  # opt out of source-aware routes
    arcis scan http://localhost:5000 --no-color
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from rich.prompt import Prompt

from arcis.cli.payloads import ATTACK_CATEGORIES, BLOCKED_STATUS_CODES, DEFAULT_FIELDS
from arcis.cli.report import RouteResult, VectorResult, print_report
from arcis.cli._console import err_console, live_status
from arcis.cli.discovery import (
    DiscoveredRoute,
    TargetCandidate,
    detect_target,
    discover_routes,
)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _parse_url(url: str) -> Tuple[str, int, str, bool]:
    """Return (host, port, path, is_https)."""
    parsed = urllib.parse.urlparse(url)
    is_https = parsed.scheme == "https"
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path, is_https


def _send(
    url: str,
    method: str,
    field: str,
    payload: str,
    timeout: int,
) -> Tuple[int, str]:
    """
    Send one request with the given payload injected into `field`.
    Returns (status_code, response_body). Status 0 means connection error.
    Uses http.client for persistent connections (faster on Windows).
    """
    try:
        # NoSQL payloads are JSON objects — keep them nested
        try:
            value: object = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            value = payload

        host, port, base_path, is_https = _parse_url(url)
        ConnClass = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
        conn = ConnClass(host, port, timeout=timeout)

        if method == "GET":
            encoded = urllib.parse.quote(str(payload), safe="")
            path = f"{base_path}{'&' if '?' in base_path else '?'}{field}={encoded}"
            conn.request("GET", path, headers={"Connection": "close"})
        else:
            body_bytes = json.dumps({field: value}).encode()
            conn.request(
                method,
                base_path,
                body=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body_bytes)),
                    "Connection": "close",
                },
            )

        resp = conn.getresponse()
        body = resp.read().decode(errors="replace")
        conn.close()
        return resp.status, body

    except Exception:
        return 0, ""


def _classify(status: int, body: str, payload: str) -> Tuple[bool, str]:
    """
    Decide if the payload was blocked.
    Returns (blocked: bool, note: str).
    """
    if status == 0:
        return False, "connection error"

    if status in BLOCKED_STATUS_CODES:
        return True, f"rejected ({status})"

    # Payload reflected verbatim → not sanitised
    if payload.strip().lower() in body.lower():
        return False, f"reflected in response ({status})"

    # 2xx but payload absent from body → sanitised / stripped
    if 200 <= status < 300:
        return True, f"sanitised ({status})"

    return False, f"status {status}"


# ── Route scanner ─────────────────────────────────────────────────────────────

def scan_route(
    base_url: str,
    method: str,
    path: str,
    fields: List[str],
    timeout: int,
    categories: Optional[List[str]],
    thorough: bool = False,
) -> RouteResult:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    result = RouteResult(method=method, path=path, reachable=False)

    # Probe the route with a harmless payload first; also find working field
    working_field = fields[0]
    for field in fields:
        probe_status, _ = _send(url, method, field, "hello", timeout)
        if probe_status == 0:
            result.error = "unreachable — is the server running?"
            return result
        if probe_status != 404:
            working_field = field
            break
    else:
        result.error = "404 not found"
        return result

    result.reachable = True

    active = {
        k: v for k, v in ATTACK_CATEGORIES.items()
        if categories is None or k.lower().replace(" ", "") in [c.lower().replace(" ", "") for c in categories]
    }

    # Build the full list of (category, label, payload) to test
    tasks: List[Tuple[str, str, str]] = []
    for category, vectors in active.items():
        test_vectors = vectors if thorough else [vectors[0]]
        for label, payload in test_vectors:
            tasks.append((category, label, payload))

    # Run all vectors in parallel (up to 10 concurrent requests)
    results_map: dict = {}

    def _test(idx: int, category: str, label: str, payload: str) -> Tuple[int, str, str, int, str]:
        status, body = _send(url, method, working_field, payload, timeout)
        blocked, note = _classify(status, body, payload)
        return idx, category, label, status, payload, blocked, note  # type: ignore[return-value]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_test, i, cat, lbl, pay): i
            for i, (cat, lbl, pay) in enumerate(tasks)
        }
        for future in as_completed(futures):
            idx, category, label, status, payload, blocked, note = future.result()
            results_map[idx] = VectorResult(
                category=category,
                label=label,
                payload=payload,
                status=status,
                blocked=blocked,
                note=note,
            )

    # Preserve original order
    result.vectors = [results_map[i] for i in range(len(tasks))]
    return result


# ── Discovery helpers ────────────────────────────────────────────────────────

def _is_interactive() -> bool:
    """True only when both stdin and stdout are TTYs. CI / piped runs are
    treated as non-interactive so we never block on a prompt."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _parse_route_args(raw_routes: Sequence[str]) -> List[Tuple[str, str]]:
    """Turn --route arguments into (METHOD, path) tuples. Bare paths
    default to POST so `--route /api/login` still works."""
    out: List[Tuple[str, str]] = []
    for r in raw_routes:
        if ":" in r and not r.startswith("http"):
            method, path = r.split(":", 1)
            out.append((method.upper(), path))
        else:
            out.append(("POST", r))
    return out


def _resolve_target(
    args: argparse.Namespace,
    cwd: Path,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve the scan target. Returns (url, source, framework_hint).

    Order of preference (handled by `detect_target`):
        1. .env / .env.local
        2. Local control-plane workspace endpoint
        3. Localhost dev port sniff

    If multiple candidates and the run is interactive (no --yes), the
    user picks one. CI auto-takes the first.
    """
    if args.url:
        if not args.url.startswith(("http://", "https://")):
            err_console.print(
                f"  [yellow]Invalid URL scheme:[/] {args.url}"
            )
            err_console.print(
                "  Only [bold]http://[/] and [bold]https://[/] are supported. "
                "Pass a full base URL like http://localhost:5000."
            )
            sys.exit(2)
        return args.url, "argv", None

    candidates = detect_target(
        cwd,
        include_control_plane=not args.no_control_plane,
    )
    if not candidates:
        return None, None, None
    if len(candidates) == 1 or args.yes or not _is_interactive():
        c = candidates[0]
        return c.url, c.source, c.framework
    return _pick_target(candidates)


def _pick_target(
    candidates: Sequence[TargetCandidate],
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Interactive prompt for choosing among multiple discovered targets."""
    err_console.print()
    err_console.print(f"  [bold cyan]Found {len(candidates)} candidate servers:[/]")
    for i, c in enumerate(candidates, start=1):
        framework = f" [dim]({c.framework})[/]" if c.framework else ""
        err_console.print(f"    [bold]{i}.[/] {c.url}  [dim]via {c.source}[/]{framework}")
    err_console.print()
    choices = [str(i) for i in range(1, len(candidates) + 1)] + ["q"]
    answer = Prompt.ask("  Scan which?", choices=choices, default="1")
    if answer == "q":
        return None, None, None
    c = candidates[int(answer) - 1]
    return c.url, c.source, c.framework


def _print_no_target_tip() -> None:
    """Surrender path: discovery returned nothing usable."""
    err_console.print()
    err_console.print("  [yellow][bold]Could not auto-detect a running server.[/][/]")
    err_console.print("    [dim]No process listening on common dev ports (3000, 5000, 5001, 8000, 8080, 4000, 8888).[/]")
    err_console.print("    [dim]No PORT or BASE_URL in .env / .env.local.[/]")
    err_console.print("    [dim]No active workspace at the local control-plane.[/]")
    err_console.print()
    err_console.print("  [bold]Tip:[/]  start your server first, or pass the URL explicitly:")
    err_console.print("    [bold]arcis scan http://localhost:<port>[/]")
    err_console.print("  Run from the project root so route discovery can find your handlers.")
    err_console.print()


def _print_no_routes_warning(target_url: str) -> None:
    """Print after a fallback to POST / when discovery yielded nothing."""
    err_console.print(
        "[yellow]  No routes discovered from source. Falling back to POST /.[/]"
    )
    err_console.print(
        "[dim]    Tip: pass --route POST:/api/login or similar to scan real endpoints, "
        "or run from a project root with package.json / pyproject.toml / go.mod.[/]"
    )


def _confirm_plan(
    *,
    args: argparse.Namespace,
    target_url: str,
    target_source: Optional[str],
    target_framework: Optional[str],
    routes: Sequence[Tuple[str, str]],
    discovered_routes: Sequence[DiscoveredRoute],
    routes_user_supplied: bool,
    categories: Optional[List[str]],
) -> bool:
    """Print the run plan. Prompt for confirmation only when interactive
    and `--yes` was not passed. Non-TTY auto-confirms (CI safe)."""
    err_console.print()
    framework_tag = f" [dim]({target_framework})[/]" if target_framework else ""
    source_tag = f"  [dim]via {target_source}[/]" if target_source else ""
    err_console.print(f"  [bold cyan]Target:[/] {target_url}{source_tag}{framework_tag}")

    if discovered_routes:
        method_counts = Counter(r.method for r in discovered_routes)
        breakdown = ", ".join(f"{n} {m}" for m, n in method_counts.most_common())
        err_console.print(
            f"  [bold cyan]Routes:[/] {len(discovered_routes)} discovered  [dim]({breakdown})[/]"
        )
    elif routes_user_supplied:
        err_console.print(
            f"  [bold cyan]Routes:[/] {len(routes)} from --route"
        )
    else:
        err_console.print(
            "  [bold cyan]Routes:[/] [yellow]none discovered, using POST /[/]"
        )

    cat_count = len(categories) if categories else len(ATTACK_CATEGORIES)
    if categories:
        wanted = {c.lower().replace(" ", "") for c in categories}
        active_counts = [
            len(v) for k, v in ATTACK_CATEGORIES.items()
            if k.lower().replace(" ", "") in wanted
        ]
    else:
        active_counts = [len(v) for v in ATTACK_CATEGORIES.values()]
    payloads_per_route = sum(active_counts) if args.thorough else len(active_counts)
    request_count = len(routes) * payloads_per_route
    err_console.print(
        f"  [bold cyan]Plan:[/]   {cat_count} attack categor"
        f"{'y' if cat_count == 1 else 'ies'}, ~{request_count} requests"
    )
    err_console.print()

    if args.yes or not _is_interactive():
        return True

    answer = Prompt.ask("  Continue?", choices=["y", "n"], default="y")
    return answer.lower().startswith("y")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis scan",
        description="Scan HTTP endpoints for common injection vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  arcis scan                                 # auto-discover server + routes
  arcis scan http://localhost:5000
  arcis scan http://localhost:3000 --route POST:/api/users --route GET:/search
  arcis scan http://localhost:8080 --route /api/login --field username --field password
  arcis scan http://localhost:5000 --categories xss sql nosql
  arcis scan --yes                           # skip the confirm prompt (CI)
        """,
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="Base URL of the running server (e.g. http://localhost:5000). "
             "Omit to auto-detect via .env / control-plane / dev-port sniff.",
    )
    parser.add_argument(
        "--route", "-r",
        action="append",
        dest="routes",
        metavar="[METHOD:]PATH",
        help=(
            "Route to test. Format: 'POST:/api/users' or just '/api/users' (defaults to POST). "
            "Repeat to test multiple routes. Skips source-aware discovery when set."
        ),
    )
    parser.add_argument(
        "--field", "-f",
        action="append",
        dest="fields",
        metavar="NAME",
        help=(
            "JSON field name to inject payloads into (default: tries common names). "
            "Repeat for multiple fields."
        ),
    )
    parser.add_argument(
        "--categories", "-c",
        nargs="+",
        metavar="CATEGORY",
        help=(
            f"Attack categories to test (default: all). "
            f"Choices: {', '.join(ATTACK_CATEGORIES.keys())}"
        ),
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=5,
        help="Per-request timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--thorough",
        action="store_true",
        help="Test all payloads per category instead of just the primary one (slower)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured terminal output",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all attack categories and their payloads, then exit.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-route progress output (still prints summary).",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip the confirm prompt before scanning (CI-friendly).",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        help="Skip source-aware route discovery; use --route flags or POST / fallback.",
    )
    parser.add_argument(
        "--no-control-plane",
        action="store_true",
        help="Skip the local control-plane probe during target discovery.",
    )

    args = parser.parse_args()

    if args.list:
        _print_payload_catalog(no_color=args.no_color)
        sys.exit(0)

    cwd = Path.cwd()

    # Resolve target. If discovery yields nothing usable, surrender clearly.
    target_url, target_source, target_framework = _resolve_target(args, cwd)
    if target_url is None:
        _print_no_target_tip()
        sys.exit(2)

    # Resolve routes. Three paths:
    #   1. User passed --route flags         -> use them, skip discovery
    #   2. --no-discovery and no --route     -> POST / fallback
    #   3. Default: source-aware route walk; if empty, POST / fallback
    routes_user_supplied = bool(args.routes)
    discovered_routes: List[DiscoveredRoute] = []

    if routes_user_supplied:
        routes = _parse_route_args(args.routes)
    elif args.no_discovery:
        routes = [("POST", "/")]
    else:
        discovered_routes = discover_routes(cwd)
        if discovered_routes:
            routes = [(r.method, r.path) for r in discovered_routes]
        else:
            routes = [("POST", "/")]

    fields = args.fields or DEFAULT_FIELDS
    categories = args.categories  # None = all

    if not _confirm_plan(
        args=args,
        target_url=target_url,
        target_source=target_source,
        target_framework=target_framework,
        routes=routes,
        discovered_routes=discovered_routes,
        routes_user_supplied=routes_user_supplied,
        categories=categories,
    ):
        err_console.print("  [dim]Cancelled.[/]")
        sys.exit(0)

    if not routes_user_supplied and not discovered_routes and not args.no_discovery:
        # Fallback ran. Make the user aware before the tip prints later.
        _print_no_routes_warning(target_url)

    use_live = not args.quiet and not args.no_color
    start = time.time()
    route_results: List[RouteResult] = []

    if not args.quiet:
        category_count = len(categories) if categories else len(ATTACK_CATEGORIES)
        err_console.print(
            f"Scanning {target_url}. {len(routes)} route(s), {category_count} categories"
        )

    if use_live:
        with live_status(initial="Probing routes...") as status:
            for i, (method, path) in enumerate(routes, start=1):
                status.update(
                    f"Probing [bold]{method} {path}[/]  ({i}/{len(routes)} routes)"
                )
                rr = scan_route(target_url, method, path, fields, args.timeout, categories, thorough=args.thorough)
                route_results.append(rr)
                if not rr.reachable:
                    err_console.print(
                        f"[yellow]  {method} {path}  skipped: {rr.error or 'unreachable'}[/]"
                    )
                else:
                    blocked = sum(1 for v in rr.vectors if v.blocked)
                    total = len(rr.vectors)
                    err_console.print(
                        f"[dim]  {method} {path}  fired {total} payload(s), "
                        f"{blocked} blocked, {total - blocked} got through[/]"
                    )
    else:
        for method, path in routes:
            rr = scan_route(target_url, method, path, fields, args.timeout, categories, thorough=args.thorough)
            route_results.append(rr)

    duration = time.time() - start
    print_report(target_url, route_results, duration, no_color=args.no_color)

    # Empty-run tip: when neither user nor discovery contributed routes
    # and the POST / fallback came back unreachable. Tells the user
    # exactly which flag they need.
    no_routes_reachable = all(not rr.reachable for rr in route_results)
    fell_back_to_root = not routes_user_supplied and not discovered_routes
    if no_routes_reachable and fell_back_to_root:
        bold = "" if args.no_color else "\033[1m"
        yellow = "" if args.no_color else "\033[33m"
        dim = "" if args.no_color else "\033[2m"
        reset = "" if args.no_color else "\033[0m"
        print()
        print(f"  {yellow}{bold}Tip{reset}{yellow}: nothing reachable at the default route.{reset}")
        print(f"  {dim}Run from your project root so source-aware discovery can find handlers,{reset}")
        print(f"  {dim}or pass real routes from your app:{reset}")
        print(f"    {bold}arcis scan {target_url} --route POST:/api/login --field email{reset}")
        print(f"    {bold}arcis scan {target_url} --route GET:/api/search --field q{reset}")
        print()

    # Upload to dashboard if ARCIS_ENDPOINT is set. Send full per-route
    # vector results (capped to 500 entries) so the dashboard drill-down
    # can show which payload reached each route.
    try:
        from .dashboard import upload as dashboard_upload
        dashboard_routes = []
        upload_vector_count = 0
        for rr in route_results:
            route_payload = {
                "method": rr.method,
                "path": rr.path,
                "reachable": rr.reachable,
                "error": rr.error,
                "vectors": [],
            }
            for v in rr.vectors:
                if upload_vector_count >= 500:
                    break
                route_payload["vectors"].append({
                    "category": v.category,
                    "label": v.label,
                    "payload": (v.payload or "")[:200],
                    "status": v.status,
                    "blocked": v.blocked,
                    "note": v.note,
                })
                upload_vector_count += 1
            dashboard_routes.append(route_payload)

        total_blocked = sum(1 for rr in route_results for v in rr.vectors if v.blocked)
        total_vulnerable = sum(1 for rr in route_results for v in rr.vectors if not v.blocked)
        total_vectors = sum(len(rr.vectors) for rr in route_results)
        dashboard_upload(
            kind="scans",
            body={
                "language": "endpoint-scan",
                "target": target_url,
                "summary": {
                    "routesScanned": sum(1 for rr in route_results if rr.reachable),
                    "routesTotal": len(route_results),
                    "totalVectors": total_vectors,
                    "totalBlocked": total_blocked,
                    "totalVulnerable": total_vulnerable,
                    "durationSeconds": round(duration, 3),
                    "routes": dashboard_routes,
                    "truncated": upload_vector_count >= 500,
                },
                "findingsCount": total_vulnerable,
            },
            quiet=args.quiet,
        )
    except Exception:
        pass

    # Exit 1 if any vulnerabilities found (useful for CI)
    any_vulnerable = any(
        not v.blocked
        for rr in route_results
        for v in rr.vectors
    )
    sys.exit(1 if any_vulnerable else 0)


def _print_payload_catalog(no_color: bool = False) -> None:
    """Render the attack catalog — what `arcis scan --list` shows."""
    bold = "" if no_color else "\033[1m"
    dim = "" if no_color else "\033[2m"
    cyan = "" if no_color else "\033[36m"
    reset = "" if no_color else "\033[0m"

    total = sum(len(v) for v in ATTACK_CATEGORIES.values())
    print()
    print(f"  {bold}arcis scan — attack catalog ({len(ATTACK_CATEGORIES)} categories, {total} payloads){reset}")
    print(f"  {dim}Pass --categories to narrow scope, e.g. --categories xss sql{reset}")
    print()
    for category, vectors in ATTACK_CATEGORIES.items():
        slug = category.lower().replace(" ", "")
        print(f"  {bold}{category}{reset}  {dim}({slug}){reset}")
        for label, payload in vectors:
            preview = payload if len(payload) <= 60 else payload[:57] + "..."
            print(f"    {cyan}{label.ljust(18)}{reset} {preview}")
        print()
    print(f"  {bold}Default fields tried (--field overrides){reset}")
    print(f"    {', '.join(DEFAULT_FIELDS)}")
    print()
