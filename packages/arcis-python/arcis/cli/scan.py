"""
arcis scan — HTTP security vulnerability scanner.

Usage:
    arcis scan http://localhost:5000
    arcis scan http://localhost:3000 --route POST:/api/users --route GET:/search
    arcis scan http://localhost:8080 --route /api/login --field username --field password
    arcis scan http://localhost:5000 --categories xss sql nosql
    arcis scan http://localhost:5000 --no-color
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

from arcis.cli.payloads import ATTACK_CATEGORIES, BLOCKED_STATUS_CODES, DEFAULT_FIELDS
from arcis.cli.report import RouteResult, VectorResult, print_report


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


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis scan",
        description="Scan HTTP endpoints for common injection vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  arcis scan http://localhost:5000
  arcis scan http://localhost:3000 --route POST:/api/users --route GET:/search
  arcis scan http://localhost:8080 --route /api/login --field username --field password
  arcis scan http://localhost:5000 --categories xss sql nosql
        """,
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="Base URL of the running server (e.g. http://localhost:5000)",
    )
    parser.add_argument(
        "--route", "-r",
        action="append",
        dest="routes",
        metavar="[METHOD:]PATH",
        help=(
            "Route to test. Format: 'POST:/api/users' or just '/api/users' (defaults to POST). "
            "Repeat to test multiple routes."
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

    args = parser.parse_args()

    if args.list:
        _print_payload_catalog(no_color=args.no_color)
        sys.exit(0)

    if not args.url:
        parser.print_usage()
        print("\narcis scan: missing required URL. Run 'arcis scan --list' to see attack categories.")
        sys.exit(1)

    # Parse routes — default to scanning / if none provided. Track whether
    # routes were user-supplied vs the GET/POST `/` fallback so we can
    # print a tip later if the fallback proves useless (which it usually
    # does on real apps with auth-gated roots).
    routes_user_supplied = bool(args.routes)
    raw_routes = args.routes or ["POST:/"]
    routes: List[Tuple[str, str]] = []
    for r in raw_routes:
        if ":" in r and not r.startswith("http"):
            method, path = r.split(":", 1)
            routes.append((method.upper(), path))
        else:
            routes.append(("POST", r))

    fields = args.fields or DEFAULT_FIELDS
    categories = args.categories  # None = all

    show_progress = not args.quiet and sys.stderr.isatty()
    start = time.time()
    route_results: List[RouteResult] = []

    if not args.quiet:
        category_count = len(categories) if categories else len(ATTACK_CATEGORIES)
        sys.stderr.write(
            f"Scanning {args.url} — {len(routes)} route(s), {category_count} categories\n"
        )
        if not routes_user_supplied:
            sys.stderr.write(
                "\033[2m  Routes: auto-default (POST /). Pass --route POST:/api/login "
                "or similar to scan real endpoints.\033[0m\n"
            )
        sys.stderr.flush()

    for i, (method, path) in enumerate(routes, start=1):
        if show_progress:
            sys.stderr.write(
                f"\033[2m  [{i}/{len(routes)}] {method} {path} — probing...\033[0m\n"
            )
            sys.stderr.flush()
        rr = scan_route(args.url, method, path, fields, args.timeout, categories, thorough=args.thorough)
        route_results.append(rr)
        if show_progress:
            if not rr.reachable:
                sys.stderr.write(
                    f"\033[33m       skipped — {rr.error or 'unreachable'}\033[0m\n"
                )
            else:
                blocked = sum(1 for v in rr.vectors if v.blocked)
                total = len(rr.vectors)
                sys.stderr.write(
                    f"\033[2m       fired {total} payload(s) — "
                    f"{blocked} blocked, {total - blocked} got through\033[0m\n"
                )
            sys.stderr.flush()

    duration = time.time() - start
    print_report(args.url, route_results, duration, no_color=args.no_color)

    # Empty-run tip: when auto-discovery (no --route flags) yielded only
    # unreachable routes, the user thinks the scanner is broken. Print an
    # explicit tip so they know auto-discovery is weak by design and the
    # fix is one flag away. This was the #1 confusion in pilot wave 1
    # (Sujay's Burrow Express on :5001 — root 404'd, scan looked dead).
    no_routes_reachable = all(not rr.reachable for rr in route_results)
    if no_routes_reachable and not routes_user_supplied:
        bold = "" if args.no_color else "\033[1m"
        yellow = "" if args.no_color else "\033[33m"
        dim = "" if args.no_color else "\033[2m"
        reset = "" if args.no_color else "\033[0m"
        print()
        print(f"  {yellow}{bold}Tip{reset}{yellow}: nothing reachable at the default route.{reset}")
        print(f"  {dim}Auto-discovery only probes POST /. Most apps return 404 there.{reset}")
        print(f"  {dim}Pass real routes from your app:{reset}")
        print(f"    {bold}arcis scan {args.url} --route POST:/api/login --field email{reset}")
        print(f"    {bold}arcis scan {args.url} --route GET:/api/search --field q{reset}")
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
                "target": args.url,
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
