"""
Terminal output formatting for arcis scan.
"""

from __future__ import annotations
import sys
from dataclasses import dataclass, field
from typing import List, Optional

# Use unicode box chars when the terminal supports it, ASCII otherwise
_SUPPORTS_UNICODE = bool(sys.stdout.encoding and sys.stdout.encoding.lower().startswith("utf"))
LINE_CHAR  = "─" if _SUPPORTS_UNICODE else "-"
TICK       = "✓" if _SUPPORTS_UNICODE else "[OK]"
CROSS      = "✗" if _SUPPORTS_UNICODE else "[!]"

# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


def _c(*codes: str, text: str, no_color: bool) -> str:
    if no_color:
        return text
    return "".join(codes) + text + RESET


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class VectorResult:
    category: str
    label: str
    payload: str
    status: int
    blocked: bool
    note: str = ""


@dataclass
class RouteResult:
    method: str
    path: str
    reachable: bool
    vectors: List[VectorResult] = field(default_factory=list)
    error: str = ""

    @property
    def protected_count(self) -> int:
        return sum(1 for v in self.vectors if v.blocked)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for v in self.vectors if not v.blocked)


# ── Printer ───────────────────────────────────────────────────────────────────

WIDTH = 56


def print_report(
    base_url: str,
    route_results: List[RouteResult],
    duration: float,
    no_color: bool = False,
) -> None:
    line = LINE_CHAR * WIDTH
    c = lambda text, *codes: _c(*codes, text=text, no_color=no_color)

    print()
    print(c("  Arcis Security Scan", BOLD, CYAN))
    print(c(f"  Target: {base_url}", DIM))
    print(c(line, DIM))

    total_vectors = 0
    total_blocked = 0
    total_vulnerable = 0

    for rr in route_results:
        print()
        route_label = f"  {rr.method}  {rr.path}"
        print(c(route_label, BOLD, WHITE))

        if not rr.reachable:
            print(c(f"    {CROSS}  {rr.error}", RED))
            continue

        # Group by category for clean output
        current_category = None
        for v in rr.vectors:
            total_vectors += 1

            if v.category != current_category:
                current_category = v.category
                print(c(f"\n    {v.category}", DIM))

            if v.blocked:
                total_blocked += 1
                status_str = c(f"{TICK}  PROTECTED", GREEN, BOLD)
            else:
                total_vulnerable += 1
                status_str = c(f"{CROSS}  VULNERABLE", RED, BOLD)

            label = v.label.ljust(24)
            note  = c(f"  {v.note}", DIM)
            print(f"      {label} {status_str}{note}")

            # On vulnerable rows, show the payload that got through so the
            # user can reproduce + test their fix without hunting elsewhere.
            if not v.blocked:
                payload_preview = v.payload if len(v.payload) <= 70 else v.payload[:67] + "..."
                print(c(f"        Payload  {payload_preview}", DIM))

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(c(line, DIM))
    print()

    routes_scanned = sum(1 for r in route_results if r.reachable)
    print(f"  Routes scanned    {routes_scanned}")
    print(f"  Attack vectors    {total_vectors}")

    if total_vectors == 0:
        print(c("  No routes were reachable. Is the server running?", YELLOW))
    elif total_vulnerable == 0:
        protected_str = c(f"{total_blocked}  {TICK}  All vectors protected", GREEN, BOLD)
        print(f"  Protected         {protected_str}")
        print(f"  Vulnerable        0")
    else:
        print(f"  Protected         {total_blocked}")
        vuln_str = c(f"{total_vulnerable}  {CROSS}  needs middleware", RED, BOLD)
        print(f"  Vulnerable        {vuln_str}")

    print(f"  Duration          {duration:.1f}s")
    print()
    print(c(line, DIM))

    # Mirror audit's Problem / Fix layout when there's something to fix.
    if total_vulnerable > 0:
        print()
        print(c("  Problem", BOLD, RED))
        print(f"    {total_vulnerable} attack payload(s) reached your app and weren't blocked.")
        print()
        print(c("  Fix", BOLD, GREEN))
        print("    Install Arcis middleware with detect-and-block enabled:")
        print(c("      Node    app.use(arcis({ block: true }))", DIM))
        print(c("      Python  app.add_middleware(ArcisMiddleware, block=True)", DIM))
        print(c("      Go      r.Use(arcisgin.MiddlewareWithConfig(arcisgin.Config{Block: true, ...}))", DIM))
        print()
        print(c("    Then re-run this scan -- every payload should come back PROTECTED.", DIM))
        print()
        print(c(line, DIM))
        print()
    else:
        print()
