"""
arcis audit — static analysis security scanner for source code.

Scans Python and JavaScript/TypeScript files for dangerous patterns:
- Unsafe YAML loading
- subprocess with shell=True
- innerHTML / document.write sinks
- JSONP callback endpoints
- Angular security trust bypass
- Pickle / marshal / shelve deserialization on user input
- JWT without algorithm enforcement
- eval() / exec() on request data
- SQL query string concatenation
- ORM raw queries (Prisma $queryRaw, Sequelize, knex.raw)
- File system operations with user-controlled paths
- HTTP requests (fetch, axios, requests) with user-controlled URLs

Usage:
    arcis audit .
    arcis audit src/ --language python
    arcis audit app/ --severity high
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Finding:
    """A single static analysis finding."""
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    snippet: str


# ── Rules ────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    """A static analysis detection rule."""
    id: str
    severity: str
    message: str
    pattern: re.Pattern
    languages: Tuple[str, ...]
    # Some rules need a negative lookahead (e.g., yaml.load WITH SafeLoader is ok)
    safe_pattern: Optional[re.Pattern] = None


RULES: List[Rule] = [
    # ── Python rules ──
    Rule(
        id="YAML-UNSAFE",
        severity="high",
        message="yaml.load() without SafeLoader — use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)",
        pattern=re.compile(r"\byaml\.load\s*\("),
        languages=("python",),
        safe_pattern=re.compile(r"yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader"),
    ),
    Rule(
        id="SHELL-TRUE",
        severity="high",
        message="subprocess call with shell=True — use shell=False with a list of arguments",
        pattern=re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
        languages=("python",),
    ),
    Rule(
        id="PICKLE-LOAD",
        severity="critical",
        message="pickle.loads() / pickle.load() on potentially untrusted data — use JSON or a safe serialization format",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        languages=("python",),
    ),
    Rule(
        id="EVAL-EXEC",
        severity="critical",
        message="eval() or exec() detected — avoid dynamic code execution on user input",
        pattern=re.compile(r"\b(?:eval|exec)\s*\("),
        languages=("python", "javascript", "typescript"),
    ),

    # ── JavaScript/TypeScript rules ──
    Rule(
        id="INNERHTML",
        severity="high",
        message=".innerHTML assignment — use textContent or a sanitization library",
        pattern=re.compile(r"\.innerHTML\s*="),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="DOCUMENT-WRITE",
        severity="high",
        message="document.write() detected — use DOM manipulation instead",
        pattern=re.compile(r"\bdocument\.write(?:ln)?\s*\("),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="ANGULAR-TRUST",
        severity="high",
        message="bypassSecurityTrust*() — verify the input is truly trusted before bypassing Angular sanitization",
        pattern=re.compile(r"\bbypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl)\s*\("),
        languages=("typescript",),
    ),
    Rule(
        id="JWT-NO-ALG",
        severity="high",
        message="jwt.verify() / jwt.decode() without explicit algorithms — always specify algorithms to prevent alg:none attacks",
        pattern=re.compile(r"\bjwt\.(?:verify|decode)\s*\("),
        languages=("javascript", "typescript"),
        safe_pattern=re.compile(r"jwt\.(?:verify|decode)\s*\([^)]*algorithms"),
    ),

    # ── Cross-language rules ──
    Rule(
        id="JSONP-CALLBACK",
        severity="medium",
        message="JSONP callback parameter detected — validate callback names with sanitizeJsonpCallback()",
        pattern=re.compile(r"""(?:request\.(?:args|query|GET)\.get\s*\(\s*["']callback["']|req\.query\.callback|params\[["']callback["']\])"""),
        languages=("python", "javascript", "typescript"),
    ),

    # ── New rules (v1.4.0) ──

    Rule(
        id="SQL-CONCAT",
        severity="critical",
        message="SQL query built with string concatenation — use parameterized queries to prevent SQL injection",
        pattern=re.compile(
            r"""(?:cursor\.execute|db\.execute|connection\.execute|conn\.execute|query\.execute)\s*\(\s*(?:f["']|["'][^"']*["']\s*\+|["'][^"']*\+|["'][^"']*%\s*(?:request|req|params|data|input|user))"""
        ),
        languages=("python",),
    ),
    Rule(
        id="ORM-RAW",
        severity="high",
        message="Raw ORM query detected — verify no user input is interpolated into this query",
        pattern=re.compile(
            r"""(?:\$queryRaw|\.query\s*\(\s*["'`]|\bsequelize\.query\s*\(|typeorm.*\.query\s*\(|knex\.raw\s*\()"""
        ),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="FS-USER-PATH",
        severity="high",
        message="File system operation with potentially user-controlled path — use path.resolve() and validate against allowed directories",
        pattern=re.compile(
            r"""(?:fs\.(?:readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|unlinkSync|stat|statSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)|open\s*\(\s*(?:request\.|req\.|f["'].*\+))"""
        ),
        languages=("javascript", "typescript", "python"),
    ),
    Rule(
        id="FETCH-USER-URL",
        severity="high",
        message="HTTP request with potentially user-controlled URL — validate with validateUrl() to prevent SSRF",
        pattern=re.compile(
            r"""(?:fetch\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`[^`]*\$\{)|(?:http|https|axios|got|superagent)\.(?:get|post|request)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)|requests\.(?:get|post|request)\s*\(\s*(?:request\.|req\.))"""
        ),
        languages=("javascript", "typescript", "python"),
    ),
    Rule(
        id="UNSAFE-DESERIALIZE",
        severity="critical",
        message="Unsafe deserialization detected — never deserialize untrusted data with marshal, shelve, or jsonpickle",
        pattern=re.compile(
            r"""\b(?:marshal\.loads?\s*\(|shelve\.open\s*\(|jsonpickle\.decode\s*\()"""
        ),
        languages=("python",),
    ),
]


# ── File scanning ────────────────────────────────────────────────────────────

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "env", ".env", "site-packages",
}


def _detect_language(filepath: str) -> Optional[str]:
    """Detect language from file extension."""
    _, ext = os.path.splitext(filepath)
    return LANGUAGE_MAP.get(ext.lower())


def _collect_files(path: str, language: Optional[str] = None) -> List[str]:
    """Collect scannable files under path."""
    files = []

    if os.path.isfile(path):
        lang = _detect_language(path)
        if lang and (language is None or lang == language):
            files.append(path)
        return files

    for root, dirs, filenames in os.walk(path):
        # Prune skipped directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in filenames:
            filepath = os.path.join(root, fname)
            lang = _detect_language(filepath)
            if lang and (language is None or lang == language):
                files.append(filepath)

    return files


def scan_file(filepath: str, rules: Optional[List[Rule]] = None) -> List[Finding]:
    """Scan a single file for security issues."""
    lang = _detect_language(filepath)
    if not lang:
        return []

    applicable_rules = rules or RULES
    applicable_rules = [r for r in applicable_rules if lang in r.languages]
    if not applicable_rules:
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return []

    findings: List[Finding] = []

    for line_num, line in enumerate(lines, start=1):
        # Skip comment-only lines
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for rule in applicable_rules:
            if rule.pattern.search(line):
                # Check safe pattern — if the line also matches safe, skip
                if rule.safe_pattern and rule.safe_pattern.search(line):
                    continue

                findings.append(Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    file=filepath,
                    line=line_num,
                    snippet=stripped[:120],
                ))

    return findings


def scan_directory(
    path: str,
    language: Optional[str] = None,
    severity: Optional[str] = None,
    rules: Optional[List[Rule]] = None,
) -> List[Finding]:
    """Scan a directory tree for security issues."""
    files = _collect_files(path, language)
    all_findings: List[Finding] = []

    for filepath in files:
        all_findings.extend(scan_file(filepath, rules))

    if severity:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_order.get(severity.lower(), 3)
        all_findings = [f for f in all_findings if severity_order.get(f.severity, 3) <= threshold]

    # Sort by severity (critical first), then file, then line
    severity_key = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: (severity_key.get(f.severity, 9), f.file, f.line))

    return all_findings


# ── Output ───────────────────────────────────────────────────────────────────

def _split_message(msg: str) -> Tuple[str, str]:
    """Split a rule message into (problem, fix) using the em-dash or
    " - " separator we use consistently across rules. If neither delimiter
    is present, the whole message is the problem and fix is empty."""
    for sep in (" — ", " -- ", " - "):
        if sep in msg:
            problem, _, fix = msg.partition(sep)
            return problem.strip(), fix.strip()
    return msg.strip(), ""


def _print_findings(findings: List[Finding], no_color: bool = False) -> None:
    """Render findings in a "Problem / Fix / Code" layout per finding,
    grouped by file with a path:line header that most editors and modern
    terminals (VS Code, iTerm2, Windows Terminal) treat as clickable."""
    if not findings:
        label = "No issues found." if no_color else "\033[32m[OK] No issues found.\033[0m"
        print()
        print(f"  {label}")
        print()
        return

    # Severity colors + 1-char glyph (ASCII, safe on Windows cp1252)
    sev_color = {
        "critical": "\033[91m",
        "high":     "\033[31m",
        "medium":   "\033[33m",
        "low":      "\033[36m",
    }
    sev_glyph = {"critical": "!!", "high": "!", "medium": "*", "low": "."}
    bold = "" if no_color else "\033[1m"
    dim = "" if no_color else "\033[2m"
    reset = "" if no_color else "\033[0m"

    def c(text: str, color: str) -> str:
        return text if no_color else f"{color}{text}{reset}"

    # Group findings by file so users see "this file has 3 issues" rather
    # than a flat alphabetical stream where the same file repeats.
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    print()
    for filepath, file_findings in by_file.items():
        # Show a relative path when possible — easier to read, and
        # editors still resolve it from CWD.
        try:
            rel = os.path.relpath(filepath)
        except ValueError:
            rel = filepath
        n = len(file_findings)
        plural = "s" if n != 1 else ""
        print(f"  {c(rel, bold)}  {c('(' + str(n) + ' issue' + plural + ')', dim)}")
        print()

        for f in file_findings:
            sev = f.severity.lower()
            color = sev_color.get(sev, "")
            glyph = sev_glyph.get(sev, "-")
            # ljust to 9 so CRITICAL (8 chars) still gets a trailing space
            # before the clickable location.
            sev_label = sev.upper().ljust(9)
            problem, fix = _split_message(f.message)

            # path:line format — most terminals make this clickable.
            location = f"{rel}:{f.line}"
            print(f"    {c(glyph + ' ' + sev_label, color)}{c(location, bold)}  {c(f.rule_id, dim)}")
            print(f"      {c('Problem ', dim)} {problem}")
            if fix:
                print(f"      {c('Fix     ', dim)} {fix}")
            # Render the offending code line indented like a code block.
            snippet = f.snippet.strip() if f.snippet else ""
            if snippet:
                print(f"      {c('Code    ', dim)} {c(snippet, dim)}")
            print()

    print(f"  {bold}{len(findings)} issue(s) found across {len(by_file)} file(s).{reset}")
    print()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis audit",
        description="Static analysis security scanner for Python and JavaScript/TypeScript source code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  arcis audit .
  arcis audit src/ --language python
  arcis audit app/ --severity high
  arcis audit . --no-color
        """,
    )

    parser.add_argument(
        "path",
        nargs="?",
        help="File or directory to scan",
    )
    parser.add_argument(
        "--language", "-l",
        choices=["python", "javascript", "typescript"],
        help="Only scan files of this language",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to report (default: all)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured terminal output",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all detection rules (id, severity, languages, message) and exit.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output (still prints findings + summary).",
    )

    args = parser.parse_args()

    if args.list:
        _print_rule_catalog(no_color=args.no_color)
        sys.exit(0)

    if not hasattr(args, "path") or args.path is None:
        parser.print_usage()
        sys.exit(1)

    if not os.path.exists(args.path):
        print(f"arcis audit: path not found: {args.path}")
        sys.exit(1)

    files = _collect_files(args.path, language=args.language)
    if not files:
        msg = (
            f"arcis audit: no scannable files found in {args.path}"
            + (f" (language={args.language})" if args.language else "")
            + "\n  Supported: .py .js .ts .jsx .tsx — pass a path that contains source files."
        )
        if args.no_color:
            print(msg)
        else:
            print(f"\033[33m{msg}\033[0m")
        sys.exit(2)

    # Live progress: print "Scanning N file(s)..." then a progress bar that
    # rewrites itself in place. Goes to stderr so piping output to a file
    # gives clean findings without progress noise.
    findings: List[Finding] = []
    show_progress = not args.quiet and sys.stderr.isatty() and not args.no_color
    if not args.quiet:
        sys.stderr.write(f"Scanning {len(files)} file(s)...\n")
        sys.stderr.flush()
    for i, filepath in enumerate(files, start=1):
        findings.extend(scan_file(filepath))
        if show_progress and (i % 10 == 0 or i == len(files)):
            pct = int(i * 100 / max(1, len(files)))
            bar_w = 24
            fill = int(bar_w * i / max(1, len(files)))
            bar = "#" * fill + "-" * (bar_w - fill)
            sys.stderr.write(
                f"\r\033[2m  [{bar}] {pct:3d}%  {i}/{len(files)}\033[0m"
            )
            sys.stderr.flush()
    if show_progress:
        sys.stderr.write("\r\033[2K")  # clear progress line
        sys.stderr.flush()

    if args.severity:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = order.get(args.severity.lower(), 3)
        findings = [f for f in findings if order.get(f.severity, 3) <= threshold]

    severity_key = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_key.get(f.severity, 9), f.file, f.line))

    # Show scan summary so green output is unambiguous: user can tell that
    # files were actually inspected, not silently skipped.
    by_lang: Dict[str, int] = {}
    for fp in files:
        lang = _detect_language(fp) or "unknown"
        by_lang[lang] = by_lang.get(lang, 0) + 1
    breakdown = ", ".join(f"{n} {lang}" for lang, n in sorted(by_lang.items()))
    summary = f"Scanned {len(files)} file(s) [{breakdown}] against {len(RULES)} rule(s)."
    if args.no_color:
        print(summary)
    else:
        print(f"\033[2m{summary}\033[0m")

    _print_findings(findings, no_color=args.no_color)

    # Final per-severity summary block — same shape across audit/scan/sca.
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    if not args.quiet:
        _print_audit_summary(
            files_scanned=len(files),
            languages=by_lang,
            rules=len(RULES),
            sev_counts=sev_counts,
            no_color=args.no_color,
        )

    # Upload to dashboard if ARCIS_ENDPOINT is set. Sends the per-severity
    # counts plus the first 200 findings (drill-down view in the UI).
    # Cap protects the server's 256 KB summary blob limit on large repos.
    try:
        from .dashboard import upload as dashboard_upload
        dashboard_findings = [
            {
                "ruleId": f.rule_id,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "snippet": (f.snippet or "")[:200],
            }
            for f in findings[:200]
        ]
        dashboard_upload(
            kind="audits",
            body={
                "language": args.language or "mixed",
                "target": os.path.abspath(args.path),
                "summary": {
                    "filesScanned": len(files),
                    "rulesApplied": len(RULES),
                    "byLanguage": by_lang,
                    "bySeverity": sev_counts,
                    "findings": dashboard_findings,
                    "truncated": len(findings) > len(dashboard_findings),
                },
                "findingsCount": len(findings),
            },
            quiet=args.quiet,
        )
    except Exception:
        # Never let upload bugs change the audit's exit code.
        pass

    sys.exit(1 if findings else 0)


# ── Discovery + summary helpers ──────────────────────────────────────────────


def _print_rule_catalog(no_color: bool = False) -> None:
    """Render the full rule list — what `arcis audit --list` shows."""
    sev_color = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
    bold = "" if no_color else "\033[1m"
    dim = "" if no_color else "\033[2m"
    reset = "" if no_color else "\033[0m"

    print()
    print(f"  {bold}arcis audit — detection rules ({len(RULES)} total){reset}")
    print()

    by_lang: Dict[str, List[Rule]] = {}
    for rule in RULES:
        for lang in rule.languages:
            by_lang.setdefault(lang, []).append(rule)

    for lang in sorted(by_lang.keys()):
        rules = sorted(by_lang[lang], key=lambda r: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r.severity, 9), r.id))
        print(f"  {bold}{lang}{reset} ({len(rules)} rules)")
        for r in rules:
            sev = r.severity.upper().ljust(8)
            sev_col = "" if no_color else sev_color.get(r.severity, "")
            print(f"    {sev_col}{sev}{reset} {bold}{r.id.ljust(18)}{reset} {r.message}")
        print()


def _print_audit_summary(
    *,
    files_scanned: int,
    languages: Dict[str, int],
    rules: int,
    sev_counts: Dict[str, int],
    no_color: bool = False,
) -> None:
    bold = "" if no_color else "\033[1m"
    dim = "" if no_color else "\033[2m"
    green = "" if no_color else "\033[32m"
    reset = "" if no_color else "\033[0m"
    line = "-" * 60
    breakdown = ", ".join(f"{n} {lang}" for lang, n in sorted(languages.items()))
    total = sum(sev_counts.values())

    print()
    print(f"{dim}{line}{reset}")
    print(f"  {bold}Audit summary{reset}")
    print(f"    Files scanned   {files_scanned}  [{breakdown}]")
    print(f"    Rules applied   {rules}")
    if total == 0:
        print(f"    Findings        {green}0  [OK] clean{reset}")
    else:
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            n = sev_counts.get(sev, 0)
            if n:
                parts.append(f"{n} {sev}")
        print(f"    Findings        {bold}{total}{reset}  ({', '.join(parts)})")
    print(f"{dim}{line}{reset}")
    print()
