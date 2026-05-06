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
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from arcis.cli._console import (
    console,
    SEVERITY_STYLES,
    SEVERITY_GLYPH,
    live_status,
)


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

    # ── Phase B rules (v1.5.0 — 2026-05-05) ──────────────────────────────────
    # Rules added in cli-audit.md Phase B. Each pattern is tuned to be
    # high-confidence on the lines it matches: positive examples come
    # from real-world misuse, negative examples are listed in the
    # tests/cli/test_audit.py classes for each rule.

    Rule(
        id="HARDCODED-SECRET",
        severity="high",
        message="Hardcoded credential pattern detected — move secrets to environment variables, never commit to source",
        pattern=re.compile(
            r"""(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36,}|gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82}|sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,}|xox[bpoa]-[A-Za-z0-9\-]{10,}|-----BEGIN (?:RSA|EC|DSA|PGP|OPENSSH) PRIVATE KEY-----)"""
        ),
        languages=("python", "javascript", "typescript"),
    ),
    Rule(
        id="WEAK-CRYPTO",
        severity="high",
        message="MD5 or SHA-1 used for hashing — vulnerable to collisions; use SHA-256+ for passwords / signatures / integrity",
        pattern=re.compile(
            r"""(?:hashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|crypto\.createCipher\s*\(\s*['"](?:des|des-ede|rc4)['"])"""
        ),
        languages=("python", "javascript", "typescript"),
    ),
    Rule(
        id="WEAK-RANDOM-FOR-SECURITY",
        severity="high",
        message="Math.random() / random.random() assigned to a security-named variable — use crypto.randomBytes / secrets.token_hex for tokens, secrets, keys",
        pattern=re.compile(
            r"""\b\w*(?:csrf|token|secret|password|passwd|nonce|otp|salt|session|api_?key|access_?key|jwt)\w*\s*=\s*(?:Math\.random|random\.random|random\.randint|random\.choice|random\.sample|random\.uniform)\s*\(""",
            re.IGNORECASE,
        ),
        languages=("python", "javascript", "typescript"),
    ),
    Rule(
        id="INSECURE-REDIRECT",
        severity="medium",
        message="Redirect to user-controlled URL — validate against an allowed-host list (Arcis: validateUrl() / validate_redirect())",
        pattern=re.compile(
            r"""(?:\bres\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`\$\{|\$\{)|\bredirect\s*\(\s*(?:request\.(?:GET|POST|args|form|query)|req\.|params\.))"""
        ),
        languages=("python", "javascript", "typescript"),
    ),
    Rule(
        id="XML-EXTERNAL-ENTITY",
        severity="high",
        message="XML parser without secure config — disable external entities (lxml: resolve_entities=False, no_network=True; xml2js: secure mode)",
        pattern=re.compile(
            r"""(?:lxml\.etree\.parse\s*\(|xml\.dom\.minidom\.parse\s*\(|xml\.etree\.ElementTree\.parse\s*\(|new\s+(?:xml2js\.Parser|XMLParser|DOMParser)\s*\()"""
        ),
        languages=("python", "javascript", "typescript"),
    ),
    Rule(
        id="SECRET-IN-LOG",
        severity="high",
        message="Logging output references a credential-named variable — credentials in logs leak via aggregators / stdout / disk",
        pattern=re.compile(
            r"""(?:console\.(?:log|info|debug|warn|error)|logger?\.(?:log|info|debug|warn|error)|\bprint)\s*\([^)]*\b(?:password|passwd|secret|token|api_?key|access_?key|private_?key|auth_?token|client_?secret|bearer)\b""",
            re.IGNORECASE,
        ),
        languages=("python", "javascript", "typescript"),
    ),
    Rule(
        id="JWT-WEAK-SECRET",
        severity="high",
        message="jwt.sign() with a hardcoded or fallback string secret — load JWT secrets from a managed secret store; never bake them into source",
        pattern=re.compile(
            r"""\bjwt\.sign\s*\([^,)]+,\s*(?:["'][^"']*["']|[^,)]*\|\|\s*["'][^"']+["'])"""
        ),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="MASS-ASSIGNMENT",
        severity="medium",
        message="Bulk-assigning request body / params to a model — attacker can set fields like is_admin / role; whitelist allowed fields explicitly",
        pattern=re.compile(
            r"""(?:Object\.assign\s*\([^,)]+,\s*(?:req\.|request\.|params\.|query\.|body\.)|setattr\s*\([^,)]+,\s*\*\*\s*(?:request\.|req\.))"""
        ),
        languages=("javascript", "typescript", "python"),
    ),
    Rule(
        id="PATH-CONFUSION",
        severity="high",
        message="path.join() with user-controlled segment — attacker can break out with ../; use path.resolve() and assert the result is under the allowed base",
        pattern=re.compile(
            r"""(?:\bpath\.join\s*\([^,)]+,\s*(?:req\.|request\.|params\.|query\.|body\.)|\bos\.path\.join\s*\([^,)]+,\s*(?:request\.(?:GET|POST|args|form|query)|req\.|params\.))"""
        ),
        languages=("python", "javascript", "typescript"),
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
    """Render findings in a Problem / Fix / Code layout per finding,
    grouped by file with a path:line header that most editors and modern
    terminals (VS Code, iTerm2, Windows Terminal) treat as clickable.

    `no_color` is honored by routing through a fresh non-styled Console
    so callers passing --no-color get plain text without ANSI codes.
    """
    out = console if not no_color else _plain_console()

    if not findings:
        out.print()
        out.print("  [bold green]No issues found.[/]")
        out.print()
        return

    # Group findings by file so users see "this file has 3 issues" rather
    # than a flat alphabetical stream where the same file repeats.
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    out.print()
    for filepath, file_findings in by_file.items():
        try:
            rel = os.path.relpath(filepath)
        except ValueError:
            rel = filepath
        n = len(file_findings)
        plural = "s" if n != 1 else ""
        out.print(f"  [bold]{_md_safe(rel)}[/]  [dim]({n} issue{plural})[/]")
        out.print()

        for f in file_findings:
            sev = f.severity.lower()
            style = SEVERITY_STYLES.get(sev, "default")
            glyph = SEVERITY_GLYPH.get(sev, "-")
            sev_label = sev.upper().ljust(9)
            problem, fix = _split_message(f.message)

            location = f"{rel}:{f.line}"
            out.print(
                f"    [{style}]{glyph} {sev_label}[/][bold]{_md_safe(location)}[/]  [dim]{_md_safe(f.rule_id)}[/]"
            )
            out.print(f"      [dim]Problem [/] {_md_safe(problem)}")
            if fix:
                out.print(f"      [dim]Fix     [/] {_md_safe(fix)}")
            snippet = f.snippet.strip() if f.snippet else ""
            if snippet:
                out.print(f"      [dim]Code    [/] [dim]{_md_safe(snippet)}[/]")
            out.print()

    out.print(f"  [bold]{len(findings)} issue(s) found across {len(by_file)} file(s).[/]")
    out.print()


def _plain_console():
    """Console with all styling/markup disabled — for --no-color paths."""
    from rich.console import Console as _Console
    return _Console(no_color=True, markup=False, highlight=False)


def _md_safe(text: str) -> str:
    """Escape rich markup brackets in user-controlled text so a snippet
    containing literal '[' or ']' doesn't break formatting."""
    return text.replace("[", r"\[")


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
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit results as a single JSON document. Suppresses all human-readable output. Intended for CI.",
    )
    parser.add_argument(
        "--sarif",
        dest="sarif_output",
        action="store_true",
        help="Emit results as SARIF 2.1.0 for GitHub Code Scanning auto-upload.",
    )

    args = parser.parse_args()

    if args.json_output and args.sarif_output:
        print("arcis audit: --json and --sarif are mutually exclusive", file=sys.stderr)
        sys.exit(2)

    # Machine-readable modes imply --quiet so progress + headers don't
    # contaminate stdout. Stderr remains available for hard errors only.
    machine_mode = args.json_output or args.sarif_output
    if machine_mode:
        args.quiet = True
        args.no_color = True

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
        if machine_mode:
            # Emit a valid empty document so CI pipelines parsing the output
            # don't choke on a non-JSON error string. Exit 2 still signals
            # "nothing scanned" to the caller.
            target_abs = os.path.abspath(args.path)
            if args.json_output:
                print(render_json(
                    target=target_abs,
                    findings=[],
                    files_scanned=0,
                    languages={},
                    rules_applied=0,
                    sev_counts={},
                    duration_seconds=0.0,
                    severity_filter=args.severity,
                ))
            else:
                print(render_sarif(target=target_abs, findings=[]))
            sys.exit(2)
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

    # Build language breakdown up front — used by both the header and the
    # final summary. Computed once so the two views agree.
    by_lang: Dict[str, int] = {}
    for fp in files:
        lang = _detect_language(fp) or "unknown"
        by_lang[lang] = by_lang.get(lang, 0) + 1

    # Apply language filter to the rule count we report so the header is
    # honest: if the user passed --language python, we apply Python rules
    # only and that's the number we should print.
    applicable_rule_count = (
        len([r for r in RULES if args.language in r.languages])
        if args.language
        else len(RULES)
    )

    if not args.quiet:
        _print_audit_header(
            target=os.path.abspath(args.path),
            file_count=len(files),
            languages=by_lang,
            rule_count=applicable_rule_count,
            severity_filter=args.severity,
            no_color=args.no_color,
        )

    # Live progress: spinner + per-file status line pinned to stderr so
    # piping the result to a file gives clean findings without progress
    # noise. Auto-disables on non-TTY (CI logs stay clean).
    findings: List[Finding] = []
    use_live = not args.quiet and not args.no_color
    start = time.time()
    if use_live:
        with live_status(initial="Scanning...") as status:
            for i, filepath in enumerate(files, start=1):
                try:
                    rel = os.path.relpath(filepath)
                except ValueError:
                    rel = filepath
                status.update(
                    f"Auditing [dim cyan]{_md_safe(rel)}[/]  ({i}/{len(files)} files)"
                )
                findings.extend(scan_file(filepath))
    else:
        for filepath in files:
            findings.extend(scan_file(filepath))
    duration = time.time() - start

    if args.severity:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = order.get(args.severity.lower(), 3)
        findings = [f for f in findings if order.get(f.severity, 3) <= threshold]

    severity_key = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_key.get(f.severity, 9), f.file, f.line))

    # Per-severity summary counts — used by both the text summary and
    # the JSON/SARIF renderers below. Compute once.
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    if machine_mode:
        target_abs = os.path.abspath(args.path)
        if args.json_output:
            print(render_json(
                target=target_abs,
                findings=findings,
                files_scanned=len(files),
                languages=by_lang,
                rules_applied=applicable_rule_count,
                sev_counts=sev_counts,
                duration_seconds=duration,
                severity_filter=args.severity,
            ))
        else:
            print(render_sarif(target=target_abs, findings=findings))
        sys.exit(1 if findings else 0)

    _print_findings(findings, no_color=args.no_color)

    if not args.quiet:
        _print_audit_summary(
            files_scanned=len(files),
            languages=by_lang,
            rules=applicable_rule_count,
            sev_counts=sev_counts,
            findings=findings,
            duration_seconds=duration,
            severity_filter=args.severity,
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
    """Render the full rule list. What `arcis audit --list` shows."""
    out = console if not no_color else _plain_console()

    out.print()
    out.print(f"  [bold]arcis audit detection rules ({len(RULES)} total)[/]")
    out.print()

    by_lang: Dict[str, List[Rule]] = {}
    for rule in RULES:
        for lang in rule.languages:
            by_lang.setdefault(lang, []).append(rule)

    for lang in sorted(by_lang.keys()):
        rules = sorted(by_lang[lang], key=lambda r: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r.severity, 9), r.id))
        out.print(f"  [bold]{lang}[/] ({len(rules)} rules)")
        for r in rules:
            sev = r.severity.upper().ljust(8)
            style = SEVERITY_STYLES.get(r.severity, "default")
            out.print(
                f"    [{style}]{sev}[/] [bold]{r.id.ljust(18)}[/] {_md_safe(r.message)}"
            )
        out.print()


def _format_duration(seconds: float) -> str:
    """Render duration as 312ms / 1.4s / 2m 18s — matches what users
    expect from CLI timers. Sub-second runs read as ms; everything else
    in seconds with one decimal."""
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins}m {secs}s"


def render_json(
    *,
    target: str,
    findings: List[Finding],
    files_scanned: int,
    languages: Dict[str, int],
    rules_applied: int,
    sev_counts: Dict[str, int],
    duration_seconds: float,
    severity_filter: Optional[str] = None,
) -> str:
    """Render the audit result as a JSON document for CI consumption.

    Schema is intentionally flat and stable. Top-level fields:
      - tool, version, target, durationMs
      - summary: filesScanned, rulesApplied, byLanguage, bySeverity, totalFindings
      - findings[]: ruleId, severity, message, file, line, snippet
    """
    try:
        from arcis import __version__ as _v
    except Exception:
        _v = "unknown"

    doc = {
        "tool": "arcis-audit",
        "version": _v,
        "target": target,
        "durationMs": int(duration_seconds * 1000),
        "severityFilter": severity_filter,
        "summary": {
            "filesScanned": files_scanned,
            "rulesApplied": rules_applied,
            "byLanguage": languages,
            "bySeverity": sev_counts,
            "totalFindings": len(findings),
        },
        "findings": [
            {
                "ruleId": f.rule_id,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "snippet": f.snippet,
            }
            for f in findings
        ],
    }
    return json.dumps(doc, indent=2)


def render_sarif(
    *,
    target: str,
    findings: List[Finding],
) -> str:
    """Render the audit result as SARIF 2.1.0 for GitHub Code Scanning.

    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    Only the fields GitHub Code Scanning actually consumes are populated.
    """
    try:
        from arcis import __version__ as _v
    except Exception:
        _v = "unknown"

    # SARIF severity maps to "error" / "warning" / "note".
    sev_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    # Build the rules table from the rules referenced in findings — keeps
    # the SARIF doc minimal and avoids shipping rules unused by this run.
    rule_ids = []
    seen: Dict[str, bool] = {}
    rules_by_id: Dict[str, Rule] = {r.id: r for r in RULES}
    for f in findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = True
            rule_ids.append(f.rule_id)

    sarif_rules = []
    for rid in rule_ids:
        rule = rules_by_id.get(rid)
        msg = rule.message if rule else rid
        sarif_rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": msg.split(" — ")[0][:120]},
            "fullDescription": {"text": msg},
            "defaultConfiguration": {
                "level": sev_to_level.get(rule.severity if rule else "medium", "warning"),
            },
        })

    results = []
    for f in findings:
        # SARIF wants forward-slash relative URIs.
        try:
            rel = os.path.relpath(f.file).replace(os.sep, "/")
        except ValueError:
            rel = f.file.replace(os.sep, "/")
        results.append({
            "ruleId": f.rule_id,
            "level": sev_to_level.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {
                        "startLine": f.line,
                        "snippet": {"text": f.snippet} if f.snippet else None,
                    },
                },
            }],
        })

    # Strip None snippet entries — SARIF validators reject null fields.
    for r in results:
        region = r["locations"][0]["physicalLocation"]["region"]
        if region.get("snippet") is None:
            region.pop("snippet", None)

    doc = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "arcis-audit",
                    "version": _v,
                    "informationUri": "https://arcis.dev",
                    "rules": sarif_rules,
                },
            },
            "results": results,
            "originalUriBaseIds": {
                "TARGET": {"uri": target.replace(os.sep, "/").rstrip("/") + "/"},
            },
        }],
    }
    return json.dumps(doc, indent=2)


def _print_audit_header(
    *,
    target: str,
    file_count: int,
    languages: Dict[str, int],
    rule_count: int,
    severity_filter: Optional[str],
    no_color: bool = False,
) -> None:
    """Run header. Printed before scanning starts so users know exactly
    what's about to happen. Mirrors the SCA + scan headers for shape."""
    out = console if not no_color else _plain_console()
    line = "-" * 60

    breakdown = ", ".join(f"{n} {lang}" for lang, n in sorted(languages.items()))
    rule_langs = sorted(languages.keys())
    rule_lang_str = ", ".join(rule_langs) if rule_langs else "all"

    out.print()
    out.print("  [bold cyan]Arcis Audit[/]")
    out.print(f"  [dim]Target:[/]   {_md_safe(target)}")
    out.print(f"  [dim]Rules:[/]    {rule_count} ({rule_lang_str})")
    out.print(f"  [dim]Files:[/]    {file_count} scanned ({breakdown})")
    if severity_filter:
        out.print(f"  [dim]Filter:[/]   severity >= {severity_filter}")
    out.print(f"  [dim]{line}[/]")
    out.print()


def _print_audit_summary(
    *,
    files_scanned: int,
    languages: Dict[str, int],
    rules: int,
    sev_counts: Dict[str, int],
    findings: List[Finding],
    duration_seconds: float,
    severity_filter: Optional[str] = None,
    no_color: bool = False,
) -> None:
    out = console if not no_color else _plain_console()
    line = "-" * 60
    breakdown = ", ".join(f"{n} {lang}" for lang, n in sorted(languages.items()))
    total = sum(sev_counts.values())

    out.print(f"[dim]{line}[/]")
    out.print("  [bold]Summary[/]")
    out.print(f"    Files scanned   {files_scanned}  [{breakdown}]")
    out.print(f"    Rules applied   {rules}")
    if total == 0:
        if severity_filter:
            # Honest about the filter. User might think the repo is clean
            # when actually they've filtered out lower-severity findings.
            out.print(
                f"    Findings        [bold green]0 at severity >= {severity_filter}[/]"
            )
        else:
            out.print("    Findings        [bold green]0  clean[/]")
    else:
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            n = sev_counts.get(sev, 0)
            if n:
                parts.append(f"{n} {sev}")
        out.print(f"    Findings        [bold]{total}[/]  ({', '.join(parts)})")
    out.print(f"    Time            {_format_duration(duration_seconds)}")

    # Top offenders. Files with the most findings. Helps the user know
    # where to start fixing. Skipped when there are no findings (nothing
    # to rank) or when there's only one file with findings (trivial).
    if findings:
        by_file: Dict[str, int] = {}
        rule_in_file: Dict[str, str] = {}
        for f in findings:
            by_file[f.file] = by_file.get(f.file, 0) + 1
            rule_in_file.setdefault(f.file, f.rule_id)
        if len(by_file) > 1:
            out.print()
            out.print("  [bold]Top offenders[/]")
            top = sorted(by_file.items(), key=lambda kv: -kv[1])[:5]
            max_path_len = max(len(os.path.relpath(fp)) for fp, _ in top)
            for fp, n in top:
                rel = os.path.relpath(fp).ljust(min(max_path_len, 40))
                plural = "" if n == 1 else "s"
                out.print(
                    f"    {_md_safe(rel)}  [bold]{n}[/] finding{plural}  "
                    f"[dim]({rule_in_file[fp]})[/]"
                )

    # Next-step hints. Only when relevant. We don't repeat hints the user
    # already followed (e.g., don't say --severity high if they're already
    # filtering). Keeps the output honest, not spammy.
    if total > 0 and not severity_filter:
        critical_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
        if critical_high > 0 and critical_high < total:
            out.print()
            out.print(
                f"  [dim]Next:[/] [bold]arcis audit --severity high[/]  "
                f"[dim]to focus on {critical_high} high-impact[/]"
            )
            out.print(
                "        [bold]arcis audit --json[/]            "
                "[dim]for CI consumption[/]"
            )
    out.print(f"[dim]{line}[/]")
    out.print()
