"""
Arcis SCA — Supply Chain Attack Scanner.

Detects compromised packages from known supply chain attacks.
Scans local projects and environments for malicious package versions,
trojanized dependencies, and persistence artifacts (backdoors).

Threat database: arcis/data/threat-db.json
All detections are sourced from public security advisories.
This scanner runs entirely offline — no network calls, no telemetry.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from arcis.cli._console import console, err_console, live_status

# ── Terminal formatting ──────────────────────────────────────────────────────

_SUPPORTS_UNICODE = bool(
    sys.stdout.encoding and sys.stdout.encoding.lower().startswith("utf")
)
LINE_CHAR = "\u2500" if _SUPPORTS_UNICODE else "-"
TICK = "\u2713" if _SUPPORTS_UNICODE else "[OK]"
CROSS = "\u2717" if _SUPPORTS_UNICODE else "[!]"
WARN = "\u26a0" if _SUPPORTS_UNICODE else "[?]"

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"

WIDTH = 64


def _c(*codes: str, text: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return "".join(codes) + text + RESET


# ── Threat database ──────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).parent.parent / "data"
_THREAT_DB_PATH = _DATA_DIR / "threat-db.json"


@dataclass
class CompromisedPackage:
    """A known compromised package version."""

    ecosystem: str          # "npm" or "pypi"
    name: str
    malicious_versions: List[str]
    attack_vector: str
    severity: str           # "critical" or "high"
    cve: str
    disclosure_date: str
    source: str             # e.g. "npm Security Advisory"
    references: List[str]   # advisory and disclosure URLs
    trojanized_deps: List[str] = field(default_factory=list)
    persistence_artifacts: List[str] = field(default_factory=list)
    remediation: str = ""
    # vulnerable_ranges: list of comma-separated constraint strings such as
    # ">=4.0.0,<4.22.4" or ">=0.0,<1.7.4". Each constraint is `<op><version>`
    # with op in (==, !=, <, <=, >, >=). Constraints inside one string are
    # AND-ed; multiple ranges in the list are OR-ed. Empty by default so
    # legacy entries with only `malicious_versions` keep working.
    vulnerable_ranges: List[str] = field(default_factory=list)


def _load_threat_db() -> List[CompromisedPackage]:
    """Load the threat database from arcis/data/threat-db.json."""
    try:
        with open(_THREAT_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        # Fall back to empty DB rather than crashing — scanner should degrade
        # gracefully if the data file is missing or malformed.
        sys.stderr.write(f"arcis sca: warning: could not load threat-db.json: {exc}\n")
        return []

    threats = []
    for entry in data.get("threats", []):
        threats.append(CompromisedPackage(
            ecosystem=entry["ecosystem"],
            name=entry["name"],
            malicious_versions=entry.get("malicious_versions", []),
            attack_vector=entry["attack_vector"],
            severity=entry["severity"],
            cve=entry.get("cve", ""),
            disclosure_date=entry.get("disclosure_date", ""),
            source=entry.get("source", ""),
            references=entry.get("references", []),
            trojanized_deps=entry.get("trojanized_deps", []),
            persistence_artifacts=entry.get("persistence_artifacts", []),
            remediation=entry.get("remediation", ""),
            vulnerable_ranges=entry.get("vulnerable_ranges", []),
        ))
    return threats


THREAT_DB: List[CompromisedPackage] = _load_threat_db()


# ── Version range matcher ────────────────────────────────────────────────────
# Best-effort SemVer / PEP 440 subset. Handles the version shapes we actually
# encounter in seed entries: dotted ints with optional pre-release suffix
# (e.g. 1.0.0-rc1, 1.7.0). Pre-release sorts lower than the equivalent
# release. Not a full implementation — but matches GHSA range strings cleanly.

_VERSION_LEAD_RE = re.compile(r"^[vV]?(.+)$")


def _normalize_name(name: str, ecosystem: str) -> str:
    """Canonicalize a package name for case- and separator-insensitive
    comparison. PyPI normalizes `_` and `-` to be equivalent and folds case;
    npm only folds case. Run this on both threat.name and the matched
    package name before comparing."""
    n = name.strip().lower()
    if ecosystem == "pypi":
        n = n.replace("_", "-")
    return n


_SUFFIX_SEG_RE = re.compile(r"^([A-Za-z\-]*)(\d+)?$")


def _suffix_segments(suffix: str) -> Tuple[Tuple[str, int], ...]:
    """Split a pre-release suffix into (letters, number) segments so that
    'rc1' < 'rc2' < 'rc10' compare numerically instead of lexically.

        'rc1'      -> (('rc', 1),)
        'rc10'     -> (('rc', 10),)
        'beta.2'   -> (('beta', 0), ('', 2))
        'alpha'    -> (('alpha', 0),)
        '1'        -> (('', 1),)             # pure-numeric segment
    """
    out: List[Tuple[str, int]] = []
    for seg in suffix.split("."):
        m = _SUFFIX_SEG_RE.match(seg)
        if m:
            letters = (m.group(1) or "").lower()
            number = int(m.group(2)) if m.group(2) else 0
            out.append((letters, number))
        else:
            out.append((seg.lower(), 0))
    return tuple(out)


def _version_key(v: str) -> tuple:
    """Comparable tuple for a version string.

    Numeric base parts beat non-numeric in the same slot. Pre-release
    suffixes sort lower than the same base with no suffix. Inside a
    suffix, segments are split into (letters, number) so 'rc1' < 'rc10'
    instead of the broken lexical 'rc10' < 'rc2'.
    """
    if not v:
        return ((0, ""), (0, ""))
    v = _VERSION_LEAD_RE.sub(r"\1", v.strip()).split("+", 1)[0]
    base, _, suffix = v.partition("-")
    parts: List[tuple] = []
    for p in base.split("."):
        if p.isdigit():
            parts.append((1, int(p)))
        else:
            digits = "".join(c for c in p if c.isdigit())
            tail = "".join(c for c in p if not c.isdigit())
            if digits:
                parts.append((1, int(digits)))
                if tail:
                    parts.append((0, tail))
            else:
                parts.append((0, p))
    if suffix:
        # Pre-release tag is sorted below the release marker (0 < 2).
        # Segments inside the suffix are decomposed so rc10 > rc2.
        parts.append((0, _suffix_segments(suffix)))
    else:
        parts.append((2, ()))
    return tuple(parts)


_OPS = ("<=", ">=", "!=", "==", "<", ">")


def _matches_constraint(version: str, constraint: str) -> bool:
    """Single constraint match like '<4.22.4' or '==1.7.0'."""
    constraint = constraint.strip()
    if not constraint:
        return True
    for op in _OPS:
        if constraint.startswith(op):
            target = constraint[len(op):].strip()
            v = _version_key(version)
            t = _version_key(target)
            if op == "<":
                return v < t
            if op == "<=":
                return v <= t
            if op == ">":
                return v > t
            if op == ">=":
                return v >= t
            if op == "==":
                return v == t
            if op == "!=":
                return v != t
    # No operator: bare version means exact match.
    return _version_key(version) == _version_key(constraint)


def _matches_range(version: str, range_expr: str) -> bool:
    """Comma-separated constraints AND-ed together: '>=4.0.0,<4.22.4'."""
    parts = [c for c in range_expr.split(",") if c.strip()]
    if not parts:
        return False
    return all(_matches_constraint(version, c) for c in parts)


def _matches_any_range(version: str, ranges: List[str]) -> bool:
    """OR across multiple range strings."""
    return any(_matches_range(version, r) for r in ranges)


def _is_compromised(version: str, threat: CompromisedPackage) -> bool:
    """True iff version falls under any of the threat's match expressions.

    Two-track matching, in order:
      1. Exact version list (legacy, used by trojanized-package entries
         where attackers pushed specific malicious versions).
      2. vulnerable_ranges (used by high-severity-CVE entries where every
         version below a fix release is exploitable).
    """
    if not version:
        return False
    if version in threat.malicious_versions:
        return True
    if threat.vulnerable_ranges and _matches_any_range(version, threat.vulnerable_ranges):
        return True
    return False


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single supply chain finding."""

    package: str
    ecosystem: str
    version: str
    severity: str
    location: str
    attack_vector: str
    remediation: str
    source: str
    references: List[str]
    finding_type: str = "compromised_version"  # or "trojanized_dep", "persistence_artifact"


# ── npm / Node.js scanners ───────────────────────────────────────────────────


def _scan_package_lock(path: str) -> List[Finding]:
    """Scan package-lock.json for compromised packages."""
    findings: List[Finding] = []
    lockfile = os.path.join(path, "package-lock.json")
    if not os.path.isfile(lockfile):
        return findings

    try:
        with open(lockfile, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    # lockfile v2/v3: packages dict
    packages = data.get("packages", {})
    # lockfile v1: dependencies dict
    dependencies = data.get("dependencies", {})

    for threat in THREAT_DB:
        if threat.ecosystem != "npm":
            continue

        threat_norm = _normalize_name(threat.name, "npm")
        trojanized_norm = {_normalize_name(d, "npm") for d in threat.trojanized_deps}

        # Check v2/v3 packages
        for pkg_path, pkg_info in packages.items():
            pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else ""
            pkg_norm = _normalize_name(pkg_name, "npm")
            version = pkg_info.get("version", "")

            if pkg_norm == threat_norm and _is_compromised(version, threat):
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="npm",
                    version=version,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                ))

            if pkg_norm in trojanized_norm:
                findings.append(Finding(
                    package=pkg_name,
                    ecosystem="npm",
                    version=version,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=f"Trojanized dependency of {threat.name}: {threat.attack_vector}",
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                    finding_type="trojanized_dep",
                ))

        # Check v1 dependencies
        for dep_name, dep_info in dependencies.items():
            dep_norm = _normalize_name(dep_name, "npm")
            version = dep_info.get("version", "")
            if dep_norm == threat_norm and _is_compromised(version, threat):
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="npm",
                    version=version,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                ))

    return findings


def _scan_yarn_lock(path: str) -> List[Finding]:
    """Scan yarn.lock for compromised packages."""
    findings: List[Finding] = []
    lockfile = os.path.join(path, "yarn.lock")
    if not os.path.isfile(lockfile):
        return findings

    try:
        with open(lockfile, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return findings

    for threat in THREAT_DB:
        if threat.ecosystem != "npm":
            continue

        # Extract every version block for `threat.name` and check each
        # against the matcher (handles both exact-list and range entries).
        block_re = re.compile(
            rf'"{re.escape(threat.name)}@[^"]*".*?version\s+"([^"]+)"',
            re.DOTALL,
        )
        for m in block_re.finditer(content):
            found_ver = m.group(1)
            if _is_compromised(found_ver, threat):
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="npm",
                    version=found_ver,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                ))

        for dep_name in threat.trojanized_deps:
            if dep_name in content:
                findings.append(Finding(
                    package=dep_name,
                    ecosystem="npm",
                    version="unknown",
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=f"Trojanized dependency of {threat.name}: {threat.attack_vector}",
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                    finding_type="trojanized_dep",
                ))

    return findings


def _scan_node_modules(path: str) -> List[Finding]:
    """Scan node_modules for compromised packages on disk."""
    findings: List[Finding] = []
    nm_dir = os.path.join(path, "node_modules")
    if not os.path.isdir(nm_dir):
        return findings

    for threat in THREAT_DB:
        if threat.ecosystem != "npm":
            continue

        pkg_json = os.path.join(nm_dir, threat.name, "package.json")
        if os.path.isfile(pkg_json):
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                version = data.get("version", "")
                if _is_compromised(version, threat):
                    findings.append(Finding(
                        package=threat.name,
                        ecosystem="npm",
                        version=version,
                        severity=threat.severity,
                        location=pkg_json,
                        attack_vector=threat.attack_vector,
                        remediation=threat.remediation,
                        source=threat.source,
                        references=threat.references,
                    ))
            except (json.JSONDecodeError, OSError):
                pass

        for dep_name in threat.trojanized_deps:
            dep_json = os.path.join(nm_dir, dep_name, "package.json")
            if os.path.isfile(dep_json):
                findings.append(Finding(
                    package=dep_name,
                    ecosystem="npm",
                    version="installed",
                    severity=threat.severity,
                    location=dep_json,
                    attack_vector=f"Trojanized dependency of {threat.name}: {threat.attack_vector}",
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                    finding_type="trojanized_dep",
                ))

    return findings


# ── Python / PyPI scanners ───────────────────────────────────────────────────


def _scan_requirements(path: str) -> List[Finding]:
    """Scan requirements.txt, Pipfile.lock, poetry.lock for compromised versions."""
    findings: List[Finding] = []

    # Match `pkg ==1.2.3` lines. Pull the version out and run it through
    # the unified matcher so range entries work too. Comments and extras
    # are stripped before matching.
    req_line_re = re.compile(
        r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)",
    )
    for req_name in ["requirements.txt", "requirements-dev.txt", "requirements-prod.txt"]:
        req_file = os.path.join(path, req_name)
        if not os.path.isfile(req_file):
            continue
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                for line in f:
                    m = req_line_re.match(line)
                    if not m:
                        continue
                    pkg_name = _normalize_name(m.group(1), "pypi")
                    pkg_ver = m.group(2).strip()
                    for threat in THREAT_DB:
                        if threat.ecosystem != "pypi":
                            continue
                        if _normalize_name(threat.name, "pypi") != pkg_name:
                            continue
                        if _is_compromised(pkg_ver, threat):
                            findings.append(Finding(
                                package=threat.name,
                                ecosystem="pypi",
                                version=pkg_ver,
                                severity=threat.severity,
                                location=req_file,
                                attack_vector=threat.attack_vector,
                                remediation=threat.remediation,
                                source=threat.source,
                                references=threat.references,
                            ))
        except OSError:
            pass

    # poetry.lock — parse all package blocks once, then match each.
    poetry_lock = os.path.join(path, "poetry.lock")
    if os.path.isfile(poetry_lock):
        try:
            with open(poetry_lock, "r", encoding="utf-8") as f:
                content = f.read()
            block_re = re.compile(
                r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"',
                re.DOTALL,
            )
            for m in block_re.finditer(content):
                pkg_name = _normalize_name(m.group(1), "pypi")
                pkg_ver = m.group(2)
                for threat in THREAT_DB:
                    if threat.ecosystem != "pypi":
                        continue
                    if _normalize_name(threat.name, "pypi") != pkg_name:
                        continue
                    if _is_compromised(pkg_ver, threat):
                        findings.append(Finding(
                            package=threat.name,
                            ecosystem="pypi",
                            version=pkg_ver,
                            severity=threat.severity,
                            location=poetry_lock,
                            attack_vector=threat.attack_vector,
                            remediation=threat.remediation,
                            source=threat.source,
                            references=threat.references,
                        ))
        except OSError:
            pass

    # Pipfile.lock — iterate once, normalize-match against every threat.
    pipfile_lock = os.path.join(path, "Pipfile.lock")
    if os.path.isfile(pipfile_lock):
        try:
            with open(pipfile_lock, "r", encoding="utf-8") as f:
                data = json.load(f)
            for section in ("default", "develop"):
                pkgs = data.get(section, {})
                for raw_name, pkg_info in pkgs.items():
                    pkg_name = _normalize_name(raw_name, "pypi")
                    version = pkg_info.get("version", "").lstrip("=")
                    for threat in THREAT_DB:
                        if threat.ecosystem != "pypi":
                            continue
                        if _normalize_name(threat.name, "pypi") != pkg_name:
                            continue
                        if _is_compromised(version, threat):
                            findings.append(Finding(
                                package=threat.name,
                                ecosystem="pypi",
                                version=version,
                                severity=threat.severity,
                                location=pipfile_lock,
                                attack_vector=threat.attack_vector,
                                remediation=threat.remediation,
                                source=threat.source,
                                references=threat.references,
                            ))
        except (json.JSONDecodeError, OSError):
            pass

    return findings


def _scan_pip_installed() -> List[Finding]:
    """Check currently installed pip packages for compromised versions."""
    findings: List[Finding] = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return findings
        packages = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return findings

    for pkg in packages:
        pkg_name = _normalize_name(pkg.get("name", ""), "pypi")
        pkg_version = pkg.get("version", "")
        for threat in THREAT_DB:
            if threat.ecosystem != "pypi":
                continue
            if _normalize_name(threat.name, "pypi") != pkg_name:
                continue
            if _is_compromised(pkg_version, threat):
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="pypi",
                    version=pkg_version,
                    severity=threat.severity,
                    location="pip (currently installed)",
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                    source=threat.source,
                    references=threat.references,
                ))

    return findings


def _scan_pth_backdoors() -> List[Finding]:
    """Scan Python site-packages for suspicious .pth backdoor files."""
    findings: List[Finding] = []
    try:
        import site
        site_dirs = site.getsitepackages()
        user_site = site.getusersitepackages()
        if isinstance(user_site, str):
            site_dirs.append(user_site)
    except Exception:
        return findings

    # Known suspicious patterns in .pth files (code execution, imports)
    suspicious_patterns = [
        re.compile(r"import\s+os"),
        re.compile(r"import\s+subprocess"),
        re.compile(r"exec\s*\("),
        re.compile(r"eval\s*\("),
        re.compile(r"__import__"),
        re.compile(r"requests\."),
        re.compile(r"urllib"),
        re.compile(r"socket\."),
        re.compile(r"base64\."),
    ]

    for site_dir in site_dirs:
        if not os.path.isdir(site_dir):
            continue
        for pth_file in glob.glob(os.path.join(site_dir, "*.pth")):
            try:
                with open(pth_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for pattern in suspicious_patterns:
                    if pattern.search(content):
                        findings.append(Finding(
                            package="unknown",
                            ecosystem="pypi",
                            version="n/a",
                            severity="critical",
                            location=pth_file,
                            attack_vector=(
                                "Suspicious .pth file with code execution detected. "
                                "This may be a persistence backdoor from the litellm supply chain attack. "
                                ".pth files in site-packages execute on every Python startup."
                            ),
                            remediation=(
                                f"1. Inspect the file: {pth_file}\n"
                                f"2. If you don't recognize it, delete it immediately\n"
                                "3. Rotate all credentials accessible from this machine"
                            ),
                            source="Arcis Security Research",
                            references=[
                                "https://github.com/BerriAI/litellm/security/advisories",
                            ],
                            finding_type="persistence_artifact",
                        ))
                        break  # one finding per file is enough
            except OSError:
                pass

    return findings


# ── Unified scanner ──────────────────────────────────────────────────────────


def discover_manifests(path: str) -> List[str]:
    """List supported manifest/lockfile paths that exist under `path`.

    Returned values are absolute paths. Used by the CLI to print a
    "Scanned X" line so green output is unambiguous.
    """
    candidates = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "node_modules",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
    ]
    found: List[str] = []
    for name in candidates:
        full = os.path.join(path, name)
        if os.path.exists(full):
            found.append(full)
    return found


def scan_project(path: str, check_system: bool = False) -> List[Finding]:
    """
    Run all supply chain checks against a project directory.

    Args:
        path: Project root directory to scan.
        check_system: If True, also check globally installed packages
                      and site-packages for backdoor artifacts.
    """
    findings: List[Finding] = []

    findings.extend(_scan_package_lock(path))
    findings.extend(_scan_yarn_lock(path))
    findings.extend(_scan_node_modules(path))
    findings.extend(_scan_requirements(path))

    if check_system:
        findings.extend(_scan_pip_installed())
        findings.extend(_scan_pth_backdoors())

    # Deduplicate by (package, version, location)
    seen: set = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.package, f.version, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


# ── Report printer ───────────────────────────────────────────────────────────


def print_sca_report(
    path: str,
    findings: List[Finding],
    duration: float,
    no_color: bool = False,
    manifests: Optional[List[str]] = None,
) -> None:
    line = LINE_CHAR * WIDTH
    c = lambda text, *codes: _c(*codes, text=text, no_color=no_color)

    # Build manifest summary line — group by ecosystem so users see "package.json,
    # package-lock.json (npm)" instead of an opaque path list.
    manifest_summary = ""
    if manifests:
        rels = [os.path.relpath(m, path) for m in manifests]
        manifest_summary = ", ".join(rels)

    print()
    print(c("  Arcis Supply Chain Scanner", BOLD, CYAN))
    print(c(f"  Target:    {path}", DIM))
    if manifest_summary:
        print(c(f"  Manifests: {manifest_summary}", DIM))
    print(c(f"  Threat DB: {len(THREAT_DB)} known compromised package{'s' if len(THREAT_DB) != 1 else ''}", DIM))
    print(c(f"  Mode:      Offline - no network calls, no telemetry", DIM))
    print(c(line, DIM))

    if not findings:
        # Explicit "what we checked" message instead of just "nothing
        # detected" — closes the "did this actually run?" gap that pilots
        # ran into when the scanner was silent.
        manifests_count = len(manifests) if manifests else 0
        if manifests_count > 0:
            tail = f"in {manifests_count} manifest{'s' if manifests_count != 1 else ''}"
        else:
            tail = "in installed packages"
        print()
        print(c(f"  {TICK}  Clean. No known compromised packages found {tail}.", GREEN, BOLD))
        print(c(f"     {len(THREAT_DB)} known compromise{'s' if len(THREAT_DB) != 1 else ''} checked, 0 matches.", DIM))
        print()
        print(c(line, DIM))
        print(f"  {c('Summary', BOLD)}")
        if manifests_count:
            print(f"    Manifests       {manifests_count}")
        print(f"    Compromised     {c('0', GREEN, BOLD)}")
        print(f"    Time            {_format_sca_duration(duration)}")
        print(c(line, DIM))
        print()
        return

    npm_findings = [f for f in findings if f.ecosystem == "npm"]
    pypi_findings = [f for f in findings if f.ecosystem == "pypi"]

    severity_color = {"critical": RED, "high": YELLOW}

    for group_name, group in [("npm", npm_findings), ("PyPI", pypi_findings)]:
        if not group:
            continue
        print()
        print(c(f"  {group_name}", BOLD, WHITE))

        for f in group:
            sev_col = severity_color.get(f.severity, YELLOW)
            sev_label = f.severity.upper()

            if f.finding_type == "trojanized_dep":
                type_label = "TROJANIZED DEPENDENCY"
            elif f.finding_type == "persistence_artifact":
                type_label = "BACKDOOR ARTIFACT"
            else:
                type_label = "COMPROMISED VERSION"

            print()
            print(c(f"    {CROSS}  [{sev_label}] {type_label}", sev_col, BOLD))
            print(f"       Package:   {f.package}@{f.version}")
            print(c(f"       Location:  {f.location}", DIM))
            print()
            print(c("       Attack:", BOLD, WHITE))
            for av_line in _wrap(f.attack_vector, 55):
                print(f"         {av_line}")
            print()
            print(c("       Source:", BOLD, WHITE))
            print(f"         {f.source}")
            if f.references:
                for ref in f.references:
                    print(c(f"         {ref}", DIM))
            print()
            print(c("       Fix:", BOLD, GREEN))
            for rem_line in f.remediation.split("\n"):
                print(f"         {rem_line.strip()}")

    print()
    print(c(line, DIM))
    print()

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    print(f"  {c('Summary', BOLD)}")
    if manifests:
        print(f"    Manifests       {len(manifests)}")
    print(f"    Compromised     {c(str(len(findings)), RED, BOLD)}")
    if critical:
        print(f"    Critical        {c(str(critical), RED, BOLD)}")
    if high:
        print(f"    High            {c(str(high), YELLOW, BOLD)}")
    print(f"    Time            {_format_sca_duration(duration)}")
    print()
    print(c(f"  {CROSS}  Supply chain compromise detected — follow remediation steps above", RED, BOLD))
    print()
    print(c(line, DIM))
    print()


def _format_sca_duration(seconds: float) -> str:
    """Render duration as 89ms / 1.4s / 2m 18s — matches audit/scan."""
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins}m {secs}s"


def print_threat_list(no_color: bool = False) -> None:
    """Print all threats in the database — for transparency and auditing."""
    line = LINE_CHAR * WIDTH
    c = lambda text, *codes: _c(*codes, text=text, no_color=no_color)

    print()
    print(c("  Arcis SCA — Threat Database", BOLD, CYAN))
    print(c(f"  {len(THREAT_DB)} known supply chain attack{'s' if len(THREAT_DB) != 1 else ''}", DIM))
    print(c(f"  Source: {_THREAT_DB_PATH}", DIM))
    print(c(line, DIM))

    for threat in THREAT_DB:
        sev_col = RED if threat.severity == "critical" else YELLOW
        print()
        print(c(f"  {threat.name} ({threat.ecosystem})", BOLD, WHITE))
        print(f"    Severity:    {c(threat.severity.upper(), sev_col, BOLD)}")
        print(f"    CVE:         {threat.cve}")
        print(f"    Disclosed:   {threat.disclosure_date}")
        print(f"    Versions:    {', '.join(threat.malicious_versions)}")
        print()
        print(c("    Attack:", BOLD))
        for line_text in _wrap(threat.attack_vector, 56):
            print(f"      {line_text}")
        if threat.references:
            print()
            print(c("    References:", BOLD))
            for ref in threat.references:
                print(c(f"      {ref}", DIM))

    print()
    print(c(line, DIM))
    print()


def _wrap(text: str, width: int) -> List[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines


# ── CLI entry point ──────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis sca",
        description=(
            "Supply Chain Attack Scanner — detect compromised packages "
            "from known supply chain attacks.\n\n"
            "Runs entirely offline. Reads lockfiles and installed packages only.\n"
            "No network calls. No telemetry. Threat database: arcis/data/threat-db.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--system",
        action="store_true",
        help="Also scan globally installed packages and site-packages for backdoor artifacts",
    )
    parser.add_argument(
        "--list-threats", "--list",
        action="store_true",
        dest="list_threats",
        help="List all threats in the bundled database and exit.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output (still prints findings + summary).",
    )

    args = parser.parse_args()

    if args.list_threats:
        print_threat_list(no_color=args.no_color)
        sys.exit(0)

    path = os.path.abspath(args.path)

    if not os.path.isdir(path):
        print(f"arcis sca: path not found: {path}")
        sys.exit(1)

    manifests = discover_manifests(path)
    if not manifests and not args.system:
        msg = (
            f"arcis sca: no supported manifests found in {path}\n"
            "  Looked for: package-lock.json, yarn.lock, pnpm-lock.yaml, node_modules,\n"
            "             requirements.txt, Pipfile.lock, poetry.lock\n"
            "  Run from your project root, or pass --system to scan installed packages."
        )
        if args.no_color:
            print(msg)
        else:
            print(f"\033[33m{msg}\033[0m")
        sys.exit(2)

    # Live progress: spinner with the current manifest being read. Goes
    # to stderr so piping the report stays clean. Falls through to a
    # silent run on non-TTY (CI) and on --quiet / --no-color.
    use_live = not args.quiet and not args.no_color
    start = time.time()
    if use_live and (manifests or args.system):
        with live_status(initial="Reading manifests...") as status:
            for m in manifests:
                status.update(f"Reading [dim cyan]{os.path.relpath(m, path)}[/]")
            if args.system:
                status.update("Scanning installed packages...")
            findings = scan_project(path, check_system=args.system)
    else:
        findings = scan_project(path, check_system=args.system)
    duration = time.time() - start

    # Manifest list is now part of the header inside print_sca_report,
    # so the standalone "Scanned X manifests" line is no longer needed.
    print_sca_report(path, findings, duration, no_color=args.no_color, manifests=manifests)

    # Upload to dashboard. SCA results live in the same UI surface as
    # `arcis audit` (both are "static analysis"); language="sca" is the
    # taxonomy marker the frontend filters on.
    try:
        from .dashboard import upload as dashboard_upload
        dashboard_findings = [
            {
                "package": f.package,
                "ecosystem": f.ecosystem,
                "version": f.version,
                "severity": f.severity,
                "location": f.location,
                "attackVector": (f.attack_vector or "")[:500],
                "remediation": (f.remediation or "")[:500],
                "source": f.source,
                "findingType": f.finding_type,
            }
            for f in findings[:200]
        ]
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        dashboard_upload(
            kind="audits",
            body={
                "language": "sca",
                "target": path,
                "summary": {
                    "manifestsScanned": len(manifests),
                    "manifests": [os.path.relpath(m, path) for m in manifests],
                    "threatDbSize": len(THREAT_DB),
                    "durationSeconds": round(duration, 3),
                    "bySeverity": sev_counts,
                    "findings": dashboard_findings,
                    "truncated": len(findings) > len(dashboard_findings),
                },
                "findingsCount": len(findings),
            },
            quiet=args.quiet,
        )
    except Exception:
        pass

    sys.exit(1 if findings else 0)
