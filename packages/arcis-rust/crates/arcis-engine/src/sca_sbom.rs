//! SBOM emitters for `arcis sca --sbom <format>`.
//!
//! Two formats:
//! * CycloneDX 1.5 JSON — `bomFormat: "CycloneDX"`, `specVersion: "1.5"`.
//!   Components carry purl + bom-ref; vulnerabilities live at root level
//!   with `affects[].ref` pointing back to component bom-refs.
//! * SPDX 2.3 JSON — `spdxVersion: "SPDX-2.3"`, `dataLicense: "CC0-1.0"`.
//!   Each vulnerability becomes a Package element of its own and is
//!   linked to affected packages via a `relationships` entry with
//!   `relationshipType: "AFFECTS"`. This is the SPDX 2.3 idiom; SPDX has
//!   no first-class vulnerability primitive, so shoehorning the
//!   CycloneDX `vulnerabilities` shape here would be off-spec.
//!
//! License fields are `NOASSERTION` everywhere — Arcis does not track
//! license metadata today. The metadata.licenses block (CycloneDX) and
//! the per-package `licenseConcluded` / `licenseDeclared` fields (SPDX)
//! both reflect this honestly rather than guessing or omitting.
//!
//! Determinism: components sort by purl, vulnerabilities sort by id
//! before emit. The (timestamp, document-id) provider is injectable via
//! `emit_*_with` so tests can pin a fixed clock + UUID for byte-stable
//! comparisons. Production callers use [`DefaultProvider`].

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use crate::sca::{Finding, PackageRef};

/// Tool name embedded in CycloneDX `metadata.tools` and SPDX
/// `creationInfo.creators`. Kept as a const so a typo can't drift across
/// the two emitters.
const TOOL_NAME: &str = "arcis-cli";
const TOOL_VENDOR: &str = "Arcis";

/// Engine crate version. Tracks the workspace version automatically.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Inputs that vary per run: a wall-clock timestamp and a 16-byte
/// document identifier. CycloneDX shapes the bytes as
/// `urn:uuid:<uuid-v4>`; SPDX shapes them as a URI under arcis.dev. Both
/// emitters consume the same provider so a test override pins both
/// formats with one fixture.
pub trait SbomProvider {
    /// ISO 8601 UTC timestamp, e.g. `2026-05-07T12:34:56Z`.
    fn timestamp(&self) -> String;
    /// Sixteen raw bytes used to seed the per-document identifier.
    fn raw_id(&self) -> [u8; 16];
}

/// Real-clock provider: timestamp from `SystemTime::now()`, raw id from
/// nanos + process id + a per-process counter. The bytes are formatted
/// per RFC 4122 §4.4 (UUID v4 variant bits) when emitted as a UUID.
pub struct DefaultProvider;

impl SbomProvider for DefaultProvider {
    fn timestamp(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_iso8601_utc(secs)
    }

    fn raw_id(&self) -> [u8; 16] {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = std::process::id() as u64;
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&nanos.to_le_bytes());
        out[8..12].copy_from_slice(&(pid as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(count as u32).to_le_bytes());
        out
    }
}

/// Format `secs` since UNIX_EPOCH as `YYYY-MM-DDTHH:MM:SSZ`. We ship a
/// hand-rolled formatter so we don't pull `chrono` for one timestamp.
/// Algorithm follows the civil-from-days conversion documented at
/// <https://howardhinnant.github.io/date_algorithms.html>.
fn format_iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Format raw 16 bytes as `urn:uuid:<uuid-v4>` per RFC 4122 §4.4. The
/// version (4) and variant (2) bit fields are forced into the standard
/// positions; everything else is taken verbatim from the provider.
fn format_uuid_urn(raw: [u8; 16]) -> String {
    let mut b = raw;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

/// Format raw 16 bytes as a 32-character lowercase hex string. SPDX
/// `documentNamespace` is a URI; the convention is a domain we control
/// followed by a unique-per-document segment.
fn format_hex32(raw: [u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `pkg:<eco>/<name>@<version>` per the package-url spec. Ecosystem
/// strings are lower-cased to match purl convention (purl uses `pypi`,
/// not OSV's `PyPI`).
pub fn purl(ecosystem: &str, name: &str, version: &str) -> String {
    format!(
        "pkg:{}/{}@{}",
        ecosystem.to_ascii_lowercase(),
        name,
        version
    )
}

/// Convert a key into a SPDXID-safe identifier. SPDXID may only contain
/// `[A-Za-z0-9.\-+]`; everything else is replaced with `-`. Result is
/// prefixed with `SPDXRef-` per spec.
fn spdxid_for(prefix: &str, key: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + key.len() + 8);
    out.push_str("SPDXRef-");
    out.push_str(prefix);
    out.push('-');
    for c in key.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    out
}

/// Extract a stable vulnerability id from a `Finding`. Walk references
/// for a GHSA URL, fall back to parsing `osv:<id>` from `source`, fall
/// back to a synthesized id keyed on package + version. The synthesized
/// fallback is stable across runs for the same finding so determinism
/// holds even when no advisory id is available.
pub fn vuln_id(finding: &Finding) -> String {
    static GHSA_RE: OnceLock<Regex> = OnceLock::new();
    let re = GHSA_RE.get_or_init(|| {
        // Case-insensitive match — embedded refs sometimes lowercase the segment.
        Regex::new(r"(?i)GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}").unwrap()
    });
    for r in &finding.references {
        if let Some(m) = re.find(r) {
            return m.as_str().to_ascii_uppercase();
        }
    }
    if let Some(rest) = finding.source.strip_prefix("osv:") {
        return rest.to_string();
    }
    format!("arcis-{}-{}", finding.package, finding.version)
}

/// Map our internal severity strings to CycloneDX 1.5 rating values.
/// The DB only emits `critical`/`high`/`medium`/`low` today; anything
/// else collapses to `unknown` rather than guessing.
fn cyclonedx_severity(sev: &str) -> &'static str {
    match sev {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "unknown",
    }
}

/// Group findings by purl. The same package can have multiple findings
/// (e.g. one DB hit + one OSV hit), and SBOMs cross-link them at the
/// component level, so the purl-keyed group is the right unit.
fn findings_by_purl(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut map: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        let key = purl(&f.ecosystem, &f.package, &f.version);
        map.entry(key).or_default().push(f);
    }
    map
}

/// Sort + dedupe packages by purl. The same package can show up in
/// multiple manifests (`location` differs); for SBOM purposes only the
/// `(ecosystem, name, version)` tuple matters.
fn unique_packages(packages: &[PackageRef]) -> Vec<&PackageRef> {
    let mut by_purl: BTreeMap<String, &PackageRef> = BTreeMap::new();
    for p in packages {
        let key = purl(&p.ecosystem, &p.name, &p.version);
        by_purl.entry(key).or_insert(p);
    }
    by_purl.into_values().collect()
}

// ── CycloneDX 1.5 ────────────────────────────────────────────────────────

/// Emit a CycloneDX 1.5 JSON document for the given packages and
/// findings. Output is pretty-printed (2-space indent) with a trailing
/// newline.
pub fn emit_cyclonedx<W: Write>(
    w: &mut W,
    packages: &[PackageRef],
    findings: &[Finding],
) -> io::Result<()> {
    emit_cyclonedx_with(w, packages, findings, &DefaultProvider)
}

/// Test-friendly form: the caller injects an `SbomProvider` so the
/// timestamp + serial number can be pinned for byte-stable assertions.
pub fn emit_cyclonedx_with<W: Write, P: SbomProvider + ?Sized>(
    w: &mut W,
    packages: &[PackageRef],
    findings: &[Finding],
    provider: &P,
) -> io::Result<()> {
    let unique = unique_packages(packages);
    let by_purl = findings_by_purl(findings);

    let components: Vec<Value> = unique
        .iter()
        .map(|p| {
            let pu = purl(&p.ecosystem, &p.name, &p.version);
            json!({
                "type": "library",
                "bom-ref": pu,
                "name": p.name,
                "version": p.version,
                "purl": pu,
                "licenses": [{ "license": { "id": "NOASSERTION" } }],
            })
        })
        .collect();

    let mut vulns: Vec<Value> = Vec::new();
    for (pu, group) in &by_purl {
        let mut seen_ids: HashSet<String> = HashSet::new();
        for f in group {
            let id = vuln_id(f);
            if !seen_ids.insert(id.clone()) {
                continue;
            }
            let entry = json!({
                "id": id,
                "source": { "name": vuln_source_name(&id) },
                "ratings": [{ "severity": cyclonedx_severity(&f.severity) }],
                "description": f.attack_vector,
                "affects": [{ "ref": pu }],
            });
            vulns.push(entry);
        }
    }
    vulns.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or("")
            .cmp(b["id"].as_str().unwrap_or(""))
    });

    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format_uuid_urn(provider.raw_id()),
        "version": 1,
        "metadata": {
            "timestamp": provider.timestamp(),
            "tools": [{
                "vendor": TOOL_VENDOR,
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
            }],
            "licenses": [{
                "expression": "NOASSERTION",
                "comment": "Arcis does not track package license metadata; all license fields in this SBOM are NOASSERTION.",
            }],
        },
        "components": components,
        "vulnerabilities": vulns,
    });

    serde_json::to_writer_pretty(&mut *w, &bom).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
}

/// Pick a reasonable `vulnerabilities[].source.name` from an id. GHSA
/// ids are explicit; CVE ids come from NVD; everything else falls into
/// the synthesized-id bucket and gets attributed to Arcis.
fn vuln_source_name(id: &str) -> &'static str {
    if id.starts_with("GHSA-") {
        "GitHub Security Advisory"
    } else if id.starts_with("CVE-") {
        "NVD"
    } else {
        "Arcis"
    }
}

// ── SPDX 2.3 ─────────────────────────────────────────────────────────────

/// Emit an SPDX 2.3 JSON document for the given packages and findings.
/// Output is pretty-printed (2-space indent) with a trailing newline.
pub fn emit_spdx<W: Write>(
    w: &mut W,
    packages: &[PackageRef],
    findings: &[Finding],
) -> io::Result<()> {
    emit_spdx_with(w, packages, findings, &DefaultProvider)
}

/// Test-friendly form: the caller injects an `SbomProvider` so the
/// timestamp + document namespace can be pinned for byte-stable
/// assertions.
pub fn emit_spdx_with<W: Write, P: SbomProvider + ?Sized>(
    w: &mut W,
    packages: &[PackageRef],
    findings: &[Finding],
    provider: &P,
) -> io::Result<()> {
    let unique = unique_packages(packages);
    let by_purl = findings_by_purl(findings);

    let mut packages_json: Vec<Value> = Vec::with_capacity(unique.len() + 1);
    let mut relationships: Vec<Value> = Vec::new();

    // Root document → DESCRIBES every component package. SPDX requires
    // the document to declare what it describes; without this the file
    // fails most validators.
    let root_id = "SPDXRef-DOCUMENT";

    for p in &unique {
        let pu = purl(&p.ecosystem, &p.name, &p.version);
        let spdx_id = spdxid_for("Package", &pu);
        packages_json.push(json!({
            "name": p.name,
            "SPDXID": spdx_id,
            "versionInfo": p.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": pu,
            }],
        }));
        relationships.push(json!({
            "spdxElementId": root_id,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        }));
    }

    // Vulnerabilities — emit each as its own Package per SPDX 2.3
    // convention (no first-class vuln primitive) and link via
    // relationships. Severity + summary go into `comment` because SPDX
    // doesn't have a structured rating field.
    let mut emitted_vulns: HashSet<String> = HashSet::new();
    let mut vuln_packages: Vec<Value> = Vec::new();
    for (pu, group) in &by_purl {
        let pkg_spdxid = spdxid_for("Package", pu);
        for f in group {
            let id = vuln_id(f);
            let vuln_spdxid = spdxid_for("Vulnerability", &id);
            if emitted_vulns.insert(id.clone()) {
                let mut external_refs = vec![json!({
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": advisory_url_for(&id, &f.references),
                })];
                if id.starts_with("CVE-") {
                    external_refs.push(json!({
                        "referenceCategory": "SECURITY",
                        "referenceType": "cve",
                        "referenceLocator": id,
                    }));
                }
                vuln_packages.push(json!({
                    "name": id,
                    "SPDXID": vuln_spdxid,
                    "versionInfo": "advisory",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "comment": format!("Severity: {}\nSummary: {}", f.severity, f.attack_vector),
                    "externalRefs": external_refs,
                }));
            }
            relationships.push(json!({
                "spdxElementId": vuln_spdxid,
                "relationshipType": "AFFECTS",
                "relatedSpdxElement": pkg_spdxid,
            }));
        }
    }

    // Stable order: vulnerability packages sort by id (BTreeMap iteration
    // above is by purl, not by id; resort defensively for byte-stable
    // output regardless of the per-purl insertion path).
    vuln_packages.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });
    packages_json.extend(vuln_packages);

    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": root_id,
        "name": "arcis-sbom",
        "documentNamespace": format!(
            "https://arcis.dev/sbom/spdx/{}",
            format_hex32(provider.raw_id())
        ),
        "creationInfo": {
            "created": provider.timestamp(),
            "creators": [format!("Tool: {TOOL_NAME}-{TOOL_VERSION}")],
            "comment": "Arcis does not track package license metadata; all license fields in this SBOM are NOASSERTION.",
        },
        "packages": packages_json,
        "relationships": relationships,
    });

    serde_json::to_writer_pretty(&mut *w, &doc).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
}

/// Pick a sensible advisory URL for the SPDX `referenceLocator`. Prefer
/// a URL from the finding's reference list that already contains the
/// id; fall back to the canonical github-advisories URL when the id is
/// GHSA-shaped or NVD URL when CVE-shaped; final fallback is
/// `NOASSERTION`.
fn advisory_url_for(id: &str, references: &[String]) -> String {
    for r in references {
        if r.contains(id) {
            return r.clone();
        }
    }
    if id.starts_with("GHSA-") {
        format!("https://github.com/advisories/{id}")
    } else if id.starts_with("CVE-") {
        format!("https://nvd.nist.gov/vuln/detail/{id}")
    } else {
        "NOASSERTION".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sca::FindingType;

    /// Pinned provider for byte-stable tests.
    struct FixedProvider {
        ts: &'static str,
        raw: [u8; 16],
    }

    impl SbomProvider for FixedProvider {
        fn timestamp(&self) -> String {
            self.ts.to_string()
        }
        fn raw_id(&self) -> [u8; 16] {
            self.raw
        }
    }

    fn fixed() -> FixedProvider {
        FixedProvider {
            ts: "2026-05-07T12:34:56Z",
            raw: [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ],
        }
    }

    fn pkg(eco: &str, name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            location: format!("/tmp/proj/{name}"),
        }
    }

    fn finding(
        eco: &str,
        name: &str,
        version: &str,
        sev: &str,
        ghsa_ref: Option<&str>,
        source: &str,
    ) -> Finding {
        let references = match ghsa_ref {
            Some(g) => vec![format!("https://github.com/advisories/{g}")],
            None => Vec::new(),
        };
        Finding {
            package: name.to_string(),
            ecosystem: eco.to_string(),
            version: version.to_string(),
            severity: sev.to_string(),
            location: format!("/tmp/proj/{name}/lock"),
            attack_vector: format!("{name} {version} compromise vector"),
            remediation: "upgrade".to_string(),
            source: source.to_string(),
            references,
            finding_type: FindingType::CompromisedVersion,
        }
    }

    /// Shared fixture: 5 packages (3 npm + 2 pypi), 3 findings (axios×2 + litellm).
    /// Mirrors the realistic mixed-ecosystem case the CLI reports today.
    fn sbom_fixture() -> (Vec<PackageRef>, Vec<Finding>) {
        let packages = vec![
            pkg("npm", "axios", "1.14.1"),
            pkg("npm", "axios", "0.30.4"),
            pkg("npm", "lodash", "4.17.20"),
            pkg("pypi", "litellm", "1.82.7"),
            pkg("pypi", "requests", "2.28.1"),
        ];
        let findings = vec![
            finding(
                "npm",
                "axios",
                "1.14.1",
                "critical",
                Some("GHSA-aaaa-bbbb-cccc"),
                "npm Security Advisory",
            ),
            finding(
                "npm",
                "axios",
                "0.30.4",
                "high",
                Some("GHSA-dddd-eeee-ffff"),
                "npm Security Advisory",
            ),
            finding(
                "pypi",
                "litellm",
                "1.82.7",
                "critical",
                None,
                "osv:GHSA-1234-5678-90ab",
            ),
        ];
        (packages, findings)
    }

    /// Render to a String for ergonomic asserts.
    fn render_cyclonedx(packages: &[PackageRef], findings: &[Finding]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        emit_cyclonedx_with(&mut buf, packages, findings, &fixed()).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn render_spdx(packages: &[PackageRef], findings: &[Finding]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        emit_spdx_with(&mut buf, packages, findings, &fixed()).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).expect("emitted SBOM must parse as JSON")
    }

    #[test]
    fn purl_format() {
        assert_eq!(purl("npm", "axios", "1.14.1"), "pkg:npm/axios@1.14.1");
        assert_eq!(purl("pypi", "litellm", "1.82.7"), "pkg:pypi/litellm@1.82.7");
        // Ecosystem case folds to purl spec convention.
        assert_eq!(purl("PyPI", "x", "1.0"), "pkg:pypi/x@1.0");
    }

    #[test]
    fn cyclonedx_shape() {
        let (packages, findings) = sbom_fixture();
        let out = render_cyclonedx(&packages, &findings);
        let v = parse(&out);

        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        let serial = v["serialNumber"].as_str().unwrap();
        assert!(
            serial.starts_with("urn:uuid:") && serial.len() == 9 + 36,
            "serialNumber must be a 36-char UUID URN, got {serial}"
        );

        let components = v["components"].as_array().unwrap();
        assert_eq!(components.len(), 5);
        let purls: Vec<&str> = components
            .iter()
            .map(|c| c["purl"].as_str().unwrap())
            .collect();
        assert!(purls.contains(&"pkg:npm/axios@1.14.1"));
        assert!(purls.contains(&"pkg:npm/axios@0.30.4"));
        assert!(purls.contains(&"pkg:npm/lodash@4.17.20"));
        assert!(purls.contains(&"pkg:pypi/litellm@1.82.7"));
        assert!(purls.contains(&"pkg:pypi/requests@2.28.1"));

        // Components sorted by purl (deterministic output).
        let sorted_purls = {
            let mut p = purls.clone();
            p.sort();
            p
        };
        assert_eq!(purls, sorted_purls);

        // License is NOASSERTION on every component.
        for c in components {
            assert_eq!(
                c["licenses"][0]["license"]["id"], "NOASSERTION",
                "component {} must declare NOASSERTION",
                c["purl"]
            );
        }
    }

    #[test]
    fn cyclonedx_vulns_cross_link() {
        let (packages, findings) = sbom_fixture();
        let out = render_cyclonedx(&packages, &findings);
        let v = parse(&out);

        let vulns = v["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 3, "3 findings → 3 vuln entries");

        let ids: Vec<&str> = vulns.iter().map(|x| x["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"GHSA-AAAA-BBBB-CCCC"));
        assert!(ids.contains(&"GHSA-DDDD-EEEE-FFFF"));
        assert!(ids.contains(&"GHSA-1234-5678-90AB"));

        // Each vuln links to its component's purl via affects[].ref.
        for vuln in vulns {
            let id = vuln["id"].as_str().unwrap();
            let affected_ref = vuln["affects"][0]["ref"].as_str().unwrap();
            let expected = match id {
                "GHSA-AAAA-BBBB-CCCC" => "pkg:npm/axios@1.14.1",
                "GHSA-DDDD-EEEE-FFFF" => "pkg:npm/axios@0.30.4",
                "GHSA-1234-5678-90AB" => "pkg:pypi/litellm@1.82.7",
                _ => panic!("unexpected vuln id: {id}"),
            };
            assert_eq!(affected_ref, expected, "wrong cross-link for {id}");
        }

        // Severity rendered in CycloneDX rating shape.
        let crit = vulns
            .iter()
            .find(|x| x["id"] == "GHSA-AAAA-BBBB-CCCC")
            .unwrap();
        assert_eq!(crit["ratings"][0]["severity"], "critical");
    }

    #[test]
    fn cyclonedx_metadata_includes_tool() {
        let (packages, findings) = sbom_fixture();
        let out = render_cyclonedx(&packages, &findings);
        let v = parse(&out);

        let tools = v["metadata"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["vendor"], TOOL_VENDOR);
        assert_eq!(tools[0]["name"], TOOL_NAME);
        let version = tools[0]["version"].as_str().unwrap();
        assert!(
            !version.is_empty(),
            "metadata.tools[0].version must be non-empty"
        );
        assert_eq!(
            version, TOOL_VERSION,
            "version must come from CARGO_PKG_VERSION"
        );
    }

    #[test]
    fn cyclonedx_determinism() {
        let (packages, findings) = sbom_fixture();
        let a = render_cyclonedx(&packages, &findings);
        let b = render_cyclonedx(&packages, &findings);
        assert_eq!(a, b, "byte-identical output for the same input");
    }

    #[test]
    fn json_validity_cyclonedx() {
        let (packages, findings) = sbom_fixture();
        let out = render_cyclonedx(&packages, &findings);
        let _ = parse(&out); // panics if invalid
        assert!(out.ends_with('\n'), "must end with a newline");
    }

    #[test]
    fn spdx_shape() {
        let (packages, findings) = sbom_fixture();
        let out = render_spdx(&packages, &findings);
        let v = parse(&out);

        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["dataLicense"], "CC0-1.0");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        let ns = v["documentNamespace"].as_str().unwrap();
        assert!(
            ns.starts_with("https://arcis.dev/sbom/spdx/"),
            "documentNamespace must be under arcis.dev, got {ns}"
        );

        let packages_arr = v["packages"].as_array().unwrap();
        // 5 components + 3 vulnerability packages = 8.
        assert_eq!(packages_arr.len(), 5 + 3);

        // Components carry purl in externalRefs and NOASSERTION license fields.
        let component_pkgs: Vec<&Value> = packages_arr
            .iter()
            .filter(|p| p["versionInfo"] != "advisory")
            .collect();
        assert_eq!(component_pkgs.len(), 5);
        for p in &component_pkgs {
            assert_eq!(p["licenseConcluded"], "NOASSERTION");
            assert_eq!(p["licenseDeclared"], "NOASSERTION");
            assert_eq!(p["copyrightText"], "NOASSERTION");
            let ext = p["externalRefs"][0].clone();
            assert_eq!(ext["referenceCategory"], "PACKAGE-MANAGER");
            assert_eq!(ext["referenceType"], "purl");
            let purl_str = ext["referenceLocator"].as_str().unwrap();
            assert!(
                purl_str.starts_with("pkg:npm/") || purl_str.starts_with("pkg:pypi/"),
                "expected purl, got {purl_str}"
            );
        }
    }

    #[test]
    fn spdx_vuln_relationships() {
        let (packages, findings) = sbom_fixture();
        let out = render_spdx(&packages, &findings);
        let v = parse(&out);

        let rels = v["relationships"].as_array().unwrap();
        let affects: Vec<&Value> = rels
            .iter()
            .filter(|r| r["relationshipType"] == "AFFECTS")
            .collect();
        assert_eq!(affects.len(), 3, "3 findings → 3 AFFECTS relationships");

        // Each AFFECTS links a Vulnerability SPDXID to a Package SPDXID.
        for r in &affects {
            let v_id = r["spdxElementId"].as_str().unwrap();
            let p_id = r["relatedSpdxElement"].as_str().unwrap();
            assert!(
                v_id.starts_with("SPDXRef-Vulnerability-"),
                "spdxElementId must be a Vulnerability ref, got {v_id}"
            );
            assert!(
                p_id.starts_with("SPDXRef-Package-"),
                "relatedSpdxElement must be a Package ref, got {p_id}"
            );
        }

        // DESCRIBES links cover every component.
        let describes: Vec<&Value> = rels
            .iter()
            .filter(|r| r["relationshipType"] == "DESCRIBES")
            .collect();
        assert_eq!(
            describes.len(),
            5,
            "root document DESCRIBES every component"
        );
    }

    #[test]
    fn spdx_creation_info_includes_tool() {
        let (packages, findings) = sbom_fixture();
        let out = render_spdx(&packages, &findings);
        let v = parse(&out);

        let creators = v["creationInfo"]["creators"].as_array().unwrap();
        assert!(!creators.is_empty(), "creators array required by SPDX 2.3");
        let entry = creators[0].as_str().unwrap();
        let expected = format!("Tool: {TOOL_NAME}-{TOOL_VERSION}");
        assert_eq!(entry, expected);
    }

    #[test]
    fn spdx_determinism() {
        let (packages, findings) = sbom_fixture();
        let a = render_spdx(&packages, &findings);
        let b = render_spdx(&packages, &findings);
        assert_eq!(a, b);
    }

    #[test]
    fn json_validity_spdx() {
        let (packages, findings) = sbom_fixture();
        let out = render_spdx(&packages, &findings);
        let _ = parse(&out);
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn empty_project_emits_valid_sbom() {
        // No findings, but components present (clean project case).
        let packages = vec![
            pkg("npm", "lodash", "4.17.20"),
            pkg("pypi", "requests", "2.28.1"),
        ];
        let findings: Vec<Finding> = Vec::new();

        let cyclo = render_cyclonedx(&packages, &findings);
        let v = parse(&cyclo);
        assert_eq!(v["components"].as_array().unwrap().len(), 2);
        assert_eq!(v["vulnerabilities"].as_array().unwrap().len(), 0);

        let spdx = render_spdx(&packages, &findings);
        let v = parse(&spdx);
        // 2 components + 0 vuln packages.
        assert_eq!(v["packages"].as_array().unwrap().len(), 2);
        // 2 DESCRIBES relationships, no AFFECTS.
        let rels = v["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 2);
        for r in rels {
            assert_eq!(r["relationshipType"], "DESCRIBES");
        }
    }

    #[test]
    fn license_field_is_noassertion() {
        let (packages, findings) = sbom_fixture();

        let cyclo = render_cyclonedx(&packages, &findings);
        let v = parse(&cyclo);
        // Document-level rationale.
        assert_eq!(v["metadata"]["licenses"][0]["expression"], "NOASSERTION");
        assert!(v["metadata"]["licenses"][0]["comment"]
            .as_str()
            .unwrap()
            .contains("NOASSERTION"));
        // Component-level (already covered in cyclonedx_shape but assert
        // here too — license posture is load-bearing for compliance).
        for c in v["components"].as_array().unwrap() {
            assert_eq!(c["licenses"][0]["license"]["id"], "NOASSERTION");
        }

        let spdx = render_spdx(&packages, &findings);
        let v = parse(&spdx);
        assert!(v["creationInfo"]["comment"]
            .as_str()
            .unwrap()
            .contains("NOASSERTION"));
        for p in v["packages"].as_array().unwrap() {
            assert_eq!(p["licenseConcluded"], "NOASSERTION");
            assert_eq!(p["licenseDeclared"], "NOASSERTION");
        }
    }

    #[test]
    fn vuln_id_extracts_ghsa_from_references() {
        let f = finding("npm", "x", "1.0", "high", Some("GHSA-aaaa-bbbb-cccc"), "");
        assert_eq!(vuln_id(&f), "GHSA-AAAA-BBBB-CCCC");
    }

    #[test]
    fn vuln_id_falls_back_to_osv_source() {
        let f = finding("npm", "x", "1.0", "high", None, "osv:GHSA-zzzz-yyyy-xxxx");
        assert_eq!(vuln_id(&f), "GHSA-zzzz-yyyy-xxxx");
    }

    #[test]
    fn vuln_id_synthesizes_when_no_id_present() {
        let f = finding("npm", "weird-pkg", "0.0.1", "high", None, "");
        assert_eq!(vuln_id(&f), "arcis-weird-pkg-0.0.1");
    }

    #[test]
    fn iso8601_format() {
        // Epoch sanity.
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
        // The 1234567890-second mark is 2009-02-13 23:31:30 UTC — a
        // well-known reference. Tested against a hard-coded value
        // rather than a chrono round-trip to keep the engine free of
        // date dependencies.
        assert_eq!(format_iso8601_utc(1234567890), "2009-02-13T23:31:30Z");
    }

    #[test]
    fn uuid_urn_sets_v4_and_variant_bits() {
        let raw = [0u8; 16];
        let urn = format_uuid_urn(raw);
        // version nibble (13th hex char, 0-indexed) must be '4'
        let body = urn.strip_prefix("urn:uuid:").unwrap();
        let chars: Vec<char> = body.chars().collect();
        assert_eq!(chars[14], '4', "version nibble must be 4: {urn}");
        // variant nibble (17th hex char) must be 8/9/a/b
        assert!(
            matches!(chars[19], '8' | '9' | 'a' | 'b'),
            "variant nibble must be 8-b: {urn}"
        );
    }
}
