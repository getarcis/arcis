//! Embedded JSON data for the Arcis CLI.
//!
//! Threat DB, audit rules, and attack vectors are baked into the binary at
//! compile time via `include_bytes!()`. The bytes point at the same files
//! the Python CLI consumes — no drift possible because there's only one
//! canonical copy in the repo.
//!
//! Schema versions are checked on load. The Rust loader refuses to deserialize
//! a payload whose `schema_version` is newer than what it knows how to handle,
//! so a future Python release that bumps the schema doesn't silently break
//! the Rust binary in the field.

use thiserror::Error;

// Embedded payloads. Paths are relative to *this file*, so:
//   crates/arcis-data/src/lib.rs  ->  ../../../../arcis-python/arcis/data/<file>
//
// The `..` count goes: src/ -> arcis-data/ -> crates/ -> arcis-rust/ -> packages/
// One more `..` lands inside packages/arcis-python/.
pub const THREAT_DB_JSON: &[u8] =
    include_bytes!("../../../../arcis-python/arcis/data/threat-db.json");

pub const PATTERNS_JSON: &[u8] =
    include_bytes!("../../../../arcis-python/arcis/data/patterns.json");

/// Schema versions the Rust engine knows how to load. Bumped in lockstep
/// with the Python side. If you bump the schema in Python, also bump it
/// here and update the loader to handle the new shape.
pub const SUPPORTED_THREAT_DB_SCHEMA: &str = "2";

#[derive(Debug, Error)]
pub enum DataError {
    #[error("invalid JSON in {file}: {source}")]
    Parse {
        file: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("{file} has schema_version {found:?}, this build supports {expected}")]
    SchemaMismatch {
        file: &'static str,
        found: String,
        expected: &'static str,
    },
}

/// Lightweight envelope used to peek at a JSON file's schema_version field
/// without committing to the full domain shape. Keeps the loader gate
/// independent of the per-command struct definitions (which live in
/// arcis-engine and may change as commands are ported).
#[derive(serde::Deserialize)]
struct SchemaProbe {
    #[serde(default)]
    schema_version: String,
}

/// Verify that the embedded threat DB matches the schema version this build
/// understands. Returns `Ok(())` on match, or a `DataError::SchemaMismatch`
/// otherwise. Called eagerly by the CLI on startup so a mismatched build
/// fails loud rather than silently producing wrong findings.
pub fn check_threat_db_schema() -> Result<(), DataError> {
    let probe: SchemaProbe =
        serde_json::from_slice(THREAT_DB_JSON).map_err(|source| DataError::Parse {
            file: "threat-db.json",
            source,
        })?;

    if probe.schema_version != SUPPORTED_THREAT_DB_SCHEMA {
        return Err(DataError::SchemaMismatch {
            file: "threat-db.json",
            found: probe.schema_version,
            expected: SUPPORTED_THREAT_DB_SCHEMA,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_db_payload_is_present() {
        // include_bytes!() either succeeds at compile time or breaks the
        // build, so the byte slice is guaranteed non-empty if we got here.
        assert!(!THREAT_DB_JSON.is_empty(), "threat-db.json should embed");
    }

    #[test]
    fn threat_db_parses_as_json() {
        let v: serde_json::Value =
            serde_json::from_slice(THREAT_DB_JSON).expect("threat-db.json should parse");
        assert!(v.is_object(), "threat-db.json root should be an object");
    }

    #[test]
    fn threat_db_schema_matches_supported_version() {
        check_threat_db_schema().expect("threat-db.json schema should match");
    }

    #[test]
    fn patterns_payload_is_present() {
        assert!(!PATTERNS_JSON.is_empty(), "patterns.json should embed");
    }

    #[test]
    fn threat_db_has_threats_array() {
        let v: serde_json::Value = serde_json::from_slice(THREAT_DB_JSON).unwrap();
        let threats = v.get("threats").and_then(|t| t.as_array());
        let count = threats.map(|a| a.len()).unwrap_or(0);
        assert!(
            count >= 30,
            "expected the seeded threat DB to have >=30 entries, got {count}"
        );
    }
}
