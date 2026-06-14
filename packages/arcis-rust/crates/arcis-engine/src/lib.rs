//! Shared engine logic for the Arcis CLI.
//!
//! Phase A is intentionally empty. As commands are ported in Phase B, the
//! relevant pieces land here:
//!
//! * `sca` - version range matcher, manifest parsers, name normalization
//! * `audit` - rule registry, regex engine, file walker
//! * `scan` - HTTP client, payload dispatcher, classifier
//! * `discovery` - env file parser, port sniffer, source-aware route walk
//!
//! The split between this crate and `arcis-cli` keeps entry-point glue
//! (clap parsing, exit codes, terminal formatting) separate from logic
//! that's worth testing in isolation.

#![forbid(unsafe_code)]

pub mod audit;
pub mod fs_util;
pub mod osv;
pub mod osv_cache;
pub mod sca;
pub mod sca_graph;
pub mod sca_lockfile;
pub mod sca_postinstall;
pub mod sca_render;
pub mod sca_sbom;
pub mod scan;
pub mod threat_db;
pub mod threat_db_refresh;
pub mod version;

/// Re-export the data crate so callers don't have to depend on it directly.
pub use arcis_data;

/// Verify all embedded data shapes that the engine knows how to load.
/// Called once at CLI startup so any schema mismatch fails loud.
pub fn check_embedded_schemas() -> Result<(), arcis_data::DataError> {
    arcis_data::check_threat_db_schema()
}

/// Engine version string. Reported by `arcis --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        // Tautological under const eval (`CARGO_PKG_VERSION` is a `&'static
        // str` literal injected by cargo) but kept as a contract check —
        // anyone replacing the env! macro with a runtime loader would
        // notice this break.
        #[allow(clippy::const_is_empty)]
        let ok = !VERSION.is_empty();
        assert!(ok);
    }

    #[test]
    fn embedded_schemas_load() {
        check_embedded_schemas().expect("embedded data should match supported schema");
    }
}
