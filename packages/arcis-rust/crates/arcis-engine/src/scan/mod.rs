//! HTTP scanner module.
//!
//! Direct port of `packages/arcis-python/arcis/cli/scan.py` (and its peers
//! `payloads.py` + `discovery.py`). Surface mirrors the engine / cli split
//! used elsewhere in the workspace:
//!
//! * `payloads` - attack-vector corpus (categories, default fields,
//!   blocked-status set). Static data, no I/O.
//! * `classifier` - `_classify(status, body, payload)` from `scan.py`:
//!   response shape -> hit / miss / connection-error.
//! * `discover` - env-file parser, port + control-plane probes,
//!   source-aware route walk for JS/TS/Python/Go.
//! * `probe` - async HTTP client (tokio + reqwest) with concurrency
//!   cap, ordered result collection.
//!
//! Output formatting (human / `--json`) lives in `arcis-cli` next to the
//! clap glue.

pub mod classifier;
pub mod discover;
pub mod payloads;
pub mod probe;
pub mod repro;

pub use classifier::{classify, Classification};
pub use discover::{
    detect_project_kind, detect_target, discover_routes, env_target, probe_control_plane,
    probe_dev_ports, read_env_files, sniff_framework, DiscoveredRoute, TargetCandidate,
    CONTROL_PLANE_URL, DEV_PORTS, ENV_TARGET_KEYS,
};
pub use payloads::{
    attack_categories, AttackCategory, AttackVector, BLOCKED_STATUS_CODES, DEFAULT_FIELDS,
};
pub use probe::{scan_route, send_one, RouteResult, ScanOptions, VectorResult};
pub use repro::format_curl;
