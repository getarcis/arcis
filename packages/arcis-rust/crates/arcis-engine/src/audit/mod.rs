//! Static analysis audit module.
//!
//! Direct port of `packages/arcis-python/arcis/cli/audit.py`. The split
//! across submodules mirrors the engine / cli boundary used elsewhere in
//! this workspace:
//!
//! * `rules` - rule registry, severity / language types, lazy regex
//!   compilation. No I/O, no walker. Pure data + compile.
//! * `walker` - file collection (mirrors `_collect_files`); honours
//!   `SKIP_DIRS` and `LANGUAGE_MAP`. (Phase B2 step 2.)
//! * `engine` - applies compiled rules to walked files, emits findings.
//!   Per-line scan, comment-skip, safe-pattern exemption, deterministic
//!   sort. (Phase B2 step 3.)
//!
//! Output formatting (human / `--json` / `--sarif`) lives in `arcis-cli`
//! next to the clap glue.

pub mod baseline;
pub mod engine;
pub mod finding_id;
pub mod render;
pub mod rules;
pub mod suppress;
pub mod walker;

pub use baseline::{
    classify as classify_baseline, Baseline, BaselineEntry, BaselineError, BaselineSummary, Diff,
    BASELINE_SCHEMA_VERSION,
};
pub use engine::{
    scan_directory, scan_directory_with_suppression, scan_file, scan_file_with_suppression,
    FileResult, Finding,
};
pub use finding_id::{assign_ids, compute as compute_finding_id, normalize_relpath};
pub use render::{render_json, render_sarif, JsonReport, SarifReport};
pub use rules::{rules, Language, Rule, Severity};
pub use walker::{
    collect_files, collect_files_with_options, detect_language, IgnoreOptions, WalkResult,
    SKIP_DIRS,
};
