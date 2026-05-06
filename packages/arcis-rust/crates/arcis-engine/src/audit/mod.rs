//! Static analysis audit module.
//!
//! Direct port of `packages/arcis-python/arcis/cli/audit.py`. The split
//! across submodules mirrors the engine / cli boundary used elsewhere in
//! this workspace:
//!
//!   * `rules`  — rule registry, severity / language types, lazy regex
//!                compilation. No I/O, no walker. Pure data + compile.
//!   * `walker` — file collection (mirrors `_collect_files`); honours
//!                `SKIP_DIRS` and `LANGUAGE_MAP`. (Phase B2 step 2.)
//!   * `engine` — applies compiled rules to walked files, emits findings.
//!                Per-line scan, comment-skip, safe-pattern exemption,
//!                deterministic sort. (Phase B2 step 3.)
//!
//! Output formatting (human / `--json` / `--sarif`) lives in `arcis-cli`
//! next to the clap glue.

pub mod rules;

pub use rules::{rules, Language, Rule, Severity};
