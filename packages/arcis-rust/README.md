# Arcis Rust CLI

Native Rust port of the Arcis CLI (`arcis scan`, `arcis audit`, `arcis sca`).
This is the strangler-fig migration: the Python CLI keeps shipping every
feature until the Rust binary is verified at byte-level parity, then we
delete Python.

See [`documents/plans/rust-cli.md`](../../../documents/plans/rust-cli.md)
for the migration plan and acceptance criteria.

## Status

**Phase A — workspace + parity harness.** Boot bones only:

- `arcis --version`
- `arcis --help`
- subcommand stubs (`scan` / `audit` / `sca` / `update`) print "Phase B"
- byte-equal-ish parity against the Python CLI via the harness in
  `tests/parity/`

Subsequent phases port `sca`, `audit`, `scan`, and discovery in risk order.

## Layout

```
packages/arcis-rust/
  Cargo.toml             — workspace root
  crates/
    arcis-cli/           — binary; the `arcis` command
    arcis-engine/        — shared library (sanitizers, matchers, parser)
    arcis-data/          — embedded JSON data via include_bytes!()
  tests/parity/          — Python harness that diffs both binaries
```

## Build

```
cargo build --workspace --release
```

The release binary lands at `target/release/arcis` (or `arcis.exe` on
Windows).

## Parity test (local)

After building, from the repo root:

```
cd packages/arcis-rust
python tests/parity/run.py --rust-bin target/release/arcis
```

The Python CLI must be installed first:

```
pip install -e packages/arcis-python
```

## Adding a parity fixture

Drop a JSON file into `tests/parity/fixtures/`:

```json
{
  "name": "scan --list shows category catalog",
  "args": ["scan", "--list"],
  "exit_code": 0,
  "stdout_pattern": "XSS"
}
```

The harness runs both binaries, asserts the exit code matches the fixture
and that the regex pattern shows up on each stdout (and that they don't
diverge from each other on exit code).

## Distribution

Eventually published as `@arcis/cli` on npm. The npm wrapper is a tiny
postinstall script that downloads the right binary for the host arch from
GitHub Releases. See the plan doc for the cutover details.
