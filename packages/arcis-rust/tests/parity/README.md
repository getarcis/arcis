# Parity test harness

Runs the Python `arcis` CLI and the built Rust `arcis` binary against the
same fixture inputs and asserts that they agree on exit code and output
shape. As more commands port from Python to Rust, fixtures move from
"structure parity" (regex match) to "byte-equal parity" (set
`"byte_equal": true` on the fixture).

Phase A covers the dispatcher only: `--version`, `--help`, `--list`,
unknown command. The four real subcommands (scan / audit / sca / update)
are stubs in Phase A and gain parity coverage as each ports.

## Running locally

```
# 1. Install the Python CLI in editable mode (one time):
pip install -e packages/arcis-python

# 2. Build the Rust binary:
cd packages/arcis-rust
cargo build --release

# 3. Run the harness:
python tests/parity/run.py --rust-bin target/release/arcis
```

`--rust-bin` is required; the harness aborts if the path doesn't point at
a real file. `--py-cmd` defaults to `python -m arcis.cli` and accepts a
shell-style override.

To narrow to one fixture during iteration:

```
python tests/parity/run.py --rust-bin target/release/arcis --fixture help-shows-catalog
```

## Adding a fixture

Drop a JSON file into `fixtures/`. Schema:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Human-readable name shown in the run report |
| `args` | string[] | yes | Argv passed to both binaries (excluding the binary name) |
| `exit_code` | int | yes | Expected exit code; both binaries must hit this |
| `stdout_pattern` | regex | no | Multi-line regex; both stdouts must match if set |
| `stderr_pattern` | regex | no | Same shape, against stderr |
| `byte_equal` | bool | no | When `true`, demand byte-equal stdout (use after ports stabilize) |

Example (Phase B, byte-equal):

```json
{
  "name": "sca on a clean project produces the same JSON",
  "args": ["sca", "tests/parity/fixtures-data/clean-project", "--json"],
  "exit_code": 0,
  "byte_equal": true
}
```

## Exit codes

The harness exits 0 when every fixture passes, 1 otherwise. CI fails the
build on non-zero. There's no "skip" mechanism on purpose: a fixture
either applies or it doesn't, and the file should be deleted if not
applicable rather than left in a half-disabled state.
