# @arcis/cli

Native Arcis security CLI, distributed via npm. Installs a single static
binary on every supported platform.

```bash
npm install -g @arcis/cli
arcis --help
```

## What it does

`arcis` is a security scanner with three subcommands:

* `arcis scan` — send live attack payloads at a running web app and report
  which got through.
* `arcis audit` — scan source code for known-unsafe patterns (Python /
  JavaScript / TypeScript). JSON and SARIF output for CI.
* `arcis sca` — match installed dependencies against the supply-chain
  threat database.

```bash
# Scan a running app for injection vulnerabilities
arcis scan http://localhost:5000

# Static audit of a project
arcis audit ./src

# Supply-chain check
arcis sca .
```

Run `arcis --list` for the full command catalog.

## How it works

This package is a thin wrapper. `npm install` runs a postinstall script
that:

1. Detects your platform and architecture.
2. Downloads the matching native binary from the GitHub Release pinned
   to this package's version.
3. Verifies the SHA-256 against the release's `SHA256SUMS` file.
4. Drops it as `bin/arcis-bin` so the npm `bin` shim can `exec` it.

No runtime dependencies. No language toolchain to install.

## Supported platforms

| Platform        | Architecture | Binary                                    |
|-----------------|--------------|-------------------------------------------|
| Linux (musl)    | x86_64       | `arcis-<v>-x86_64-unknown-linux-musl`     |
| Linux (musl)    | aarch64      | `arcis-<v>-aarch64-unknown-linux-musl`    |
| macOS           | arm64        | `arcis-<v>-aarch64-apple-darwin`          |
| Windows (MSVC)  | x86_64       | `arcis-<v>-x86_64-pc-windows-msvc`        |

The musl Linux builds are statically linked and run on Alpine,
`FROM scratch` Docker images, and minimal CI runners.

## Skipping the install download

If you install with `--ignore-scripts`, the binary won't be fetched.
You can rerun the installer manually:

```bash
node $(npm root -g)/@arcis/cli/install.js
```

Or set `ARCIS_CLI_SKIP_INSTALL=1` to defer the download intentionally
(useful for offline-first CI images that vendor the binary themselves).

## Source

The binary is built from the `packages/arcis-rust/` Rust workspace in
the [Arcis monorepo](https://github.com/getarcis/arcis). Build pipeline:
[`.github/workflows/rust-release.yml`](https://github.com/getarcis/arcis/blob/nwl/.github/workflows/rust-release.yml).

## License

MIT.
