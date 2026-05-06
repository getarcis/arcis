// Target-detection + URL-construction helpers for `@arcis/cli`.
//
// Pure functions only — no I/O, no network, no `process` mutation. The
// install script (`install.js`) wires these to the real npm install
// flow; the test suite (`test/targets.test.js`) exercises them with
// fake (platform, arch) tuples so we cover every combination from a
// single host.

"use strict";

// Map of (platform, arch) -> { target, archive, binary }.
// Mirrors documents/plans/rust-cli.md Phase C1 + the build matrix in
// `.github/workflows/rust-release.yml`.
const TARGETS = {
  "linux-x64": {
    target: "x86_64-unknown-linux-musl",
    archive: "tar.gz",
    binary: "arcis",
  },
  "linux-arm64": {
    target: "aarch64-unknown-linux-musl",
    archive: "tar.gz",
    binary: "arcis",
  },
  "darwin-arm64": {
    target: "aarch64-apple-darwin",
    archive: "tar.gz",
    binary: "arcis",
  },
  "win32-x64": {
    target: "x86_64-pc-windows-msvc",
    archive: "zip",
    binary: "arcis.exe",
  },
};

// Repository slug used to construct release-download URLs. Keep in sync
// with the repository `repository.url` in package.json.
const REPO = "Gagancm/arcis";

/** Resolve the target descriptor for a (platform, arch) tuple.
 *
 * Returns `null` when the host is unsupported so the caller can print
 * a helpful message instead of throwing a stack trace at the user.
 */
function detectTarget(platform, arch) {
  const key = `${platform}-${arch}`;
  return TARGETS[key] || null;
}

/** Human-readable list of supported platforms for error messages. */
function supportedPlatforms() {
  return Object.keys(TARGETS).map((k) => k.replace("-", "/")).sort();
}

/** Construct the GitHub-Releases URL for a binary archive.
 *
 *   archiveUrl({ version: "0.2.0", target: "x86_64-unknown-linux-musl",
 *                archive: "tar.gz" })
 *     -> https://github.com/Gagancm/arcis/releases/download/cli-v0.2.0/
 *        arcis-0.2.0-x86_64-unknown-linux-musl.tar.gz
 */
function archiveUrl({ version, target, archive }) {
  const filename = `arcis-${version}-${target}.${archive}`;
  return `https://github.com/${REPO}/releases/download/cli-v${version}/${filename}`;
}

/** URL of the SHA256SUMS file for a release. One file covers every
 * platform; install.js fetches it once and looks up the entry matching
 * the archive it just downloaded.
 */
function checksumsUrl(version) {
  return `https://github.com/${REPO}/releases/download/cli-v${version}/SHA256SUMS`;
}

/** Parse a `SHA256SUMS` file body into a Map<filename, hex_digest>.
 *
 * The release workflow writes lines as `<digest>  <filename>` (sha256sum
 * default format). We accept either two-space or single-space separators
 * because BSD `shasum -a 256` uses a single space.
 */
function parseChecksums(body) {
  const out = new Map();
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    // Match: <64-hex-digest> [* or space] <filename>
    const m = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (!m) continue;
    const digest = m[1].toLowerCase();
    const filename = m[2].trim();
    out.set(filename, digest);
  }
  return out;
}

module.exports = {
  TARGETS,
  REPO,
  detectTarget,
  supportedPlatforms,
  archiveUrl,
  checksumsUrl,
  parseChecksums,
};
