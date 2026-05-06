// Unit tests for the target-detection + URL helpers in lib/targets.js.
// Run via `npm test` (uses node --test, no third-party runner).

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  TARGETS,
  detectTarget,
  supportedPlatforms,
  archiveUrl,
  checksumsUrl,
  parseChecksums,
} = require("../lib/targets");

test("detectTarget picks the right tuple for each supported host", () => {
  assert.deepEqual(detectTarget("linux", "x64"), {
    target: "x86_64-unknown-linux-musl",
    archive: "tar.gz",
    binary: "arcis",
  });
  assert.deepEqual(detectTarget("linux", "arm64"), {
    target: "aarch64-unknown-linux-musl",
    archive: "tar.gz",
    binary: "arcis",
  });
  assert.deepEqual(detectTarget("darwin", "arm64"), {
    target: "aarch64-apple-darwin",
    archive: "tar.gz",
    binary: "arcis",
  });
  assert.deepEqual(detectTarget("win32", "x64"), {
    target: "x86_64-pc-windows-msvc",
    archive: "zip",
    binary: "arcis.exe",
  });
});

test("detectTarget returns null for unsupported combinations", () => {
  assert.equal(detectTarget("darwin", "x64"), null, "Intel macOS not shipped");
  assert.equal(detectTarget("linux", "ia32"), null, "32-bit Linux not shipped");
  assert.equal(detectTarget("freebsd", "x64"), null, "FreeBSD not in matrix");
  assert.equal(detectTarget("win32", "arm64"), null, "Windows arm64 not shipped");
});

test("TARGETS exposes exactly the four matrix entries", () => {
  assert.equal(Object.keys(TARGETS).length, 4);
});

test("supportedPlatforms returns a sorted human-readable list", () => {
  const list = supportedPlatforms();
  assert.equal(list.length, 4);
  // Sorted alphabetically.
  assert.deepEqual(
    list,
    ["darwin/arm64", "linux/arm64", "linux/x64", "win32/x64"],
  );
});

test("archiveUrl builds the canonical GitHub download path", () => {
  const url = archiveUrl({
    version: "0.2.0",
    target: "x86_64-unknown-linux-musl",
    archive: "tar.gz",
  });
  assert.equal(
    url,
    "https://github.com/Gagancm/arcis/releases/download/cli-v0.2.0/arcis-0.2.0-x86_64-unknown-linux-musl.tar.gz",
  );
});

test("archiveUrl handles zip archives for Windows", () => {
  const url = archiveUrl({
    version: "0.2.0",
    target: "x86_64-pc-windows-msvc",
    archive: "zip",
  });
  assert.ok(url.endsWith("/arcis-0.2.0-x86_64-pc-windows-msvc.zip"));
});

test("checksumsUrl points at the SHA256SUMS file at the release root", () => {
  assert.equal(
    checksumsUrl("0.2.0"),
    "https://github.com/Gagancm/arcis/releases/download/cli-v0.2.0/SHA256SUMS",
  );
});

test("parseChecksums handles the sha256sum default format", () => {
  const body = [
    "abc123def456abc123def456abc123def456abc123def456abc123def456abcd  arcis-0.2.0-x86_64-unknown-linux-musl.tar.gz",
    "1111111111111111111111111111111111111111111111111111111111111111  arcis-0.2.0-aarch64-apple-darwin.tar.gz",
    "",
    "# comment-line-allowed",
  ].join("\n");
  const map = parseChecksums(body);
  assert.equal(map.size, 2);
  assert.equal(
    map.get("arcis-0.2.0-x86_64-unknown-linux-musl.tar.gz"),
    "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
  );
  assert.equal(
    map.get("arcis-0.2.0-aarch64-apple-darwin.tar.gz"),
    "1111111111111111111111111111111111111111111111111111111111111111",
  );
});

test("parseChecksums handles BSD shasum-style single-space separator", () => {
  // Some macOS shasum -a 256 outputs use a single space rather than two.
  const body =
    "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcd arcis-0.2.0-aarch64-apple-darwin.tar.gz";
  const map = parseChecksums(body);
  assert.equal(map.size, 1);
  assert.equal(
    map.get("arcis-0.2.0-aarch64-apple-darwin.tar.gz"),
    "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcd",
  );
});

test("parseChecksums handles binary-mode `*` filename prefix", () => {
  // `sha256sum -b` produces lines like `<digest> *<filename>`.
  const body =
    "1234567890123456789012345678901234567890123456789012345678901234 *arcis-0.2.0-x86_64-pc-windows-msvc.zip";
  const map = parseChecksums(body);
  assert.equal(
    map.get("arcis-0.2.0-x86_64-pc-windows-msvc.zip"),
    "1234567890123456789012345678901234567890123456789012345678901234",
  );
});

test("parseChecksums lowercases hex digests for case-insensitive comparison", () => {
  const body =
    "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  arcis-0.2.0-x86_64-unknown-linux-musl.tar.gz";
  const map = parseChecksums(body);
  assert.equal(
    map.get("arcis-0.2.0-x86_64-unknown-linux-musl.tar.gz"),
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  );
});

test("parseChecksums skips malformed lines silently", () => {
  const body = [
    "not-a-valid-checksum-line",
    "tooshort  arcis-foo.tar.gz",
    "abc123def456abc123def456abc123def456abc123def456abc123def456abcd  arcis-good.tar.gz",
  ].join("\n");
  const map = parseChecksums(body);
  assert.equal(map.size, 1);
  assert.equal(
    map.get("arcis-good.tar.gz"),
    "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
  );
});
