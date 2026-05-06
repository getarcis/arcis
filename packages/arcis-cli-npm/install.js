#!/usr/bin/env node
// Postinstall script for `@arcis/cli`.
//
// Downloads the native Arcis binary matching the host platform/arch
// from the GitHub Release pinned to this package version, verifies the
// SHA-256 checksum against the release's SHA256SUMS file, extracts the
// binary, and writes it to bin/ so the npm `bin` symlink works.
//
// Plain stdlib: no transitive deps. Runs at install time, before any
// optional dependencies are available, so we cannot rely on third-party
// packages here. Same pattern Claude Code, esbuild, and swc use.

"use strict";

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { pipeline } = require("node:stream/promises");
const { spawnSync } = require("node:child_process");

const {
  detectTarget,
  supportedPlatforms,
  archiveUrl,
  checksumsUrl,
  parseChecksums,
} = require("./lib/targets");

const MAX_REDIRECTS = 5;

function log(msg) {
  // Indent matches npm postinstall convention.
  process.stderr.write(`arcis-cli: ${msg}\n`);
}

function fail(msg, exitCode = 1) {
  process.stderr.write(`arcis-cli: ${msg}\n`);
  process.exit(exitCode);
}

/** Read the package version so the URL pin matches what npm thinks it
 * just installed. Doing this at install time means a single source of
 * truth — bumping `version` in package.json automatically retargets
 * the GitHub Release. */
function packageVersion() {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(__dirname, "package.json"), "utf8"),
  );
  return pkg.version;
}

/** Stream-download a URL with redirect-following + timeout. Returns a
 * Promise<Buffer>. Bails after MAX_REDIRECTS to avoid loops. */
function fetchToBuffer(url, redirects = 0) {
  if (redirects > MAX_REDIRECTS) {
    return Promise.reject(new Error(`too many redirects fetching ${url}`));
  }
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { headers: { "User-Agent": "@arcis/cli installer" }, timeout: 60_000 },
      (res) => {
        // 3xx redirects: location header, recurse.
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          // Some redirect targets are relative — resolve via URL ctor.
          const next = new URL(res.headers.location, url).toString();
          res.resume();
          fetchToBuffer(next, redirects + 1).then(resolve, reject);
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(
            new Error(`HTTP ${res.statusCode} fetching ${url}`),
          );
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error(`timeout fetching ${url}`));
    });
    req.on("error", reject);
  });
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/** Extract a tarball entry named `wantedName` from a .tar.gz buffer.
 * Returns the binary bytes. Plain stdlib `zlib` + a minimal tar parser
 * (USTAR header, 512-byte blocks). Supports normal-file entries and
 * GNU `LongName` extension headers, which is enough for our archives.
 */
function extractTarGz(gzipBuf, wantedName) {
  const tar = zlib.gunzipSync(gzipBuf);
  let offset = 0;
  let pendingLongName = null;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    // All-zero block marks end-of-archive.
    let allZero = true;
    for (const b of header) {
      if (b !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) break;

    const rawName = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const sizeStr = header.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim();
    const size = parseInt(sizeStr || "0", 8);
    const typeflag = String.fromCharCode(header[156]);
    const blocks = Math.ceil(size / 512);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;

    let name = pendingLongName || rawName;
    pendingLongName = null;

    if (typeflag === "L") {
      // GNU long-name extension: next entry uses this name.
      pendingLongName = tar
        .subarray(dataStart, dataEnd)
        .toString("utf8")
        .replace(/\0.*$/, "");
    } else if (typeflag === "0" || typeflag === "" || typeflag === "\0") {
      // Normal file. Match against basename so directory prefix doesn't matter.
      if (path.basename(name) === wantedName) {
        return tar.subarray(dataStart, dataEnd);
      }
    }

    offset = dataStart + blocks * 512;
  }
  throw new Error(`tar archive missing entry: ${wantedName}`);
}

/** Extract the binary from a .zip archive. Uses system `unzip` on
 * Unix-y hosts and PowerShell `Expand-Archive` on Windows so we don't
 * need a JS zip dep. */
async function extractZip(zipBuf, wantedName, scratchDir) {
  const zipPath = path.join(scratchDir, "archive.zip");
  await fsp.writeFile(zipPath, zipBuf);
  if (process.platform === "win32") {
    // PowerShell Expand-Archive is preinstalled on every supported
    // Windows host. -Force overwrites a previous extraction attempt.
    const result = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `Expand-Archive -Path '${zipPath}' -DestinationPath '${scratchDir}' -Force`,
      ],
      { stdio: "inherit" },
    );
    if (result.status !== 0) {
      throw new Error("PowerShell Expand-Archive failed");
    }
  } else {
    const result = spawnSync("unzip", ["-o", "-q", zipPath, "-d", scratchDir], {
      stdio: "inherit",
    });
    if (result.status !== 0) {
      throw new Error("unzip failed (install `unzip` and retry, or open an issue)");
    }
  }
  // Walk scratchDir for the binary (matches behavior of tar extraction).
  const found = await findFile(scratchDir, wantedName);
  if (!found) {
    throw new Error(`zip archive missing entry: ${wantedName}`);
  }
  return fsp.readFile(found);
}

async function findFile(rootDir, basename) {
  const stack = [rootDir];
  while (stack.length) {
    const cur = stack.pop();
    const entries = await fsp.readdir(cur, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.isFile() && e.name === basename) return full;
    }
  }
  return null;
}

async function main() {
  // Some users install with --ignore-scripts (correctly defensive). Tell
  // them what's missing and how to recover instead of failing silently.
  if (process.env.ARCIS_CLI_SKIP_INSTALL === "1") {
    log("ARCIS_CLI_SKIP_INSTALL=1 set; skipping binary download.");
    return;
  }

  const platform = process.platform;
  const arch = process.arch;
  const desc = detectTarget(platform, arch);
  if (!desc) {
    fail(
      `unsupported host: ${platform}/${arch}.\n` +
        `  Supported: ${supportedPlatforms().join(", ")}.\n` +
        `  Open an issue at https://github.com/Gagancm/arcis/issues if you need this combination.`,
    );
    return;
  }

  const version = packageVersion();
  const url = archiveUrl({ version, target: desc.target, archive: desc.archive });
  const sumsUrl = checksumsUrl(version);
  log(`platform: ${platform}/${arch} -> ${desc.target}`);
  log(`fetching ${url}`);

  let archiveBuf;
  try {
    archiveBuf = await fetchToBuffer(url);
  } catch (err) {
    fail(
      `download failed: ${err.message}\n` +
        `  Verify a release exists at https://github.com/Gagancm/arcis/releases/tag/cli-v${version}\n` +
        `  Or set ARCIS_CLI_SKIP_INSTALL=1 to defer the download (you'll need to install the binary manually).`,
    );
    return;
  }

  log(`fetching ${sumsUrl}`);
  let sumsBuf;
  try {
    sumsBuf = await fetchToBuffer(sumsUrl);
  } catch (err) {
    fail(`checksum download failed: ${err.message}`);
    return;
  }
  const checksums = parseChecksums(sumsBuf.toString("utf8"));
  const archiveName = url.split("/").pop();
  const expected = checksums.get(archiveName);
  if (!expected) {
    fail(
      `SHA256SUMS does not list ${archiveName}.\n` +
        `  Release may be incomplete; please open an issue.`,
    );
    return;
  }
  const actual = sha256Hex(archiveBuf);
  if (actual !== expected) {
    fail(
      `SHA-256 mismatch for ${archiveName}:\n` +
        `  expected: ${expected}\n` +
        `  actual:   ${actual}\n` +
        `  This is a serious problem. Do not run the binary. Open an issue.`,
    );
    return;
  }
  log(`sha-256 ok (${actual.slice(0, 12)}...)`);

  // Extract the binary. The archive contains a single dir named
  // `arcis-<version>-<target>/` with the binary inside.
  const scratch = await fsp.mkdtemp(path.join(os.tmpdir(), "arcis-cli-"));
  let binaryBuf;
  try {
    if (desc.archive === "tar.gz") {
      binaryBuf = extractTarGz(archiveBuf, desc.binary);
    } else {
      binaryBuf = await extractZip(archiveBuf, desc.binary, scratch);
    }
  } catch (err) {
    fail(`archive extraction failed: ${err.message}`);
    return;
  } finally {
    await fsp.rm(scratch, { recursive: true, force: true }).catch(() => {});
  }

  // Place the binary alongside the Node shim. `bin/arcis` is the shim
  // npm puts on PATH; it `spawnSync`s the native binary saved here as
  // `bin/arcis-bin` (or `arcis-bin.exe` on Windows).
  const binDir = path.join(__dirname, "bin");
  await fsp.mkdir(binDir, { recursive: true });
  const binaryName =
    process.platform === "win32" ? "arcis-bin.exe" : "arcis-bin";
  const binaryPath = path.join(binDir, binaryName);
  await fsp.writeFile(binaryPath, binaryBuf);
  if (process.platform !== "win32") {
    await fsp.chmod(binaryPath, 0o755);
  }
  log(`installed binary -> ${binaryPath}`);
}

main().catch((err) => {
  fail(`unexpected error: ${err && err.stack ? err.stack : err}`);
});
