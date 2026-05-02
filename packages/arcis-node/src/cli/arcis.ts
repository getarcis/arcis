#!/usr/bin/env node
/**
 * @arcis/node — `arcis` CLI dispatcher.
 *
 * Surface (mirrors the Python CLI's discovery layer):
 *
 *   arcis              → catalog
 *   arcis --list       → catalog with examples
 *   arcis --help / -h  → catalog + run-cmd hint
 *   arcis --version / -V
 *   arcis update [--apply] [--check]
 *   arcis scan / audit / sca → forward to Python `arcis` if on PATH,
 *                              else print install hint
 *
 * Why we delegate scan/audit/sca to Python rather than re-implementing:
 * the threat database, audit rules, and attack-payload catalog are
 * Python-side data files. Maintaining two copies means drift; one
 * canonical CLI + a thin Node forwarder is simpler. The Node binary
 * exists primarily so users who installed `@arcis/node` from npm get
 * the same `arcis update` / discovery UX as Python users.
 */

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ── ANSI helpers ─────────────────────────────────────────────────────

const USE_COLOR =
  !process.env.NO_COLOR && process.stdout.isTTY === true;

function c(text: string, ...codes: string[]): string {
  if (!USE_COLOR) return text;
  return codes.join("") + text + "\x1b[0m";
}

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const RED = "\x1b[31m";

// ── Version + npm registry helpers ───────────────────────────────────

function getInstalledVersion(): string {
  // Read the package.json that ships with this build so we report the
  // actual installed version, not whatever was hardcoded.
  try {
    const here = fileURLToPath(import.meta.url);
    // Walk up to find the package root (contains package.json).
    let dir = dirname(here);
    for (let i = 0; i < 6; i++) {
      try {
        const raw = readFileSync(resolve(dir, "package.json"), "utf-8");
        const pkg = JSON.parse(raw) as { name?: string; version?: string };
        if (pkg.name === "@arcis/node" && pkg.version) {
          return pkg.version;
        }
      } catch {
        // climb
      }
      const parent = resolve(dir, "..");
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
    // ignore
  }
  return "?";
}

interface NpmRegistryResponse {
  "dist-tags"?: { latest?: string };
}

async function fetchLatestVersion(): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);
    try {
      const resp = await fetch("https://registry.npmjs.org/@arcis/node", {
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!resp.ok) return null;
      const data = (await resp.json()) as NpmRegistryResponse;
      return data["dist-tags"]?.latest ?? null;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  }
}

function parseVersion(v: string): number[] | null {
  const parts = v.split(".");
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    out.push(Number(p));
  }
  return out;
}

function versionCompare(a: number[], b: number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

// ── Python forwarder ─────────────────────────────────────────────────

function hasPythonArcis(): boolean {
  // Check both `arcis` (Windows: arcis.exe) and `python -m arcis.cli` so
  // users who have the Python package installed but not on PATH still work.
  const probes: Array<{ cmd: string; args: string[] }> = [
    { cmd: "arcis", args: ["--version"] },
    { cmd: "python", args: ["-m", "arcis.cli", "--version"] },
    { cmd: "python3", args: ["-m", "arcis.cli", "--version"] },
  ];
  for (const p of probes) {
    try {
      const result = spawnSync(p.cmd, p.args, {
        stdio: ["ignore", "ignore", "ignore"],
        timeout: 3000,
        shell: process.platform === "win32",
      });
      if (result.status === 0) return true;
    } catch {
      // try next
    }
  }
  return false;
}

function forwardToPython(args: string[]): never {
  // Try `arcis` first, fall back to `python -m arcis.cli`. Mirror exit
  // code so CI scripts using the Node CLI get the same behavior they'd
  // get from the Python CLI.
  const candidates: Array<{ cmd: string; args: string[] }> = [
    { cmd: "arcis", args },
    { cmd: "python", args: ["-m", "arcis.cli", ...args] },
    { cmd: "python3", args: ["-m", "arcis.cli", ...args] },
  ];
  for (const cand of candidates) {
    const result = spawnSync(cand.cmd, cand.args, {
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    if (result.error) continue;
    process.exit(result.status ?? 0);
  }
  console.error(
    c("arcis: could not invoke the Python CLI. Install with:", RED, BOLD),
  );
  console.error("  pip install arcis");
  process.exit(127);
}

// ── Catalog ──────────────────────────────────────────────────────────

function printCatalog(verbose: boolean): void {
  const ver = getInstalledVersion();
  console.log();
  console.log(`  ${c("Arcis", BOLD, CYAN)}  ${c(`v${ver}`, DIM)}  ${c("(node)", DIM)}`);
  console.log(c("  Zero-dep security middleware + scanners.", DIM));
  console.log();
  console.log(c("  Commands", BOLD));
  const rows: Array<[string, string, string]> = [
    [
      "scan",
      "Send live attack payloads to a running app.",
      "arcis scan http://localhost:8000 --route POST:/echo --field q",
    ],
    [
      "audit",
      "Static-analyse Python / JS / TS source for unsafe patterns.",
      "arcis audit .",
    ],
    [
      "sca",
      "Match installed dependencies against the supply-chain threat DB.",
      "arcis sca .",
    ],
    ["update", "Check npm for a newer @arcis/node release.", "arcis update --apply"],
  ];
  for (const [name, desc, example] of rows) {
    console.log(`    ${c(name.padEnd(8), BOLD, GREEN)} ${desc}`);
    if (verbose) {
      console.log(`             ${c(example, DIM)}`);
    }
  }
  console.log();
  console.log(c("  Discovery", BOLD));
  console.log(`    ${c("--list", BOLD, CYAN).padEnd(24)} Show this catalog (verbose).`);
  console.log(
    `    ${c("<cmd> --help", BOLD, CYAN).padEnd(24)} Show full flags for that command.`,
  );
  console.log();
  console.log(c("  Note", BOLD));
  console.log(
    `    scan/audit/sca delegate to the Python CLI (canonical impl).`,
  );
  console.log(`    Install once with:  ${c("pip install arcis", GREEN)}`);
  console.log();
}

// ── Update command ───────────────────────────────────────────────────

async function updateCommand(args: string[]): Promise<void> {
  // Note: this function uses `process.exitCode = N; return;` rather than
  // `process.exit(N)` because the fetch() call leaves an internal undici
  // handle open momentarily on Windows, and process.exit() during that
  // window throws a libuv assertion on stderr. exitCode + return lets
  // Node drain handles cleanly before exit.
  const apply = args.includes("--apply");
  const check = args.includes("--check");
  const yes = args.includes("--yes") || args.includes("-y");

  const current = getInstalledVersion();
  const latest = await fetchLatestVersion();

  if (check) {
    if (latest === null) {
      console.error("arcis: could not reach npm to check for updates");
      process.exitCode = 2;
      return;
    }
    const cur = parseVersion(current);
    const lat = parseVersion(latest);
    if (!cur || !lat || versionCompare(cur, lat) >= 0) {
      console.log(`@arcis/node ${current} is up-to-date`);
      process.exitCode = 0;
      return;
    }
    console.error(`@arcis/node ${current} is outdated; latest is ${latest}`);
    process.exitCode = 1;
    return;
  }

  console.log();
  console.log(c("  @arcis/node update check", BOLD, CYAN));
  console.log(c("  Source: https://registry.npmjs.org/@arcis/node", DIM));
  console.log();

  if (latest === null) {
    console.log(`    Installed   @arcis/node ${current}`);
    console.log(
      `    Latest      ${c("? unreachable", YELLOW)}  ${c("(network error or npm down)", DIM)}`,
    );
    console.log();
    console.log(c("  Try again later, or run 'npm view @arcis/node version' directly.", DIM));
    console.log();
    process.exitCode = 2;
    return;
  }

  const cur = parseVersion(current);
  const lat = parseVersion(latest);
  if (!cur || !lat) {
    console.log(
      `    Installed   @arcis/node ${current}  ${c("(pre-release or unparseable)", DIM)}`,
    );
    console.log(`    Latest      @arcis/node ${latest}`);
    console.log();
    console.log(c("  Skipping comparison — manually decide.", DIM));
    console.log();
    process.exitCode = 0;
    return;
  }

  if (versionCompare(cur, lat) >= 0) {
    console.log(`    Installed   @arcis/node ${current}`);
    console.log(`    Latest      @arcis/node ${latest}`);
    console.log();
    console.log(c("  You are on the latest version.", BOLD, GREEN));
    console.log();
    process.exitCode = 0;
    return;
  }

  console.log(`    Installed   @arcis/node ${current}`);
  console.log(
    `    Latest      ${c(`@arcis/node ${latest}`, BOLD)}  ${c("(update available)", YELLOW)}`,
  );
  console.log();
  console.log(c("  Run to upgrade", BOLD));
  console.log(`    ${c("npm install @arcis/node@latest", GREEN)}`);
  console.log();

  if (!apply) {
    console.log(c("  Or rerun: 'arcis update --apply' to upgrade in place.", DIM));
    console.log();
    process.exitCode = 1;
    return;
  }

  if (!yes && process.stdin.isTTY) {
    process.stdout.write("Upgrade now? [y/N] ");
    const response = await new Promise<string>((res) => {
      process.stdin.once("data", (chunk: Buffer) => res(chunk.toString().trim().toLowerCase()));
    });
    if (!response.startsWith("y")) {
      process.exitCode = 1;
      return;
    }
  }

  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  console.log(`  $ ${npmCmd} install @arcis/node@latest`);
  const result = spawnSync(npmCmd, ["install", "@arcis/node@latest"], {
    stdio: "inherit",
  });
  process.exitCode = result.status ?? 1;
}

// ── Main ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printCatalog(false);
    process.exit(0);
  }

  const arg0 = args[0];

  if (arg0 === "--list" || arg0 === "-l") {
    printCatalog(true);
    process.exit(0);
  }

  if (arg0 === "-h" || arg0 === "--help") {
    printCatalog(false);
    console.log(c("  Run 'arcis <command> --help' for full flags.", DIM));
    console.log();
    process.exit(0);
  }

  if (arg0 === "-V" || arg0 === "--version") {
    console.log(getInstalledVersion());
    process.exit(0);
  }

  if (arg0 === "update") {
    await updateCommand(args.slice(1));
    return;
  }

  if (arg0 === "scan" || arg0 === "audit" || arg0 === "sca") {
    if (!hasPythonArcis()) {
      console.error(
        c(
          `arcis: '${arg0}' is implemented by the Python CLI. Install with:`,
          YELLOW,
          BOLD,
        ),
      );
      console.error("  pip install arcis");
      console.error();
      console.error(c("Why: scan/audit/sca rely on Python's threat-DB and rule data.", DIM));
      console.error(
        c(
          "@arcis/node implements the middleware + dashboard upload — see the docs.",
          DIM,
        ),
      );
      process.exit(127);
    }
    forwardToPython(args);
    return;
  }

  console.error(`arcis: unknown command '${arg0}'`);
  console.error("Run 'arcis --list' for available commands.");
  process.exit(1);
}

main().catch((err) => {
  console.error(c(`arcis: unexpected error: ${err}`, RED));
  process.exit(1);
});
