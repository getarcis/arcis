/**
 * Smoke tests for the @arcis/node CLI dispatcher (`arcis` binary).
 *
 * Each test invokes the built CLI as a subprocess, asserts the exit
 * code, and spot-checks stdout. Mirrors the Python dispatcher tests
 * (`tests/cli/test_dispatcher.py`).
 *
 * The binary is built by `npm run build`; these tests assume the build
 * artifact at `dist/cli/arcis.mjs` exists. CI runs `npm run build`
 * before the test step.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "..", "..", "dist", "cli", "arcis.mjs");

function runCli(
  args: string[],
  opts: { env?: Record<string, string> } = {},
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync("node", [CLI_PATH, ...args], {
    encoding: "utf-8",
    env: {
      // Strip color so our string assertions don't have to deal with ANSI.
      NO_COLOR: "1",
      // Inherit PATH so the CLI can probe for `python` / `arcis` if a
      // delegating test runs.
      PATH: process.env.PATH,
      ...opts.env,
    },
    timeout: 15_000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  };
}

describe("arcis (Node CLI dispatcher)", () => {
  beforeAll(() => {
    if (!existsSync(CLI_PATH)) {
      throw new Error(
        `Built CLI not found at ${CLI_PATH}. Run 'npm run build' first.`,
      );
    }
  });

  it("no args prints catalog (exit 0)", () => {
    const { stdout, status } = runCli([]);
    expect(status).toBe(0);
    expect(stdout).toContain("Arcis");
    expect(stdout).toContain("scan");
    expect(stdout).toContain("audit");
    expect(stdout).toContain("sca");
    expect(stdout).toContain("update");
  });

  it("--list prints verbose catalog with examples", () => {
    const { stdout, status } = runCli(["--list"]);
    expect(status).toBe(0);
    // Verbose mode includes example commands under each row.
    expect(stdout).toContain("arcis scan http");
    expect(stdout).toContain("arcis audit");
  });

  it("--help prints catalog + run-cmd hint", () => {
    const { stdout, status } = runCli(["--help"]);
    expect(status).toBe(0);
    expect(stdout).toContain("Run 'arcis <command> --help'");
  });

  it("--version prints semver string", () => {
    const { stdout, status } = runCli(["--version"]);
    expect(status).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("-V short flag prints version", () => {
    const { stdout, status } = runCli(["-V"]);
    expect(status).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("unknown command exits 1 with helpful message", () => {
    const { stderr, status } = runCli(["nope"]);
    expect(status).toBe(1);
    expect(stderr).toContain("unknown command");
    expect(stderr).toContain("--list");
  });

  it("scan/audit/sca either delegate to Python or exit 127", () => {
    // Hard to assert a specific outcome here without controlling whether
    // the test environment has Python's `arcis` on PATH. What we CAN
    // assert: the dispatcher recognized the command (didn't print
    // "unknown command") and either delegated successfully or exited
    // 127 with the install hint. Both are correct behaviors.
    const result = runCli(["audit", "--help"]);
    if (result.status === 127) {
      expect(result.stderr).toContain("pip install arcis");
    } else {
      // Python CLI was found; argparse should have printed help.
      expect((result.stdout + result.stderr).toLowerCase()).not.toContain(
        "unknown command",
      );
    }
  });
});
