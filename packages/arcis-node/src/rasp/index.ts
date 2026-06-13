/**
 * @module @arcis/node/rasp
 * EXPERIMENTAL runtime application self-protection (RASP) spike — Day 3.
 *
 * The capability gap vs Aikido Zen: instead of guessing at the perimeter with
 * regex, RASP confirms an attack AT THE SINK. It tracks request-derived
 * ("tainted") input through the request via AsyncLocalStorage, instruments a
 * dangerous sink (child_process), and flags only when tainted input that
 * carries shell metacharacters actually reaches `exec`. That means it catches
 * obfuscated payloads a regex misses AND fires far fewer false positives,
 * because pure-data input (no metacharacters) reaching a sink is allowed.
 *
 * Opt-in and OFF by default: nothing here runs unless `enableRasp()` is called,
 * and the taint context is only populated when `raspMiddleware()` is mounted.
 * Behind a flag, as the plan requires. This is a spike, not a shipped pillar —
 * see documents/rasp-go-no-go.md.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import childProcess from 'node:child_process';
import type { Request, Response, NextFunction, RequestHandler } from 'express';

interface RaspContext {
  /** Distinct request-derived string values, the taint set for this request. */
  tainted: Set<string>;
}

const als = new AsyncLocalStorage<RaspContext>();

/**
 * Shell metacharacters that let user input change a command's STRUCTURE rather
 * than appear as a single argument. Tainted input containing any of these,
 * reaching a shell sink, is a command-injection attempt. Plain data (a
 * filename, a name) never carries these, so it is allowed through — the low-FP
 * property that distinguishes RASP from perimeter pattern-matching.
 */
const SHELL_METACHARACTERS = /[;&|`$(){}<>\n]|\$\(|&&|\|\|/;

/** A confirmed tainted-input-reaching-sink event. */
export interface RaspFinding {
  /** The instrumented sink, e.g. "child_process.exec". */
  sink: string;
  /** The tainted request value that reached the sink. */
  tainted: string;
  /** The full command/argument passed to the sink (truncated for logs). */
  command: string;
}

export class RaspViolation extends Error {
  constructor(public readonly finding: RaspFinding) {
    super(`RASP: tainted input reached ${finding.sink}`);
    this.name = 'RaspViolation';
  }
}

/**
 * Pure core: does any tainted value appear in `command` AND carry shell
 * metacharacters? Returns the finding or null. Exported for testing — this is
 * the load-bearing logic; the monkey-patch below just wires it to the sink.
 */
export function detectTaintedSink(
  command: string,
  tainted: Iterable<string>,
  sink = 'child_process.exec',
): RaspFinding | null {
  for (const value of tainted) {
    // Ignore trivially-short values: a 1-char input matching is noise, and a
    // bare metacharacter alone is not "user data flowing into a sink".
    if (value.length < 3) continue;
    if (command.includes(value) && SHELL_METACHARACTERS.test(value)) {
      return { sink, tainted: value, command: command.slice(0, 500) };
    }
  }
  return null;
}

/** Recursively collect string values from a request part into the taint set. */
function collectTainted(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 6 || value == null) return;
  if (typeof value === 'string') {
    if (value.length >= 3) out.add(value);
    return;
  }
  if (typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      collectTainted(v, out, depth + 1);
    }
  }
}

/**
 * Express middleware that builds the per-request taint set (from body / query /
 * params) and runs the rest of the request inside the AsyncLocalStorage scope,
 * so an instrumented sink can see which inputs are request-derived.
 */
export function raspMiddleware(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const tainted = new Set<string>();
    collectTainted(req.body, tainted);
    collectTainted(req.query, tainted);
    collectTainted(req.params, tainted);
    als.run({ tainted }, () => next());
  };
}

interface RaspOptions {
  /** Throw RaspViolation on a finding (default). false = observe-only. */
  block?: boolean;
  /** Called on every finding, regardless of block mode. */
  onViolation?: (finding: RaspFinding) => void;
}

let installed = false;
let blockMode = true;
let onViolation: (finding: RaspFinding) => void = () => {};
let originalExec: typeof childProcess.exec | null = null;
let originalExecSync: typeof childProcess.execSync | null = null;

function guard(command: unknown, sink: string): void {
  if (typeof command !== 'string') return;
  const ctx = als.getStore();
  if (!ctx) return; // no request context (not behind the middleware) -> no taint data
  const finding = detectTaintedSink(command, ctx.tainted, sink);
  if (!finding) return;
  try {
    onViolation(finding);
  } catch {
    // a buggy observer must not break the guard
  }
  if (blockMode) throw new RaspViolation(finding);
}

/**
 * Install the sink instrumentation. Idempotent, opt-in, process-global (it
 * mutates the shared child_process module — the monkey-patch fragility the
 * go/no-go writeup weighs). Call once at startup; pair with `raspMiddleware()`.
 */
export function enableRasp(options: RaspOptions = {}): void {
  if (installed) return;
  installed = true;
  blockMode = options.block ?? true;
  onViolation = options.onViolation ?? (() => {});

  originalExec = childProcess.exec;
  originalExecSync = childProcess.execSync;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (childProcess as any).exec = function patchedExec(command: unknown, ...rest: unknown[]) {
    guard(command, 'child_process.exec');
    return (originalExec as (...a: unknown[]) => unknown).call(childProcess, command, ...rest);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (childProcess as any).execSync = function patchedExecSync(command: unknown, ...rest: unknown[]) {
    guard(command, 'child_process.execSync');
    return (originalExecSync as (...a: unknown[]) => unknown).call(childProcess, command, ...rest);
  };
}

/** Restore the original sinks. Idempotent. Primarily for tests / teardown. */
export function disableRasp(): void {
  if (!installed) return;
  if (originalExec) (childProcess as { exec: unknown }).exec = originalExec;
  if (originalExecSync) (childProcess as { execSync: unknown }).execSync = originalExecSync;
  installed = false;
  originalExec = null;
  originalExecSync = null;
}

/** Run a function inside a taint scope. Test helper / non-Express integration. */
export function withTaintScope<T>(taintedValues: Iterable<string>, fn: () => T): T {
  return als.run({ tainted: new Set(taintedValues) }, fn);
}
