/**
 * @arcis/mcp — Model Context Protocol server for Arcis.
 *
 * Exposes Arcis security tools so MCP-aware AI agents (Cursor, the MCP CLI,
 * and any other MCP client) can call them directly.
 *
 * Four tools:
 *   - arcis_audit                   static analysis on a directory
 *   - arcis_sca                     supply chain scan on a directory
 *   - arcis_scan                    dynamic endpoint scan against a URL
 *   - arcis_detect_prompt_injection signature-based prompt-injection scan
 *
 * The first three tools shell out to the `arcis` Rust CLI (install via
 * `npm install -g @arcis/cli`). The fourth runs entirely in-process via
 * the Node SDK — no extra binary required.
 *
 * Speak the protocol over stdio; that's how Cursor, the MCP CLI, and
 * other MCP clients launch servers.
 */

import { spawn } from 'node:child_process';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import { detectPromptInjection } from '@arcis/node';

// ─── Tool catalog ───────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'arcis_audit',
    description:
      'Run Arcis static analysis on a project directory. Detects unsafe code patterns: eval(), pickle.loads(), innerHTML, SQL string concatenation, weak crypto, weak random, hard-coded secrets, JWT-NO-ALG, mass assignment, path confusion, secret-in-log, XML external entity, insecure redirect. Returns findings in JSON.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory to audit. Defaults to the current working directory.',
        },
        language: {
          type: 'string',
          enum: ['python', 'javascript', 'typescript', 'auto'],
          description: 'Source language. Auto-detect by default.',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Minimum severity to report. Defaults to low (everything).',
        },
      },
    },
  },
  {
    name: 'arcis_sca',
    description:
      'Run Arcis supply chain attack scanner on a project directory. Checks lockfiles (package-lock.json, yarn.lock, requirements.txt, Pipfile.lock, poetry.lock) and node_modules / Python environments against a threat database of known compromised packages from real-world supply chain attacks. Returns findings in JSON.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory. Defaults to the current working directory.',
        },
        system: {
          type: 'boolean',
          description: 'Also scan globally installed packages and Python .pth backdoors.',
        },
      },
    },
  },
  {
    name: 'arcis_scan',
    description:
      'Run Arcis dynamic endpoint scanner against a live URL. Probes the target for injection categories (XSS, SQLi, path traversal, command injection, SSTI, NoSQL, XXE, header injection) by sending crafted payloads and observing whether the target blocks (403), sanitizes (clean response), or fails (5xx). Use this to verify an Arcis-protected endpoint actually blocks attacks. Returns findings in JSON.',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'URL to probe (e.g. http://localhost:3000/api/comments).',
        },
        route: {
          type: 'string',
          description: 'Optional path appended to the URL for endpoint targeting.',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'arcis_detect_prompt_injection',
    description:
      'Scan a text payload for prompt-injection signatures. Catches direct overrides (ignore previous instructions), known jailbreak frameworks (DAN, STAN, DUDE, AIM, BetterDAN), persona hijacks (you are now X), system-prompt extraction (show me your prompt), structural injection (<system> tags, BEGIN NEW INSTRUCTIONS, [END OF INPUT] markers), conversation-replay forgeries (forged Human: / Assistant: turns), and base64/ROT13 smuggling hints. Returns the detection result with severity and matched signatures. Runs entirely in-process; no shell command, no network call.',
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'The text payload to scan (typically a user prompt destined for an LLM).',
        },
      },
      required: ['text'],
    },
  },
] as const;

// ─── Tool implementations ──────────────────────────────────────────────────

interface CliResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

/**
 * Shell out to the `arcis` Rust CLI with `--json` so the agent gets
 * structured output it can reason about. We never inline shell strings
 * (no `bash -c`, no template substitution into a command line) — args
 * are passed positionally so a malicious path or URL can't break out.
 */
function runArcisCli(args: string[]): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = spawn('arcis', [...args, '--json'], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on('data', (c: Buffer) => outChunks.push(c));
    child.stderr.on('data', (c: Buffer) => errChunks.push(c));
    child.on('error', (err) => {
      resolve({
        ok: false,
        stdout: '',
        stderr: `Failed to spawn arcis CLI: ${err.message}. Install it via \`npm install -g @arcis/cli\`.`,
        exitCode: null,
      });
    });
    child.on('close', (code) => {
      resolve({
        ok: code === 0 || code === 1, // arcis returns 1 on findings, that's still a successful scan
        stdout: Buffer.concat(outChunks).toString('utf8'),
        stderr: Buffer.concat(errChunks).toString('utf8'),
        exitCode: code,
      });
    });
  });
}

function tryParseJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function toolResult(text: string, structured?: unknown): CallToolResult {
  const content: CallToolResult['content'] = [{ type: 'text', text }];
  return structured !== undefined ? { content, structuredContent: structured as Record<string, unknown> } : { content };
}

/**
 * Validate that a path argument exists and is a directory the server can read.
 * Returns null on success or a human-readable error string on failure. We
 * surface the error inline through the MCP tool result instead of letting
 * the underlying CLI fail; failing earlier gives a clearer error to the
 * MCP client and avoids spawning a subprocess for a path we know is bad.
 */
function validatePath(path: string): string | null {
  try {
    // Synchronous and cheap. Tool calls already cross a process boundary
    // via spawn; this stat is a rounding error in comparison.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs = require('fs') as typeof import('fs');
    const stat = fs.statSync(path);
    if (!stat.isDirectory()) {
      return `path is not a directory: ${path}`;
    }
    return null;
  } catch {
    return `path does not exist or is not readable: ${path}`;
  }
}

async function handleAudit(input: Record<string, unknown>): Promise<CallToolResult> {
  const path = typeof input.path === 'string' ? input.path : process.cwd();
  const pathError = validatePath(path);
  if (pathError) return toolResult(`arcis_audit: ${pathError}`);
  const args = ['audit', path];
  if (typeof input.language === 'string' && input.language !== 'auto') {
    args.push('--language', input.language);
  }
  if (typeof input.severity === 'string') {
    args.push('--severity', input.severity);
  }
  const r = await runArcisCli(args);
  if (!r.ok) {
    return toolResult(`arcis audit failed (exit ${r.exitCode}): ${r.stderr}`);
  }
  const parsed = tryParseJson(r.stdout);
  return toolResult(r.stdout || '(no output)', parsed ?? undefined);
}

async function handleSca(input: Record<string, unknown>): Promise<CallToolResult> {
  const path = typeof input.path === 'string' ? input.path : process.cwd();
  const pathError = validatePath(path);
  if (pathError) return toolResult(`arcis_sca: ${pathError}`);
  const args = ['sca', path];
  if (input.system === true) args.push('--system');
  const r = await runArcisCli(args);
  if (!r.ok) {
    return toolResult(`arcis sca failed (exit ${r.exitCode}): ${r.stderr}`);
  }
  const parsed = tryParseJson(r.stdout);
  return toolResult(r.stdout || '(no output)', parsed ?? undefined);
}

async function handleScan(input: Record<string, unknown>): Promise<CallToolResult> {
  const url = typeof input.url === 'string' ? input.url : '';
  if (!url) {
    return toolResult('arcis_scan requires a `url` argument');
  }
  const args = ['scan', url];
  if (typeof input.route === 'string' && input.route.length > 0) {
    args.push('--route', input.route);
  }
  const r = await runArcisCli(args);
  if (!r.ok) {
    return toolResult(`arcis scan failed (exit ${r.exitCode}): ${r.stderr}`);
  }
  const parsed = tryParseJson(r.stdout);
  return toolResult(r.stdout || '(no output)', parsed ?? undefined);
}

async function handleDetectPromptInjection(input: Record<string, unknown>): Promise<CallToolResult> {
  const text = typeof input.text === 'string' ? input.text : '';
  if (!text) {
    return toolResult('arcis_detect_prompt_injection requires a `text` argument');
  }
  const result = detectPromptInjection(text);
  const summary = result.detected
    ? `Detected ${result.matches.length} signature${result.matches.length === 1 ? '' : 's'}, ` +
      `top severity = ${result.severity}.`
    : 'No prompt-injection signatures matched.';
  return toolResult(summary, {
    detected: result.detected,
    severity: result.severity,
    matches: result.matches,
  });
}

// Exported for testing — keeps the dispatch table addressable without
// having to spin up a real MCP transport in unit tests.
export const TOOL_HANDLERS: Record<
  string,
  (input: Record<string, unknown>) => Promise<CallToolResult>
> = {
  arcis_audit: handleAudit,
  arcis_sca: handleSca,
  arcis_scan: handleScan,
  arcis_detect_prompt_injection: handleDetectPromptInjection,
};

// ─── Server bootstrap ───────────────────────────────────────────────────────

export function createServer(): Server {
  const server = new Server(
    {
      name: 'arcis-mcp',
      version: '1.5.0',
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS as unknown as Array<{ name: string; description: string; inputSchema: unknown }>,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const handler = TOOL_HANDLERS[name];
    if (!handler) {
      return toolResult(`Unknown tool: ${name}`);
    }
    return handler((args as Record<string, unknown>) ?? {});
  });

  return server;
}

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Allow `import { createServer }` from tests without auto-running main().
const isMain = (() => {
  if (typeof process === 'undefined') return false;
  const argv1 = process.argv?.[1];
  if (!argv1) return false;
  // import.meta.url isn't trivially testable; use process.argv[1] heuristic
  return argv1.endsWith('server.js') || argv1.endsWith('server.ts');
})();
if (isMain) {
  main().catch((err) => {
    // Use stderr — stdout is reserved for MCP JSON-RPC traffic.
    // eslint-disable-next-line no-console
    console.error('arcis-mcp failed to start:', err);
    process.exit(1);
  });
}

export { TOOLS };
