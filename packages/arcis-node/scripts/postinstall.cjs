/* eslint-disable */
// Postinstall notice for @arcis/node.
//
// Surface the fact that the Arcis CLI (audit / scan / sca) ships as a
// separate native binary. Without this message, users who installed the
// Node SDK type `arcis` in their shell, get "command not found", and
// assume the package is broken.
//
// Skip in CI / non-TTY / when npm asks us not to log.
if (process.env.CI || process.env.ARCIS_SKIP_NOTICE) return;

const isTTY = process.stdout && process.stdout.isTTY;
const c = (s, code) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);

const lines = [
  '',
  c('  Arcis Node SDK installed.', '1;36'),
  '',
  c('  The CLI (audit / scan / sca) ships separately as a native binary:', '2'),
  c('    npm install -g @arcis/cli', '32'),
  '',
  c('  This package is the SDK / middleware. It does not put a CLI on', '2'),
  c('  your shell PATH. Docs: https://arcis-website.pages.dev/documentation/cli.html', '2'),
  '',
];
for (const line of lines) console.log(line);
