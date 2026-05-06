/* eslint-disable */
// Postinstall notice for @arcis/node.
//
// Surface the fact that the Arcis CLI (audit / scan / sca) ships in the
// Python package only. Without this message, users who installed the Node
// SDK type `arcis` in their shell, get "command not found", and assume
// the package is broken.
//
// Skip in CI / non-TTY / when npm asks us not to log.
if (process.env.CI || process.env.ARCIS_SKIP_NOTICE) return;

const isTTY = process.stdout && process.stdout.isTTY;
const c = (s, code) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);

const lines = [
  '',
  c('  Arcis Node SDK installed.', '1;36'),
  '',
  c('  The CLI (audit / scan / sca) ships separately in Python:', '2'),
  c('    pip install arcis', '32'),
  '',
  c('  This package is the SDK / middleware. It does not put a CLI on', '2'),
  c('  your shell PATH. Docs: https://gagancm.github.io/arcis/documentation/cli.html', '2'),
  '',
];
for (const line of lines) console.log(line);
