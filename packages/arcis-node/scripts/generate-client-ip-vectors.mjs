#!/usr/bin/env node
/**
 * Generates spec/client-ip-vectors.json: shared client-IP resolution and
 * rate-limit key fixtures for every Arcis SDK.
 *
 * Ground truth:
 *   - Proxy trust walk: Express's own resolver (proxy-addr), the same code
 *     behind `app.set('trust proxy', ...)`. The Arcis default trust set equals
 *     Express's 'loopback, linklocal, uniquelocal'.
 *   - Arcis rules on top (documented in spec/API_SPEC.md "Client IP
 *     resolution"): a port on a forwarded entry is stripped; if the selected
 *     entry is still not an IP, the nearest valid hop to its right is used;
 *     IPv4-mapped IPv6 and zone identifiers are normalized.
 *   - Rate-limit keys: express-rate-limit's ipKeyGenerator (IPv6 grouped by
 *     subnet, /56 by default).
 *
 * Usage: node scripts/generate-client-ip-vectors.mjs
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import proxyaddr from 'proxy-addr';
import { ipKeyGenerator } from 'express-rate-limit';

const here = dirname(fileURLToPath(import.meta.url));
const versionOf = (name) =>
  JSON.parse(readFileSync(resolve(here, '../node_modules', name, 'package.json'), 'utf-8')).version;

const DEFAULT_TRUST = ['loopback', 'linklocal', 'uniquelocal'];

/** Strip a port: "1.2.3.4:80" and "[2001:db8::1]:443". Leaves other text alone. */
function stripPort(value) {
  const v = value.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
  if (bracketed) return bracketed[1];
  const v4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(v);
  if (v4WithPort) return v4WithPort[1];
  return v;
}

/** Normalize a valid address: drop an IPv6 zone, unwrap IPv4-mapped IPv6. */
function normalize(address) {
  let a = address.trim();
  const zone = a.indexOf('%');
  if (zone !== -1 && a.includes(':')) a = a.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(a);
  if (mapped) a = mapped[1];
  return isIP(a) ? a.toLowerCase() : null;
}

function resolveClientIp(peer, xff, trust) {
  const headers = xff === undefined ? {} : { 'x-forwarded-for': xff };
  const req = { connection: { remoteAddress: peer }, socket: { remoteAddress: peer }, headers };
  const compiled = proxyaddr.compile(trust);
  // Normalize the chain first so ports do not defeat the trust check.
  const chain = proxyaddr.all(req).map((entry, index) => (index === 0 ? entry : stripPort(entry)));
  let selected = chain.length - 1;
  for (let i = 0; i < chain.length - 1; i++) {
    const address = normalize(chain[i]);
    if (address === null || !compiled(address, i)) {
      selected = i;
      break;
    }
  }
  // Fall back toward the peer until a valid address is found.
  for (let i = selected; i >= 0; i--) {
    const address = normalize(chain[i]);
    if (address !== null) return address;
  }
  return null;
}

const PEERS = [
  '203.0.113.5', '2001:db8:ffff::5', '100.64.0.1',
  '127.0.0.1', '::1', '::ffff:127.0.0.1', '10.0.0.2', '172.16.0.9', '192.168.1.1',
  '169.254.1.1', 'fe80::1%eth0', 'fd00::1',
];
const FORWARDED = [
  undefined,
  '198.51.100.7',
  '198.51.100.7, 10.0.0.3',
  '1.1.1.1, 198.51.100.7',
  'evil-spoof, 198.51.100.7',
  'garbage',
  '198.51.100.7:1234',
  '[2001:db8:1234:5678::9]:443',
  '  198.51.100.7  ,  10.0.0.3  ',
  '10.0.0.3, 192.168.0.4',
  '2001:db8:1234:56ff:ffff::9',
  '::ffff:198.51.100.7',
  '',
];
const TRUSTS = [
  ['default', DEFAULT_TRUST],
  ['none', []],
  ['explicit_public_proxy', ['203.0.113.0/24']],
  ['explicit_private_and_public', ['10.0.0.0/8', '203.0.113.0/24']],
];

const cases = [];
for (const [trustName, trust] of TRUSTS) {
  for (const peer of PEERS) {
    for (const xff of FORWARDED) {
      const clientIp = resolveClientIp(peer, xff, trust);
      cases.push({
        id: `${trustName}|${peer}|${xff === undefined ? '-' : xff}`,
        trusted_proxies: trustName === 'default' ? null : trust,
        peer,
        x_forwarded_for: xff ?? null,
        expected_client_ip: clientIp,
        expected_key: clientIp === null ? null : ipKeyGenerator(clientIp),
      });
    }
  }
}

const KEY_INPUTS = [
  '1.2.3.4', '::ffff:1.2.3.4', '::1', '2001:db8:1234:5600::1', '2001:db8:1234:56ff:ffff::9',
  'fe80::1', '2001:db8::', '2001:0db8:0000:0000:0000:0000:0000:0001',
];
const SUBNETS = [56, 64, 48, 128, false];
const keyCases = KEY_INPUTS.flatMap((ip) =>
  SUBNETS.map((subnet) => ({ ip, ipv6_subnet: subnet, expected_key: ipKeyGenerator(ip, subnet) })),
);

const vectors = {
  version: '1.0',
  description:
    'Client IP resolution and rate-limit key fixtures. trusted_proxies null means the default trust set (loopback, link-local, unique local: 127.0.0.0/8, ::1, 169.254.0.0/16, fe80::/10, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7). Expected values come from Express proxy-addr plus the Arcis rules in spec/API_SPEC.md, and keys from express-rate-limit ipKeyGenerator. Regenerate with packages/arcis-node/scripts/generate-client-ip-vectors.mjs.',
  reference: { 'proxy-addr': versionOf('proxy-addr'), 'express-rate-limit': versionOf('express-rate-limit') },
  default_trusted_proxies: [
    '127.0.0.0/8', '::1/128', '169.254.0.0/16', 'fe80::/10', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7',
  ],
  resolution: cases,
  keys: keyCases,
};

const target = resolve(here, '../../../spec/client-ip-vectors.json');
writeFileSync(target, JSON.stringify(vectors, null, 2) + '\n');
console.log(`wrote ${cases.length} resolution cases and ${keyCases.length} key cases to ${target}`);
