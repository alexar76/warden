#!/usr/bin/env node
// Deterministic synthetic keys, real detector, cumulative observations across ordinary files.
// This measures a bounded corpus, never proves the absence of false positives.
// npm run build && node scripts/redteam/fragment-collisions.mjs OUT.json DIR [...]
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, extname } from 'node:path';
import { checkFragments, fragmentFingerprints, secretValues } from '../../dist/flow-guard.js';
const [output, ...roots] = process.argv.slice(2);
if (!output || !roots.length) throw new Error('Expected OUT.json DIR [...]');
let seed = 0;
const pick = (alphabet, n) => {
  let out = '';
  while (out.length < n) for (const b of createHash('sha256').update(`fragment collisions ${seed++}`).digest()) out += alphabet[b % alphabet.length];
  return out.slice(0, n);
};
const b62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const formats = {
  stripe: () => ['rk', 'live', pick(b62, 40)].join('_'),
  github: () => ['ghp', pick(b62, 36)].join('_'),
  aws: () => 'AKIA' + pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 16) + ' ' + pick(b62 + '+/', 40),
  anthropic: () => ['sk', 'ant', 'api03', pick(b62 + '_-', 93)].join('-'),
  hex: () => pick('0123456789abcdef', 64),
  base64: () => pick(b62 + '+/', 43) + '=',
  jwt: () => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + pick(b62, 120) + '.' + pick(b62 + '_-', 43),
  pem: () => 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ' + pick(b62 + '+/', 384),
};
const states = [];
let current;
for (const make of Object.values(formats)) for (let i = 0; i < 60; i++) {
  const records = fragmentFingerprints(secretValues(make(), true));
  if (!current || current.fragments.index.length + records.length > 16_384) {
    current = { v: 1, untrusted: [], private: [], full: false, notified: false, fragments: { v: 2, index: [], seen: [] } };
    states.push(current);
  }
  current.fragments.index.push(...records);
}
const allowed = new Set(['.md', '.txt', '.ts', '.tsx', '.js', '.mjs', '.py', '.json', '.yml', '.yaml', '.html', '.css', '.sh', '.toml']);
const skipped = new Set(['.git', '.claude', 'node_modules', 'dist', 'coverage', 'artifacts', '.next']);
function* files(path) {
  const stat = statSync(path);
  if (stat.isDirectory()) {
    for (const ent of readdirSync(path, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) if (!ent.isSymbolicLink() && !skipped.has(ent.name)) yield* files(join(path, ent.name));
  } else if (stat.isFile() && stat.size <= 4 * 1_048_576 && allowed.has(extname(path))) yield path;
}
const report = { at: new Date().toISOString(), syntheticKeys: 480, formats: Object.keys(formats), batches: states.length, files: 0, bytes: 0, scannedCharacters: 0, fragmentDenials: [], fragmentReviews: [], unavailable: [], observations: 0 };
const visited = new Set();
for (const root of roots) for (const file of files(root)) {
  if (visited.has(file)) continue; visited.add(file);
  const text = readFileSync(file, 'utf8');
  report.files++; report.bytes += Buffer.byteLength(text); report.scannedCharacters += Math.min(text.length, 524_288);
  for (const [batch, state] of states.entries()) {
    const result = checkFragments({ body: text }, state, false, true);
    if (result.secret) report.fragmentDenials.push({ file, batch });
    if (result.review) report.fragmentReviews.push({ file, batch });
    if (result.unavailable) report.unavailable.push({ file, batch });
  }
}
report.observationsBySize = Object.fromEntries([5, 6, 7, 'edge'].map(size => [size, states.reduce((n, s) => n + s.fragments.seen.filter(r => size === 'edge' ? r.edge : !r.edge && r.size === size).length, 0)]));
report.observations = states.reduce((n, s) => n + s.fragments.seen.length, 0);
writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report));
