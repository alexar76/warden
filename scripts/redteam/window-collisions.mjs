#!/usr/bin/env node
// How small can the flow guard's key window be before ordinary text matches a piece of a key by chance?
// Key-like values of eight real formats (made up here, same alphabet and structure) are cut into windows the way
// src/flow-guard-fingerprints.ts does: letters and digits only, lower-cased, look-alikes folded, a letter and a digit in every
// window, none starting in the leading letters. Then every window of a large body of ordinary text, forwards and
// backwards, is looked up. A hit is a false positive the guard would deny as "part of a credential".
//
// Two tables: "sizes" cuts every key at 6 to 10 characters with no other rule (how the sizes were chosen), and
// "guard" applies the guard's own rules (8, or 10 for hex keys, no shared key structure). The guard table's key
// windows are checked against tokenFingerprints() from dist/, so it measures the code that ships.
//
//   node scripts/redteam/window-collisions.mjs OUT.json DIR_OR_FILE [...]
//   DIR_OR_FILE: a directory is walked; a file is read as text (gzip is unpacked); NAME.list holds one path per line.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { join, extname } from 'node:path';
import { secretTokens, tokenFingerprints } from '../../dist/flow-guard.js';

const [out, ...sources] = process.argv.slice(2);
const SIZES = [6, 7, 8, 9, 10];
const MAX_FILE = 4 * 1024 * 1024;
const TEXT_EXT = new Set(['.md', '.txt', '.ts', '.js', '.mjs', '.cjs', '.py', '.json', '.jsonl', '.yml', '.yaml', '.toml', '.html', '.css', '.sh', '.go', '.rs', '.sol', '.sql', '.csv', '.tsx', '.jsx', '.ini', '.cfg', '.conf', '.env', '.example', '.gz', '.xml', '.svg']);

// Deterministic made-up keys: a seeded stream, so the measurement repeats exactly.
let seed = 0;
function bytes(n) { const out = []; while (out.length < n) out.push(...createHash('sha256').update(`window collisions ${seed++}`).digest()); return out.slice(0, n); }
const pick = (alphabet, n) => bytes(n).map(b => alphabet[b % alphabet.length]).join('');
const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B64 = B62 + '+/';
const HEX = '0123456789abcdef';
const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const FORMATS = {
  stripe: () => ['rk', 'live', pick(B62, 40)].join('_'),
  github: () => ['ghp', pick(B62, 36)].join('_'),
  aws: () => 'AKIA' + pick(UP, 16) + ' ' + pick(B64, 40),
  anthropic: () => ['sk', 'ant', 'api03', pick(B62 + '_-', 93)].join('-'),
  hex: () => pick(HEX, 64),
  base64: () => pick(B64, 43) + '=',
  // The header of every HS256 JWT is the same text: a key that is a JWT shares it with every other JWT.
  jwt: () => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + pick(B62, 120) + '.' + pick(B62 + '_-', 43),
  // Every RSA private key in PKCS#8 opens with the same ASN.1 bytes.
  pem: () => 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ' + pick(B64, 64 * 6),
};

const CONFUSABLE = { а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ԛ: 'q', ԝ: 'w', α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', γ: 'y', ζ: 'z' };
const alnum = s => s.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, ch => CONFUSABLE[ch] ?? '');
const TOKEN_RUN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
function entropy(s) { const c = new Map(); for (const ch of s) c.set(ch, (c.get(ch) ?? 0) + 1); let h = 0; for (const n of c.values()) h -= (n / s.length) * Math.log2(n / s.length); return h; }
// The same extraction the guard uses for a credential file.
function tokens(text) {
  const outT = new Set();
  for (const m of text.matchAll(TOKEN_RUN)) { const a = alnum(m[0]); if (a.length >= 16 && /\d/.test(a) && /[a-z]/.test(a) && entropy(a) >= 3.5) outT.add(a); }
  return [...outT];
}

const stores = Object.fromEntries(SIZES.map(w => [w, new Map()])); // window → format
const guard = new Map(); // the guard's own windows → format
const KEY_STRUCTURE = ['anbgkqhkig9w0baqefaa', 'a0gcsqgsib3dqebcwua', 'a0gcsqgsib3dqebbquaa', 'byqgsm49ageg', 'ccqgsm49aweh', 'bsubbaaiq', 'mcowbqydk2vw', 'mcowbqydk2vu'];
const fpHash = w => createHash('sha256').update(w).digest('hex').slice(0, 12);
const PER_FORMAT = 60;
for (const [name, make] of Object.entries(FORMATS)) {
  for (let i = 0; i < PER_FORMAT; i++) {
    const key = make();
    const mine = new Set();
    for (const t of tokens(key.split('.').filter(r => !r.startsWith('eyJ')).join(' '))) {
      const size = /^[0-9a-f]+$/.test(t) ? 10 : 8;
      const start = /^(mii|mig|mhc|mc4|mco)/.test(t) ? Math.max(48, /^[a-z]*/.exec(t)[0].length) : /^[a-z]*/.exec(t)[0].length;
      for (let j = start; j + size <= t.length; j++) {
        const w = t.slice(j, j + size);
        if (/\d/.test(w) && /[a-z]/.test(w) && !KEY_STRUCTURE.some(k => k.includes(w))) { guard.set(w, name); mine.add(fpHash(w)); }
      }
    }
    const shipped = new Set(tokenFingerprints(secretTokens(key, true)));
    if (shipped.size !== mine.size || [...mine].some(h => !shipped.has(h))) throw new Error(`this script and dist/flow-guard.js cut a ${name} key differently`);
    for (const t of tokens(key)) {
      for (const w of SIZES) for (let j = /^[a-z]*/.exec(t)[0].length; j + w <= t.length; j++) {
        const win = t.slice(j, j + w);
        if (/\d/.test(win) && /[a-z]/.test(win)) stores[w].set(win, name);
      }
    }
  }
}

function* files(path) {
  if (path.endsWith('.list')) { for (const p of readFileSync(path, 'utf8').split('\n').filter(Boolean)) yield* files(p); return; }
  // Results of earlier runs quote key windows as examples: scanning them would count the measurement itself.
  if (path.includes('/scripts/redteam/results/')) return;
  let st;
  try { st = statSync(path); } catch { return; }
  if (st.isFile()) { yield path; return; }
  for (const e of readdirSync(path)) {
    if (e === 'node_modules' || e === '.git' || e === 'dist' || e === '.venv' || e === 'venv' || e === '__pycache__') continue;
    yield* files(join(path, e));
  }
}
function* texts(file) {
  const ext = extname(file).toLowerCase();
  if (!TEXT_EXT.has(ext) && ext !== '') return;
  let buf;
  try { if (statSync(file).size > MAX_FILE) return; buf = readFileSync(file); } catch { return; }
  if (ext === '.gz') { try { buf = gunzipSync(buf); } catch { return; } }
  const s = buf.toString('utf8');
  if (s.includes('\u0000')) return;
  yield s;
}

const hits = Object.fromEntries([...SIZES, 'guard'].map(w => [w, { windows: 0, files: new Set(), byFormat: {}, examples: [] }]));
let scannedChars = 0, scannedFiles = 0;
for (const src of sources) for (const f of files(src)) for (const t of texts(f)) {
  scannedFiles++;
  const a = alnum(t);
  scannedChars += a.length;
  const back = [...a].reverse().join('');
  for (const text of [a, back]) for (const w of [8, 10]) {
    const h = hits.guard;
    for (let i = 0; i + w <= text.length; i++) {
      const fmt = guard.get(text.slice(i, i + w));
      if (fmt) {
        h.windows++; h.files.add(f); h.byFormat[fmt] = (h.byFormat[fmt] ?? 0) + 1;
        if (h.examples.length < 8) h.examples.push({ file: f.slice(-90), window: text.slice(i, i + w), format: fmt });
      }
    }
  }
  for (const w of SIZES) {
    const store = stores[w], h = hits[w];
    for (let i = 0; i + w <= a.length; i++) {
      const fmt = store.get(a.slice(i, i + w));
      if (fmt) {
        h.windows++; h.files.add(f); h.byFormat[fmt] = (h.byFormat[fmt] ?? 0) + 1;
        if (h.examples.length < 8) h.examples.push({ file: f.slice(-90), window: a.slice(i, i + w), format: fmt });
      }
    }
  }
}
const result = {
  at: new Date().toISOString(),
  keys: Object.keys(FORMATS).length * PER_FORMAT, formats: Object.keys(FORMATS),
  scanned: { files: scannedFiles, lettersAndDigits: scannedChars },
  sizes: Object.fromEntries(SIZES.map(w => [w, { keyWindows: stores[w].size, hitWindows: hits[w].windows, filesHit: hits[w].files.size, byFormat: hits[w].byFormat, examples: hits[w].examples }])),
  guard: { keyWindows: guard.size, hitWindows: hits.guard.windows, filesHit: hits.guard.files.size, byFormat: hits.guard.byFormat, examples: hits.guard.examples },
};
writeFileSync(out, JSON.stringify(result, null, 2) + '\n');
for (const w of SIZES) console.log(`window ${w}: ${stores[w].size} key windows, ${hits[w].windows} hits in ${hits[w].files.size} files`, JSON.stringify(hits[w].byFormat));
console.log(`guard (8, hex 10, no shared structure): ${guard.size} key windows, ${hits.guard.windows} hits in ${hits.guard.files.size} files`, JSON.stringify(hits.guard.byFormat));
console.log(`scanned ${scannedFiles} texts, ${scannedChars} letters and digits`);
