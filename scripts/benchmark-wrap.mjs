import { fileURLToPath } from 'node:url';
// Warm local stdio benchmark; no network, no npx startup. Run after npm run build.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir, cpus } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { WrapFrames } from '../dist/wrap-wire.js';
const root = resolve(fileURLToPath(new URL(".", import.meta.url)), '..');
const dir = mkdtempSync(join(tmpdir(), 'warden-bench-'));
const config = join(dir, 'fixture.json');
writeFileSync(config, JSON.stringify({ count: 50 }));
const samples = 100, warmup = 10;
async function run(wrap) {
  const fixture = join(root, 'test/fixtures/wrap-server.mjs');
  const p = spawn(process.execPath, wrap ? [join(root, 'dist/mcp-server.js'), 'wrap', '--id', 'benchmark', '--state-dir', dir, '--', process.execPath, fixture] : [fixture], {
    env: { ...process.env, WARDEN_FIXTURE_CONFIG: config }, stdio: ['pipe', 'pipe', 'ignore'],
  });
  const pending = new Map(); let id = 0;
  const frames = new WrapFrames('ndjson');
  p.stdout.on('data', chunk => { for (const b of frames.push(chunk)) { const msg = JSON.parse(b); pending.get(msg.id)?.(msg); pending.delete(msg.id); } });
  const request = (method, params) => new Promise((resolve, reject) => {
    const next = ++id, timer = setTimeout(() => reject(new Error('benchmark timeout')), 15000);
    pending.set(next, msg => { clearTimeout(timer); msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result); });
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: next, method, params }) + '\n');
  });
  try {
    await request('initialize', {}); await request('tools/list', {});
    const timings = { list: [], call: [] };
    for (let i = -warmup; i < samples; i++) {
      for (const [key, method, params] of [['list', 'tools/list', {}], ['call', 'tools/call', { name: 'tool0', arguments: {} }]]) {
        const start = performance.now(); await request(method, params);
        if (i >= 0) timings[key].push(performance.now() - start);
      }
    }
    return timings;
  } finally { const done = new Promise(r => p.on('close', r)); p.stdin.end(); await done; }
}
function stats(values) { const s = [...values].sort((a, b) => a - b); return { p50: +s[Math.ceil(s.length * .5) - 1].toFixed(3), p95: +s[Math.ceil(s.length * .95) - 1].toFixed(3) }; }
try {
  const direct = await run(false), wrap = await run(true);
  const result = { date: new Date().toISOString(), node: process.version, platform: process.platform, arch: process.arch, cpu: cpus()[0]?.model, samples, warmup, tools: 50, milliseconds: {} };
  for (const key of ['list', 'call']) {
    const baseline = stats(direct[key]), proxy = stats(wrap[key]);
    result.milliseconds[key] = { direct: baseline, wrap: proxy, quantileDifference: { p50: +(proxy.p50 - baseline.p50).toFixed(3), p95: +(proxy.p95 - baseline.p95).toFixed(3) } };
  }
  console.log(JSON.stringify(result, null, 2));
} finally { rmSync(dir, { recursive: true, force: true }); }
