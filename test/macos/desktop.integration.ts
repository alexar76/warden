import { afterEach, describe, expect, it } from 'vitest';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { screenResponseStamp } from '../../src/flow-guard.js';
import { atomicScreenPrepared, atomicScreenReceipt, ATOMIC_SCREEN_PROTOCOL as protocol } from '../../src/atomic-screen.js';

const root = fileURLToPath(new URL('../..', import.meta.url));
const binary = join(root, 'native/macos/.build/warden-desktop-test');
const production = join(root, 'native/macos/.build/warden-desktop');
const children: ChildProcessWithoutNullStreams[] = [], dirs: string[] = [];
afterEach(async () => {
  for (const p of children.splice(0)) {
    p.stdin.end();
    if (p.exitCode === null) await Promise.race([new Promise<void>(r => p.once('close', () => r())), new Promise<void>(r => setTimeout(() => { p.kill('SIGKILL'); r(); }, 1000).unref())]);
  }
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function client(options: { wrap?: boolean; production?: boolean; approve?: boolean } = {}) {
  if (process.platform !== 'darwin') throw new Error('This native integration gate requires macOS; no skipped or simulated success');
  const dir = mkdtempSync(join(tmpdir(), 'warden-native-')); dirs.push(dir);
  const target = options.production ? production : binary;
  const p = options.wrap ? spawn(process.execPath, [join(root, 'dist/mcp-server.js'), 'wrap', '--id', 'native-test', '--state-dir', join(dir, 'pins'), '--flow', 'native', '--screen-read', 'screenshot', '--screen-atomic', '--', target, '--demo'],
    { env: { ...process.env, WARDEN_STATE_DIR: join(dir, 'flow'), WARDEN_FLOW_SESSION: 'native-integration', WARDEN_FLOW_POLICY: join(dir, 'none.json'), WARDEN_FLOW_MODE: '' }, stdio: 'pipe' })
    : spawn(target, ['--demo'], { stdio: 'pipe' });
  children.push(p);
  const messages: any[] = [], asked: any[] = [], pending = new Map<any, (v: any) => void>(); let seq = 0, buf = '', stderr = '';
  const send = (value: any) => p.stdin.write(JSON.stringify(value) + '\n');
  p.stderr.on('data', b => stderr += b);
  p.stdout.on('data', b => {
    buf += b;
    while (buf.includes('\n')) {
      const i = buf.indexOf('\n'), line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line) continue;
      const m = JSON.parse(line); messages.push(m);
      if (m.method === 'elicitation/create') {
        asked.push(m);
        if (options.approve !== undefined) send({ jsonrpc: '2.0', id: m.id, result: { action: 'accept', content: { run: options.approve } } });
      }
      if (!m.method) { pending.get(m.id)?.(m); pending.delete(m.id); }
    }
  });
  const request = (method: string, params: any = {}) => new Promise<any>((resolve, reject) => {
    const id = ++seq, timer = setTimeout(() => { pending.delete(id); reject(new Error(`Native timeout ${method}: ${stderr}`)); }, 8000);
    pending.set(id, v => { clearTimeout(timer); resolve(v); }); send({ jsonrpc: '2.0', id, method, params });
  });
  const initialize = async () => {
    const r = await request('initialize', { protocolVersion: '2025-06-18', capabilities: { elicitation: {} }, clientInfo: { name: 'warden-native-integration', version: '1' } });
    expect(r.error, stderr).toBeUndefined(); return r;
  };
  return { p, request, initialize, messages, asked, send, stderr: () => stderr, lastCommit: undefined as any };
}
const observation = { name: 'screenshot', arguments: {} };
const click = { name: 'click', arguments: { index: '3' } };
const prepare = async (c: ReturnType<typeof client>, action: any = click) => {
  const r = await c.request('warden/screen/prepare', { protocol, observation, action }); expect(r.error, c.stderr()).toBeUndefined();
  const p = atomicScreenPrepared(r.result);
  expect(p.stamp).toBe(screenResponseStamp(`mcp__native__${action.name}`, action.arguments, 'mcp__native__screenshot', {}, p.observation));
  return p;
};
const commit = async (c: ReturnType<typeof client>, p: Awaited<ReturnType<typeof prepare>>, action: any = click) => {
  const response = await c.request('warden/screen/commit', {
    protocol, ticket: p.ticket, expected: { revision: p.revision, stamp: p.stamp }, action,
  });
  c.lastCommit = response.error ?? { status: response.result?.status, reason: response.result?.reason };
  return response;
};
const nativeDiagnostic = (c: ReturnType<typeof client>) => JSON.stringify({ lastCommit: c.lastCommit, stderr: c.stderr() });
const stats = async (c: ReturnType<typeof client>) => (await c.request('test/stats')).result;

describe('native AppKit target-side integration (real macOS window; no global input)', () => {
  it('matches the shared stamp and invokes the retained native handler exactly once on the main thread', async () => {
    const c = client(); await c.initialize();
    expect((await stats(c))).toMatchObject({ count: 0, mainThread: true, windowVisible: true });
    const p = await prepare(c), r = await commit(c, p);
    expect(atomicScreenReceipt(r.result, p).status).toBe('committed'); expect((await stats(c)).count).toBe(1);
    expect((await commit(c, p)).result).toMatchObject({ status: 'refused', reason: 'unknown' }); expect((await stats(c)).count).toBe(1);
  });
  it('resolves native global coordinates to an owned button, then dispatches by retained object', async () => {
    const c = client(); await c.initialize(); const read = await c.request('tools/call', { name: 'screenshot', arguments: {} });
    const b = read.result.structuredContent.elements[0].bounds;
    const a = { name: 'click', arguments: { x: b.x + b.width / 2, y: b.y + b.height / 2 } };
    const p = await prepare(c, a); expect((await commit(c, p, a)).result.status).toBe('committed'); expect((await stats(c)).count).toBe(1);
  });
  it.each(['title', 'identity', 'handler', 'bounds', 'window', 'disabled', 'hidden', 'close', 'replace-object', 'overlay', 'aba', 'semantic', 'untracked-title'])('refuses native %s drift with zero handler invocations', async kind => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    expect((await c.request('test/change', { kind })).error).toBeUndefined();
    const r = await commit(c, p); expect(r.error).toBeUndefined(); expect(r.result.status).toBe('refused'); expect((await stats(c)).count).toBe(0);
  });
  it.each(['sheet', 'button-alpha', 'window-alpha', 'ancestor-alpha', 'partial-alpha', 'implementation'])('refuses an untracked native %s visibility/modal change', async kind => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    const mutation = await c.request('test/change', { kind: `untracked-${kind}` });
    expect(mutation.error).toBeUndefined();
    if (kind === 'sheet') expect(mutation.result).toMatchObject({ logicalParent: true, knownSheet: true });
    const r = await commit(c, p);
    expect(r.error).toBeUndefined(); expect(r.result.status).toBe('refused');
    expect((await stats(c)).count).toBe(0);
  });
  it.each(['sheet', 'button-alpha', 'window-alpha', 'ancestor-alpha'])('does not prepare an unavailable native %s target', async kind => {
    const c = client(); await c.initialize(); await c.request('test/change', { kind: `untracked-${kind}` });
    const r = await c.request('warden/screen/prepare', { protocol, observation, action: click });
    expect(r.error).toBeDefined(); expect(r.result).toBeUndefined(); expect((await stats(c)).count).toBe(0);
  });
  it('allows a fresh explicit approval for a consistently translucent visible target', async () => {
    const c = client(); await c.initialize(); await c.request('test/change', { kind: 'untracked-partial-alpha' });
    const p = await prepare(c); expect((await commit(c, p)).result.status).toBe('committed'); expect((await stats(c)).count).toBe(1);
  });
  it('passes multilingual native labels through the same cross-language target stamp', async () => {
    const c = client(); await c.initialize(); await c.request('test/change', { kind: 'unicode' });
    const p = await prepare(c), response = await commit(c, p);
    expect(response.result.status, nativeDiagnostic(c)).toBe('committed'); expect((await stats(c)).count).toBe(1);
  });
  it('rechecks the revision after an overridable native hit-test changes application semantics', async () => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    await c.request('test/change', { kind: 'hit-test-mutation' });
    expect((await commit(c, p)).result.status).toBe('refused'); expect(await stats(c), nativeDiagnostic(c)).toMatchObject({ hitRaceTriggered: true, count: 0 });
  });
  it.each(['handler', 'title', 'disabled', 'bounds', 'expiry', 'monotonic-expiry', 'sheet', 'button-alpha', 'window-alpha'])('refuses %s changes during native hit-test even without an invalidation callback', async kind => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    await c.request('test/change', { kind: `hit-untracked-${kind}` });
    const r = await commit(c, p);
    expect(r.error).toBeUndefined(); expect(r.result.status).toBe('refused');
    expect(await stats(c), nativeDiagnostic(c)).toMatchObject({ hitRaceTriggered: true, count: 0 });
    expect((await commit(c, p)).result.reason).toBe('unknown');
  });
  it.each(['handler', 'title', 'bounds'])('does not issue a stale native approval after %s changes in prepare hit-test', async kind => {
    const c = client(); await c.initialize();
    await c.request('test/change', { kind: `hit-untracked-${kind}` });
    const r = await c.request('warden/screen/prepare', { protocol, observation, action: click });
    expect(r.error).toBeDefined(); expect(r.result).toBeUndefined();
    expect(await stats(c)).toMatchObject({ hitRaceTriggered: true, count: 0 });
  });
  it('rejects Objective-C block arguments rather than treating them as an id sender', async () => {
    const c = client(); await c.initialize();
    expect((await c.request('test/invalid-registration', { kind: 'block' })).result).toMatchObject({ refused: true });
    expect((await stats(c)).count).toBe(0);
  });
  it.each(['expiry', 'rollback', 'monotonic-expiry'])('refuses %s without running the native handler', async kind => {
    const c = client(); await c.initialize(); const p = await prepare(c); await c.request('test/change', { kind });
    expect((await commit(c, p)).result).toMatchObject({ status: 'refused', reason: 'expired' }); expect((await stats(c)).count).toBe(0);
  });
  it('binds the exact action and consumes attempts on mismatch, cancellation and restart', async () => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    expect((await commit(c, p, { ...click, arguments: { index: 'other' } })).result).toMatchObject({ status: 'refused', reason: 'mismatch' });
    expect((await commit(c, p)).result.reason).toBe('unknown');
    const q = await prepare(c); await c.request('warden/screen/cancel', { protocol, ticket: q.ticket }); expect((await commit(c, q)).result.reason).toBe('unknown');
    const other = client(); await other.initialize(); expect((await commit(other, await prepare(c))).result.reason).toBe('unknown');
    expect((await stats(c)).count).toBe(0); expect((await stats(other)).count).toBe(0);
  });
  it('refuses raw effects and malformed schemas, including duplicate escaped JSON keys', async () => {
    const c = client(); await c.initialize();
    for (const action of [click, { name: 'press_keys', arguments: { keys: 'Enter' } }, { name: 'type_text', arguments: { text: 'not sent' } }]) expect((await c.request('tools/call', action)).error).toBeDefined();
    for (const a of [{ ...click, arguments: { index: true } }, { ...click, arguments: { index: '3', x: 1, y: 1 } }, { ...click, arguments: { x: 999999, y: 999999 } }, { ...click, arguments: { index: '3', selector: 'other' } }]) {
      expect((await c.request('warden/screen/prepare', { protocol, observation, action: a })).error).toBeDefined();
    }
    c.p.stdin.write('{"jsonrpc":"2.0","id":-1,"method":"tools/call","params":{"name":"click","n\\u0061me":"screenshot"}}\n');
    await c.request('ping'); expect(c.messages.some(m => m.id === null && m.error)).toBe(true); expect((await stats(c)).count).toBe(0);
  });
  it('refuses a native revision invalidation from the final injected clock callback', async () => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    await c.request('test/clock-race', { at: 2 });
    expect((await commit(c, p)).result.status).toBe('refused');
    expect((await c.request('test/clock-stats')).result.triggered).toBe(true);
    expect((await stats(c)).count).toBe(0);
  });
  it('does not issue a native ticket if a preparation clock callback invalidates the state', async () => {
    const c = client(); await c.initialize();
    await c.request('test/clock-race', { at: 1 });
    const r = await c.request('warden/screen/prepare', { protocol, observation, action: click });
    expect(r.error).toBeDefined(); expect(r.result).toBeUndefined();
    expect((await c.request('test/clock-stats')).result.triggered).toBe(true);
    expect((await stats(c)).count).toBe(0);
  });
  it('invokes the pinned native implementation without routing through an application sendAction override', async () => {
    const c = client(); await c.initialize(); const p = await prepare(c);
    await c.request('test/intercept-dispatch');
    expect((await commit(c, p)).result.status).toBe('committed');
    expect((await stats(c)).count).toBe(1);
    expect((await c.request('test/dispatch-stats')).result.intercepted).toBe(0);
  });
  it('refuses reentrant native commits and reads while the approved handler is running', async () => {
    const c = client(); await c.initialize(); const first = await prepare(c), nested = await prepare(c);
    await c.request('test/arm-reentrant', { protocol, ticket: nested.ticket, expected: { revision: nested.revision, stamp: nested.stamp }, action: click });
    expect((await commit(c, first)).result.status).toBe('committed');
    expect(await stats(c)).toMatchObject({ count: 1, reentrantRefused: true });
    expect((await commit(c, nested)).result.reason).toBe('unknown');
  });
  it('production build has no test/mutation transport endpoints', async () => {
    const c = client({ production: true }); await c.initialize();
    expect((await c.request('test/change', { kind: 'semantic' })).error).toBeDefined(); expect((await c.request('test/stats')).error).toBeDefined();
    for (const name of ['test/intercept-dispatch', 'test/dispatch-stats', 'test/clock-race', 'test/clock-stats']) expect((await c.request(name)).error).toBeDefined();
    const p = await prepare(c); expect((await commit(c, p)).result.status).toBe('committed');
  });
  it('refuses a native method with an unsafe target-action signature before dispatch', async () => {
    const c = client(); await c.initialize();
    expect((await c.request('test/invalid-registration')).result).toMatchObject({ refused: true }); expect((await stats(c)).count).toBe(0);
    const p = await prepare(c); expect((await commit(c, p)).result.status).toBe('committed');
  });
  it('real wrap approval reaches the native handler once and hides internal tickets', async () => {
    const c = client({ wrap: true, approve: true }); await c.initialize(); await c.request('tools/list');
    await c.request('tools/call', { name: 'screenshot', arguments: {} });
    const r = await c.request('tools/call', click); expect(r.error, c.stderr()).toBeUndefined();
    expect(r.result.content[0].text).toContain('Native AppKit action dispatched'); expect(c.asked).toHaveLength(1); expect((await stats(c)).count).toBe(1);
    expect(c.messages.some(m => m.result?.ticket || m.result?.revisionBefore)).toBe(false);
  });
  it('real wrap refuses a target-side mutation after the proxy final read, without a native action', async () => {
    const c = client({ wrap: true, approve: true }); await c.initialize(); await c.request('tools/list'); await c.request('tools/call', { name: 'screenshot' });
    await c.request('test/change', { kind: 'race-before-commit' });
    expect((await c.request('tools/call', click)).error.message).toContain('atomic server refused'); expect((await stats(c)).count).toBe(0);
  });
  it('a declined wrap form does not dispatch the native action', async () => {
    const c = client({ wrap: true, approve: false }); await c.initialize(); await c.request('tools/list'); await c.request('tools/call', { name: 'screenshot' });
    expect((await c.request('tools/call', click)).error).toBeDefined(); expect((await stats(c)).count).toBe(0);
  });
});
