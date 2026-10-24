import { afterEach, describe, expect, it, vi } from 'vitest';
import { AtomicScreenServer, ATOMIC_SCREEN_PROTOCOL as protocol, atomicScreenPrepared, atomicScreenReceipt } from '../src/atomic-screen.js';

const observation = { name: 'screenshot', arguments: {} };
const action = { name: 'click', arguments: { x: 12.5, y: 15 } };
const snapshot = () => ({ content: [{ type: 'text', text: JSON.stringify({ url: 'https://mail.example/inbox', elements: [
  { index: 3, role: 'button', name: 'Send', accessibilityIdentifier: 'mail.send', bounds: { x: 10, y: 10, width: 40, height: 30 } },
] }) }] });
function server(apply?: ConstructorParameters<typeof AtomicScreenServer>[0]['apply']) {
  const effects: unknown[] = [];
  const instance = new AtomicScreenServer({ observation, actions: ['click', 'press_keys', 'type_text'], snapshot: snapshot(), apply: apply ?? ((a, target) => {
    effects.push({ a, target }); return { result: { content: [{ type: 'text', text: 'done' }] }, snapshot: snapshot() };
  }) });
  const prepare = (a: unknown = action) => instance.prepare({ protocol, observation, action: a });
  const request = (p = prepare(), a: unknown = action) => ({ protocol, ticket: p.ticket, expected: { revision: p.revision, stamp: p.stamp }, action: structuredClone(a) });
  return { instance, effects, prepare, request };
}
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });
describe('atomic server-owned screen transactions', () => {
  it('compares target and revision then commits synchronously to the resolved element, never coordinates', () => {
    const s = server(), p = atomicScreenPrepared(s.prepare()), req = s.request(p);
    const result = atomicScreenReceipt(s.instance.commit(req), p);
    expect(result.status).toBe('committed'); expect(s.effects).toEqual([{ a: action, target: '3' }]);
    expect(s.instance.commit(req)).toMatchObject({ status: 'refused', reason: 'unknown' });
    expect(s.effects).toHaveLength(1);
  });
  it.each(['role', 'id', 'box', 'context', 'focus', 'handler', 'aba'])('refuses a %s mutation between observation and commit', kind => {
    const s = server(), req = s.request(), next = snapshot(), data = JSON.parse(next.content[0]!.text);
    if (kind === 'role') data.elements[0].role = 'link';
    if (kind === 'id') data.elements[0].accessibilityIdentifier = 'delete';
    if (kind === 'box') data.elements[0].bounds.x++;
    if (kind === 'context') data.url = 'https://other.example';
    if (kind === 'focus') data.focusedRef = 3;
    next.content[0]!.text = JSON.stringify(data);
    s.instance.replace(next); if (kind === 'aba') s.instance.replace(snapshot());
    expect(s.instance.commit(req)).toMatchObject({ status: 'refused', reason: 'stale' }); expect(s.effects).toHaveLength(0);
  });
  it.each(['arguments', 'name', 'stamp', 'revision', 'ticket'])('refuses a forged %s binding with zero effects', kind => {
    const s = server(), req = s.request();
    if (kind === 'arguments') (req.action as typeof action).arguments.x++;
    if (kind === 'name') (req.action as typeof action).name = 'press_keys';
    if (kind === 'stamp' || kind === 'revision') req.expected[kind] = '0'.repeat(64);
    if (kind === 'ticket') req.ticket = '0'.repeat(64);
    expect(s.instance.commit(req).status).toBe('refused'); expect(s.effects).toHaveLength(0);
  });
  it('isolates copied snapshots, tickets and action arguments from caller mutation', () => {
    const s = server(), original = structuredClone(action), p = s.prepare(original), req = s.request(p);
    original.arguments.x = 50; p.observation.changed = true; s.instance.read().changed = true;
    expect(s.instance.commit(req).status).toBe('committed'); expect(s.effects).toEqual([{ a: action, target: '3' }]);
  });
  it('invalidates other prepared actions after any committed effect, even unchanged visible metadata', () => {
    const s = server(), first = s.request(), second = s.request();
    expect(s.instance.commit(first).status).toBe('committed'); expect(s.instance.commit(second)).toMatchObject({ status: 'refused', reason: 'stale' });
    expect(s.effects).toHaveLength(1);
  });
  it('invalidates old approvals even if replacing changed state fails serialization', () => {
    const s = server(), req = s.request();
    expect(() => s.instance.replace({ changed: undefined })).toThrow();
    expect(s.instance.commit(req)).toMatchObject({ status: 'refused', reason: 'unavailable' });
    expect(() => s.prepare()).toThrow('unavailable'); expect(s.effects).toHaveLength(0);
    s.instance.replace(snapshot()); expect(() => s.prepare()).not.toThrow();
  });
  it('supports a generic observation/action controller without authorizing its read operation as an effect', () => {
    const obs = { name: 'computer', arguments: { action: 'screenshot' } }, a = { name: 'computer', arguments: { action: 'click', index: 3 } };
    let target: string | undefined;
    const s = new AtomicScreenServer({ observation: obs, actions: ['computer'], snapshot: snapshot(), apply: (_action, ref) => {
      target = ref; return { result: {}, snapshot: snapshot() };
    } });
    expect(() => s.prepare({ protocol, observation: obs, action: obs })).toThrow('target');
    const p = s.prepare({ protocol, observation: obs, action: a });
    expect(s.commit({ protocol, ticket: p.ticket, expected: { revision: p.revision, stamp: p.stamp }, action: a }).status).toBe('committed'); expect(target).toBe('3');
  });
  it('refuses expired and clock-rollback tickets and expires pending capacity without dispatch', () => {
    vi.useFakeTimers(); const s = server(), old = s.request(); vi.setSystemTime(Date.now() + 300_001);
    expect(s.instance.commit(old)).toMatchObject({ status: 'refused', reason: 'expired' });
    const future = s.request(); vi.setSystemTime(Date.now() - 1000);
    expect(s.instance.commit(future)).toMatchObject({ status: 'refused', reason: 'expired' }); expect(s.effects).toHaveLength(0);
    for (let i = 0; i < 256; i++) s.prepare();
    expect(() => s.prepare()).toThrow('Too many'); vi.setSystemTime(Date.now() + 300_001); expect(() => s.prepare()).not.toThrow();
  });
  it('expires tickets by monotonic elapsed time even when wall time is restored', () => {
    vi.useFakeTimers();
    const clock = vi.spyOn(process.hrtime, 'bigint').mockReturnValue(1_000_000n);
    const s = server(), req = s.request();
    clock.mockReturnValue(300_001_000_001n);
    expect(s.instance.commit(req)).toMatchObject({ status: 'refused', reason: 'expired' });
    expect(s.effects).toHaveLength(0);
  });
  it('rechecks expiry at the effect boundary after validating the target', () => {
    vi.useFakeTimers();
    const s = server(), req = s.request();
    const time = Date.now();
    vi.spyOn(Date, 'now').mockReturnValueOnce(time).mockReturnValue(time + 300_001);
    expect(s.instance.commit(req)).toMatchObject({ status: 'refused', reason: 'expired' });
    expect(s.effects).toHaveLength(0);
  });
  it('reclaims monotonic-expired capacity even while wall time stays unchanged', () => {
    vi.useFakeTimers();
    const clock = vi.spyOn(process.hrtime, 'bigint').mockReturnValue(1_000_000n);
    const s = server(); for (let i = 0; i < 256; i++) s.prepare();
    expect(() => s.prepare()).toThrow('Too many');
    clock.mockReturnValue(300_001_000_001n);
    expect(() => s.prepare()).not.toThrow(); expect(s.effects).toHaveLength(0);
  });
  it('cancel and restart make an approval unusable', () => {
    const s = server(), req = s.request(); s.instance.cancel({ protocol, ticket: req.ticket });
    expect(s.instance.commit(req).status).toBe('refused'); expect(server().instance.commit(s.request()).status).toBe('refused');
    expect(s.effects).toHaveLength(0);
  });
  it('poisons an uncertain failed effect and consumes its ticket; no implicit retries', () => {
    let count = 0;
    const s = server(() => { count++; throw new Error('network/input outcome uncertain'); }), req = s.request();
    expect(() => s.instance.commit(req)).toThrow('uncertain'); expect(s.instance.commit(req).status).toBe('refused');
    expect(() => s.prepare()).toThrow('unavailable'); expect(() => s.instance.read()).toThrow('unavailable'); expect(count).toBe(1);
    s.instance.replace(snapshot()); expect(() => s.prepare()).not.toThrow();
  });
  it('prevents reentrant mutations and effects inside the synchronous commit section', () => {
    let s: ReturnType<typeof server>, other: ReturnType<ReturnType<typeof server>['request']>;
    s = server(() => {
      expect(() => s.instance.replace(snapshot())).toThrow('already running');
      expect(() => s.prepare()).toThrow('unavailable');
      expect(s.instance.commit(other)).toMatchObject({ status: 'refused', reason: 'unavailable' });
      return { result: {}, snapshot: snapshot() };
    });
    const req = s.request(); other = s.request(); expect(s.instance.commit(req).status).toBe('committed');
  });
  it('rejects async backends at registration; a promise-returning contract violation poisons execution', () => {
    expect(() => server((async () => ({ result: {}, snapshot: snapshot() })) as any)).toThrow('Unsupported');
    const s = server((() => Promise.resolve({ result: {}, snapshot: snapshot() })) as any);
    expect(() => s.instance.commit(s.request())).toThrow('uncertain'); expect(() => s.prepare()).toThrow('unavailable');
  });
  it.each([
    { name: 'click', arguments: { index: 3, selector: '#elsewhere' } },
    { name: 'click', arguments: { x: 999, y: 999 } },
    { name: 'click', arguments: { index: 3, ref: '3' } },
    { name: 'press_keys', arguments: { keys: ['cmd+v', 'Enter'] } },
    { name: 'unknown', arguments: {} },
    { name: 'click', arguments: { index: 3 }, extra: true },
  ])('rejects unsupported or ambiguous action schemas %j', a => {
    const s = server(); expect(() => s.prepare(a)).toThrow(); expect(s.effects).toHaveLength(0);
  });
  it('rejects pixels-only and duplicate target observations', () => {
    const s = server(); s.instance.replace({ content: [{ type: 'image', data: 'pixels' }] }); expect(() => s.prepare()).toThrow('target');
    const next = snapshot(), data = JSON.parse(next.content[0]!.text); data.elements.push({ ...data.elements[0], index: 4 }); next.content[0]!.text = JSON.stringify(data);
    s.instance.replace(next); expect(() => s.prepare()).toThrow('target');
  });
  it('strictly validates protocol envelopes and receipts instead of trusting a success string', () => {
    const s = server(), p = s.prepare(), req = s.request(p);
    for (const bad of [{ ...req, extra: true }, { ...req, protocol: 'v0' }, { ...req, expected: { ...req.expected, extra: true } }]) expect(() => s.instance.commit(bad)).toThrow();
    for (const bad of [{ ...p, protocol: 'v0' }, { ...p, ticket: '' }, { ...p, extra: true }, { ...p, expiresAt: Date.now() + 400_000 }]) expect(() => atomicScreenPrepared(bad)).toThrow();
    const receipt = s.instance.commit(req);
    for (const bad of [{}, { ...receipt, stamp: '0'.repeat(64) }, { ...receipt, revisionAfter: p.revision }, { ...receipt, extra: true }]) expect(() => atomicScreenReceipt(bad, p)).toThrow();
  });
});
