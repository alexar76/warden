import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { screenTargetStamp, type ScreenView } from '../src/flow-guard.js';
import { screenLease } from '../src/wrap-screen.js';
import { parseWrapArgs } from '../src/wrap-cli.js';

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const hash = (v: string) => createHash('sha256').update(v).digest('hex');
function view(): ScreenView {
  return { at: new Date().toISOString(), tool: 'mcp__screen__screenshot', origin: 'https://mail.example', titles: ['Mail'], refs: {}, policyComplete: true, focused: '3',
    elements: { '3': { role: 'button', referenceHash: hash('3'), identityHash: hash('send'), bounds: { x: 100, y: 50, width: 40, height: 20 } } } };
}
describe('fresh snapshot equality is evidence, never automatic permission', () => {
  it('ignores observation timestamps/revisions but binds exact target, context and geometry', () => {
    const before = view(), after = structuredClone(before); after.at = new Date(Date.now() + 100).toISOString(); after.revision = 'new';
    expect(screenTargetStamp('mcp__screen__click', { index: 3 }, before)).toBe(screenTargetStamp('mcp__screen__click', { index: 3 }, after));
    expect(screenTargetStamp('mcp__screen__click', { x: 110, y: 55 }, before)).toBeTruthy();
  });
  it.each(['role', 'identity', 'bounds', 'context', 'title', 'reference', 'incomplete', 'missing-bounds', 'duplicate', 'overlap', 'conflicting-context'])('refuses comparison or changes the stamp for %s', kind => {
    const before = view(), after = structuredClone(before), e = after.elements!['3']!;
    if (kind === 'role') e.role = 'link'; if (kind === 'identity') e.identityHash = hash('delete'); if (kind === 'bounds') e.bounds!.x++;
    if (kind === 'context') after.origin = 'https://other.example'; if (kind === 'title') after.titles = ['Other']; if (kind === 'reference') e.referenceHash = hash('4');
    if (kind === 'incomplete') delete after.policyComplete; if (kind === 'missing-bounds') delete e.bounds;
    if (kind === 'conflicting-context') after.contextAmbiguous = true;
    if (kind === 'duplicate' || kind === 'overlap') after.elements!['4'] = { ...e, ...(kind === 'overlap' ? { identityHash: hash('other') } : {}) };
    const input = kind === 'overlap' ? { x: 110, y: 55 } : { index: 3 };
    expect(screenTargetStamp('mcp__screen__click', input, after)).not.toBe(screenTargetStamp('mcp__screen__click', input, before));
  });
  it('requires the same focused element for keyboard actions and consistent coordinate/reference dispatch', () => {
    const before = view(), after = structuredClone(before); after.focused = '4';
    expect(screenTargetStamp('mcp__screen__press_keys', { keys: 'Enter' }, before)).toBeTruthy();
    expect(screenTargetStamp('mcp__screen__press_keys', { keys: 'Enter' }, after)).toBeUndefined();
    for (const args of [{ index: 3, ref: '3' }, { index: 3, x: 500, y: 500 }, { index: '03' }, { x: '110', y: 55 }, { index: 3, selector: '#other' }, { position: { x: 110, y: 55, selector: '#other' } }]) expect(screenTargetStamp('mcp__screen__click', args, before)).toBeUndefined();
    expect(screenTargetStamp('mcp__screen__press_keys', { keys: ['cmd+v', 'Enter'] }, before)).toBeUndefined();
  });
});
describe('operator-selected observation and cross-process lease', () => {
  it.each([
    ['--screen-read', 'screenshot'],
    ['--screen-atomic'],
    ['--flow', 'screen', '--screen-atomic'],
    ['--flow', 'screen', '--screen-read', 'screenshot', '--screen-atomic', '--audit-only'],
    ['--flow', 'screen', '--screen-read', 'send_email'],
    ['--flow', 'screen', '--screen-read-input', '{}'],
    ['--flow', 'screen', '--screen-read', 'computer', '--screen-read-input', '{"action":"screenshot","text":"send"}'],
    ['--flow', 'screen', '--screen-read', 'computer', '--screen-read-input', '{"action":"send","action":"screenshot"}'],
  ].map(flags => [flags]))('rejects unsafe or ambiguous observation configuration %j', async flags => {
    await expect(parseWrapArgs(['wrap', ...flags, '--', process.execPath])).rejects.toThrow();
  });
  it.each([
    ['--flow', 'screen', '--screen-read', 'get_elements'],
    ['--flow', 'screen', '--screen-read', 'screenshot', '--screen-atomic'],
    ['--flow', 'screen', '--screen-read', 'browser_snapshot'],
    ['--flow', 'screen', '--screen-read', 'computer', '--screen-read-input', '{"action":"screenshot"}'],
  ].map(flags => [flags]))('accepts explicit supported observation configuration %j', async flags => {
    expect((await parseWrapArgs(['wrap', ...flags, '--', process.execPath])).screenRead).toBeTruthy();
  });
  it('does not reclaim an uncertain GUI lease on a new proxy or a new attempt', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-screen-lease-')); dirs.push(dir); const env = { WARDEN_STATE_DIR: dir };
    const first = screenLease('session', env); expect(() => screenLease('session', env)).toThrow('pending'); first();
    const second = screenLease('session', env); second(true);
    expect(() => screenLease('session', env)).toThrow('operator review');
  });
});
