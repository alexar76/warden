import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readLogs, stats } from '../scripts/flow-log-stats.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function stateDir(logs: Record<string, object[]>): string {
  const dir = mkdtempSync(join(tmpdir(), 'warden-stats-')); dirs.push(dir);
  mkdirSync(join(dir, 'claude-code', 'flow'), { recursive: true });
  for (const [name, events] of Object.entries(logs)) {
    writeFileSync(join(dir, 'claude-code', 'flow', `${name}.log`), events.map(e => JSON.stringify(e)).join('\n') + '\nnot json\n');
  }
  return dir;
}

const audit = [
  { at: '2026-11-10T10:00:00Z', event: 'taint', tool: 'Bash', src: 'shell output' },
  { at: '2026-11-10T10:01:00Z', event: 'pre', tool: 'Bash', decision: 'ask', reason: 'opaque_shell', disposition: 'audit_only', mode: 'audit' },
  { at: '2026-11-10T10:02:00Z', event: 'pre', tool: 'Write', decision: 'deny', reason: 'secret_to_file', disposition: 'audit_only', mode: 'audit' },
];
const deny = [
  { at: '2026-11-11T09:00:00Z', event: 'pre', tool: 'Bash', decision: 'deny', reason: 'secret', disposition: 'refused', mode: 'deny' },
  { at: '2026-11-11T09:00:01Z', event: 'pre', tool: 'mcp__x__task_execute', decision: 'allow', reason: 'task_adapter_delegated', mode: 'deny' },
];
const clean = [{ at: '2026-11-11T09:05:00Z', event: 'stop', sources: 0, mode: 'deny' }];

describe('flow-log-stats', () => {
  it('counts sessions, taint and decisions; allow entries are not decisions', () => {
    const s = stats(readLogs(stateDir({ a: audit, b: deny, c: clean })));
    expect(s.sessions).toBe(3);
    expect(s.tainted).toBe(1);
    expect(s.decisions).toBe(3);
    expect(s.byMode).toEqual({ audit: 2, deny: 1 });
    expect(s.byReason).toEqual({ opaque_shell: 1, secret_to_file: 1, secret: 1 });
  });

  it('reports what deny would have refused in audit sessions: ask and deny alike', () => {
    expect(stats(readLogs(stateDir({ a: audit }))).auditWouldRefuseInDeny).toBe(2);
  });

  it('filters by --since', () => {
    const s = stats(readLogs(stateDir({ a: audit, b: deny }), '2026-11-11T00:00:00Z'));
    expect(s.sessions).toBe(1);
    expect(s.byMode).toEqual({ deny: 1 });
  });

  it('counts unattended adapter resolutions', () => {
    const s = stats(readLogs(stateDir({ o: [{ at: 'x', event: 'codex', tool: 'Bash', resolution: 'allowed_unattended' }, { at: 'y', event: 'codex', resolution: 'refused' }] })));
    expect(s.adapterResolutions).toEqual({ 'codex:allowed_unattended': 1, 'codex:refused': 1 });
  });

  it('runs as a command, and handles an empty state dir', () => {
    const out = execFileSync(process.execPath, [join(root, 'scripts/flow-log-stats.mjs'), stateDir({ a: audit }), '--json']).toString();
    expect(JSON.parse(out).auditWouldRefuseInDeny).toBe(2);
    const empty = mkdtempSync(join(tmpdir(), 'warden-stats-empty-')); dirs.push(empty);
    expect(execFileSync(process.execPath, [join(root, 'scripts/flow-log-stats.mjs'), empty]).toString()).toMatch(/sessions 0/);
  });
});
