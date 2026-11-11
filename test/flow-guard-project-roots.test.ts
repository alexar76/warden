import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { flowPre, flowPost, loadPolicy, readFlowState, flowPaths } from '../src/flow-guard.js';

// TONM-13, field false positive: a Multica agent works in <task workspace>/tonmobile-e2e and writes its report
// to <task workspace>/reply.md. After outside text that write counted as "outside the project" (destructive_action).
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function session(policy: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), 'warden-roots-')); dirs.push(dir);
  const file = join(dir, 'policy.json'); writeFileSync(file, JSON.stringify(policy));
  const env = { ...process.env, WARDEN_STATE_DIR: dir, WARDEN_FLOW_POLICY: file, WARDEN_FLOW_MODE: '' };
  for (const k of ['ENV', 'BASH_ENV', 'RIPGREP_CONFIG_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) delete (env as Record<string, unknown>)[k];
  const base = { session_id: 'roots', cwd: '/ws/task-7/tonmobile-e2e' };
  return {
    env,
    taint: () => flowPost({ ...base, tool_name: 'WebFetch', tool_input: { url: 'https://issue.example/7' }, tool_response: 'Task text from the tracker.' }, env),
    pre: (tool: string, input: Record<string, unknown>) => flowPre({ ...base, tool_name: tool, tool_input: input }, env),
    read: (path: string) => { flowPost({ ...base, tool_name: 'Read', tool_input: { file_path: path }, tool_response: { file: { content: 'Notes.' } } }, env); return readFlowState(flowPaths(env.WARDEN_STATE_DIR!, 'roots').state).untrusted.length; },
  };
}
const reply = { file_path: '/ws/task-7/reply.md', content: 'Run dev: 18 tests, 0 failed.' };

describe('extra project roots (projectRoots)', () => {
  it('reproduces the field false positive without the setting', () => {
    const s = session({});
    s.taint();
    expect(s.pre('Write', reply)?.permissionDecision).toBe('ask');
  });

  it('a write to the task workspace root is inside the project with projectRoots [".."]', () => {
    const s = session({ projectRoots: ['..'] });
    s.taint();
    expect(s.pre('Write', reply)).toBeUndefined();
    expect(s.pre('Write', { file_path: '/ws/task-8/reply.md', content: 'x' })?.permissionDecision).toBe('ask');
  });

  it('protected settings stay protected inside an extra root', () => {
    const s = session({ mode: 'deny', projectRoots: ['..'] });
    expect(s.pre('Write', { file_path: '/ws/task-7/.claude/settings.json', content: '{"hooks":{}}' })?.permissionDecision).toBe('deny');
  });

  it('ignores a root that would switch the check off: "/" or anything containing the home folder', () => {
    for (const root of ['/', homedir(), join(homedir(), '..')]) {
      const s = session({ projectRoots: [root] });
      s.taint();
      expect(s.pre('Write', reply)?.permissionDecision, root).toBe('ask');
    }
  });

  it('a file read from an extra root is the operator\'s own data, not outside text', () => {
    expect(session({}).read('/ws/task-7/CLAUDE.md')).toBe(1);
    expect(session({ projectRoots: ['..'] }).read('/ws/task-7/CLAUDE.md')).toBe(0);
  });

  it('loads only bounded string entries', () => {
    const s = session({ projectRoots: ['..', 7, '', 'a\nb', 'x'.repeat(2000), '/srv/qa'] });
    expect(loadPolicy(s.env).projectRoots).toEqual(['..', '/srv/qa']);
  });
});
