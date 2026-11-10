import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { flowPre } from '../src/flow-guard.js';
import { preToolUse, withDenyMode } from '../src/claude-hook.js';

// TONM-14: with `"mode": "deny"` a call that touches WARDEN's or Claude Code's own settings still got `ask` while the
// session was clean. Under `claude -p` or a skip-permissions daemon nobody answers, so `deny` must never ask.
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function env(mode: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const dir = mkdtempSync(join(tmpdir(), 'warden-deny-')); dirs.push(dir);
  const policy = join(dir, 'policy.json'); writeFileSync(policy, JSON.stringify({ mode }));
  const e: NodeJS.ProcessEnv = { ...process.env, WARDEN_STATE_DIR: join(dir, 'state'), WARDEN_FLOW_POLICY: policy, WARDEN_FLOW_MODE: '', WARDEN_HOOK_STRICT: '', ...extra };
  for (const k of ['ENV', 'BASH_ENV', 'RIPGREP_CONFIG_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) delete e[k];
  return e;
}

const call = (tool_name: string, tool_input: Record<string, unknown>) => ({ session_id: 'deny-mode', cwd: '/work/proj', tool_name, tool_input });
const settingsWrite = call('Write', { file_path: '/work/proj/.claude/settings.json', content: '{"hooks":{}}' });
const gitHook = call('Edit', { file_path: '/work/proj/.git/hooks/pre-commit', old_string: 'a', new_string: 'b' });

describe('mode deny never asks', () => {
  it('refuses a change to protected settings in a clean session', () => {
    expect(flowPre(settingsWrite, env('deny'))?.permissionDecision).toBe('deny');
    expect(flowPre(gitHook, env('deny'))?.permissionDecision).toBe('deny');
  });

  it('keeps the question in mode ask, and stays silent in audit and off', () => {
    expect(flowPre(settingsWrite, env('ask'))?.permissionDecision).toBe('ask');
    expect(flowPre(settingsWrite, env('audit'))).toBeUndefined();
    expect(flowPre(settingsWrite, env('off'))).toBeUndefined();
  });

  it('turns the MCP scan\'s strict questions into refusals', async () => {
    const strictDeny = env('deny', { WARDEN_HOOK_STRICT: '1' });
    const out = await preToolUse(call('mcp__unknown__do', {}), strictDeny) as { hookSpecificOutput: { permissionDecision: string } };
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    const strictAsk = env('ask', { WARDEN_HOOK_STRICT: '1' });
    expect((await preToolUse(call('mcp__unknown__do', {}), strictAsk) as typeof out).hookSpecificOutput.permissionDecision).toBe('ask');
    expect(withDenyMode({ permissionDecision: 'ask', permissionDecisionReason: 'x' }, strictDeny)?.permissionDecision).toBe('deny');
    expect(withDenyMode(undefined, strictDeny)).toBeUndefined();
  });

  it('the plugin scripts agree: flow-pre and the MCP pre-tool-use hook print deny', () => {
    const run = (script: string, body: object, e: NodeJS.ProcessEnv) =>
      execFileSync(process.execPath, [join(root, 'claude-plugin/scripts', script)], { input: JSON.stringify(body), env: e }).toString().trim();
    const e = env('deny', { WARDEN_HOOK_STRICT: '1' });
    expect(JSON.parse(run('flow-pre.mjs', settingsWrite, e)).hookSpecificOutput.permissionDecision).toBe('deny');
    expect(JSON.parse(run('pre-tool-use.mjs', call('mcp__unknown__do', {}), e)).hookSpecificOutput.permissionDecision).toBe('deny');
    expect(JSON.parse(run('pre-tool-use.mjs', call('mcp__unknown__do', {}), env('ask', { WARDEN_HOOK_STRICT: '1' }))).hookSpecificOutput.permissionDecision).toBe('ask');
  });
});

describe('the plugin\'s flow-pre entry fails closed in mode deny', () => {
  // A copy of the entry script without the guard parts next to it: the import fails.
  function lone(): string {
    const dir = mkdtempSync(join(tmpdir(), 'warden-lone-')); dirs.push(dir);
    writeFileSync(join(dir, 'flow-pre.mjs'), readFileSync(join(root, 'claude-plugin/scripts/flow-pre.mjs')));
    return join(dir, 'flow-pre.mjs');
  }
  const run = (script: string, e: NodeJS.ProcessEnv) =>
    execFileSync(process.execPath, [script], { input: JSON.stringify(call('Bash', { command: 'ls' })), env: e, stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim();

  it('refuses when the guard cannot load and the policy is deny', () => {
    expect(JSON.parse(run(lone(), env('deny'))).hookSpecificOutput.permissionDecision).toBe('deny');
    expect(JSON.parse(run(lone(), env('ask', { WARDEN_FLOW_MODE: 'deny' }))).hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('decides nothing for a person at the keyboard (ask, audit, off)', () => {
    for (const mode of ['ask', 'audit', 'off']) expect(run(lone(), env(mode))).toBe('');
  });
});
