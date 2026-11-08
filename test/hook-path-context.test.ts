import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { codexPost, codexPre } from '../src/flow-guard-codex.js';
import { createWardenPlugin } from '../src/opencode-plugin.js';

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'warden-hook-path-context-')); dirs.push(dir);
  const project = join(dir, 'project'), home = join(dir, 'codex-user-home');
  mkdirSync(project); mkdirSync(home);
  const policy = join(dir, 'policy.json'); writeFileSync(policy, '{}');
  const env: NodeJS.ProcessEnv = { ...process.env, PATH: '/usr/bin:/bin', CODEX_HOME: home,
    WARDEN_STATE_DIR: join(dir, 'state'), WARDEN_FLOW_POLICY: policy,
    WARDEN_FLOW_MODE: '', WARDEN_CODEX_BLOCK: '', WARDEN_OPENCODE_BLOCK: '' };
  for (const name of ['ENV', 'BASH_ENV', 'RIPGREP_CONFIG_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) delete env[name];
  // Generic OAuth-like material: detection must come from the credential path,
  // not a recognizable provider token prefix.
  const token = 'oauth_' + createHash('sha256').update('warden path context fixture').digest('hex');
  return { dir, project, home, env, token };
}

async function openCodeSession(s: ReturnType<typeof fixture>) {
  const hooks = await createWardenPlugin({ env: s.env, block: 'data' })({ directory: s.project });
  const sessionID = 'path-context-root';
  await hooks.event!({ event: { type: 'session.created', properties: { info: { id: sessionID } } } }, {});
  await hooks['tool.execute.after']!({ tool: 'webfetch', sessionID, args: { url: 'https://example.invalid/source' } },
    { output: 'Outside reference material.' });
  return { hooks, sessionID };
}

describe('hook execution path context', () => {
  it('establishes the credential boundary for a custom CODEX_HOME auth read', () => {
    const s = fixture(), auth = join(s.home, 'auth.json');
    writeFileSync(auth, JSON.stringify({ tokens: { access_token: s.token } }));
    const base = { session_id: 'custom-auth-home', cwd: s.project };
    codexPost({ ...base, tool_name: 'Bash', tool_input: { command: 'cat ' + auth },
      tool_response: readFileSync(auth, 'utf8') }, { env: s.env, block: 'data' });
    codexPost({ ...base, tool_name: 'mcp__fetch__fetch', tool_input: { url: 'https://example.invalid/source' },
      tool_response: 'Outside reference material.' }, { env: s.env, block: 'data' });
    const decision = codexPre({ ...base, tool_name: 'mcp__mail__send_email',
      tool_input: { to: 'report@example.invalid', body: 'Public digest.' } }, { env: s.env, block: 'data' }) as
      { hookSpecificOutput?: { permissionDecision: string; permissionDecisionReason: string } } | undefined;
    expect(decision?.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(decision?.hookSpecificOutput?.permissionDecisionReason).toMatch(/credential boundary/i);
  });

  it('refuses a protected plugin write relative to bash.workdir', async () => {
    const s = fixture(), { hooks, sessionID } = await openCodeSession(s);
    await expect(hooks['tool.execute.before']!({ tool: 'bash', sessionID },
      { args: { command: 'printf noop > plugin/warden.js', workdir: join(s.project, '.opencode') } }))
      .rejects.toThrow(/settings/i);
  });

  it('records a relative credential read in bash.workdir before later outbound calls', async () => {
    const s = fixture(), { hooks, sessionID } = await openCodeSession(s);
    const workdir = join(s.dir, '.ssh'); mkdirSync(workdir);
    const auth = join(workdir, 'config'); writeFileSync(auth, JSON.stringify({ access_token: s.token }));
    await hooks['tool.execute.after']!({ tool: 'bash', sessionID, args: { command: 'cat config', workdir } },
      { output: readFileSync(auth, 'utf8') });
    await expect(hooks['tool.execute.before']!({ tool: 'send_report', sessionID },
      { args: { to: 'report@example.invalid', body: 'Public digest.' } }))
      .rejects.toThrow(/credential boundary/i);
  });
});
