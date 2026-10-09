import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = join(root, 'test/fixtures/wrap-server.mjs');
const dirs: string[] = [];
beforeAll(() => { execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'], { cwd: root }); }, 30_000);
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function runAction(project: string, inputs: Record<string, string>) {
  const runner = mkdtempSync(join(tmpdir(), 'warden-runner-')); dirs.push(runner);
  const out = join(runner, 'output'), summary = join(runner, 'summary');
  writeFileSync(out, ''); writeFileSync(summary, '');
  const env = { PATH: process.env.PATH!, HOME: runner, RUNNER_TEMP: runner, GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: summary,
    GITHUB_ACTION_PATH: root, WARDEN_BIN: join(root, 'dist/mcp-server.js'), WARDEN_STATE_DIR: join(runner, 'state'),
    WARDEN_VERSION: '0.9.0', WARDEN_LOCK: 'warden.lock.json', WARDEN_LAUNCH_STDIO: 'false', WARDEN_PUBLIC_ONLY: 'true',
    WARDEN_FAIL_ON: 'high', WARDEN_HISTOR: 'false', WARDEN_SARIF: 'warden.sarif', WARDEN_CONFIG: '', ...inputs };
  const r = spawnSync('bash', [join(root, 'action/run.sh')], { cwd: project, env, encoding: 'utf8' });
  const outputs = Object.fromEntries(readFileSync(out, 'utf8').trim().split('\n').filter(Boolean).map(l => l.split(/=(.*)/s).slice(0, 2)));
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, outputs, summary: readFileSync(summary, 'utf8') };
}

function project(servers: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), 'warden-action-')); dirs.push(dir);
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));
  return dir;
}

describe('GitHub Action step', () => {
  it('on a pull request: starts nothing, vets launch lines, writes SARIF, summary and outputs', () => {
    const dir = project({ notes: { command: process.execPath, args: [fixture], env: { WARDEN_FIXTURE_PID: 'started.pid' } }, rm: { command: 'sh', args: ['-c', 'rm -rf /'] } });
    const r = runAction(dir, {});
    expect(r.code).toBe(1);
    expect(existsSync(join(dir, 'started.pid'))).toBe(false);
    expect(r.outputs).toMatchObject({ blocked: '1', servers: '2', sarif: 'warden.sarif' });
    expect(r.summary).toContain('WARDEN · MCP server scan');
    expect(JSON.parse(readFileSync(join(dir, 'warden.sarif'), 'utf8')).version).toBe('2.1.0');
    expect(r.stdout).toContain('::error title=WARDEN::1 MCP server(s) blocked');
  });

  it('with the lock committed and stdio allowed, a clean project passes', () => {
    const dir = project({ notes: { command: process.execPath, args: [fixture] } });
    execFileSync(process.execPath, [join(root, 'dist/mcp-server.js'), 'scan', '--project', '--lock', 'warden.lock.json', '--update-lock', '--state-dir', join(dir, 's')], { cwd: dir });
    const r = runAction(dir, { WARDEN_LAUNCH_STDIO: 'true' });
    expect(r.code).toBe(0);
    expect(r.outputs.blocked).toBe('0');
    expect(r.summary).toContain('**0 blocked**');
  });

  it('rejects inputs that are not what they claim to be, before running anything', () => {
    const dir = project({});
    expect(runAction(dir, { WARDEN_VERSION: '0.9.0; rm -rf /' }).code).toBe(2);
    expect(runAction(dir, { WARDEN_FAIL_ON: 'whatever' }).code).toBe(2);
  });

  it('takes explicit config files one per line, names with spaces included', () => {
    const dir = project({});
    writeFileSync(join(dir, 'my config.json'), JSON.stringify({ mcpServers: { off: { command: 'x', disabled: true } } }));
    const r = runAction(dir, { WARDEN_CONFIG: '  my config.json  \n' });
    expect(r.code).toBe(0);
    expect(r.outputs.servers).toBe('1');
  });
});

describe('integrations name the version they ship with', () => {
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version as string;
  it('action.yml defaults to this version and pins third-party actions by commit', () => {
    const action = readFileSync(join(root, 'action.yml'), 'utf8');
    expect(action).toMatch(new RegExp(`version:[\\s\\S]*?default: ${version.replace(/\./g, '\\.')}\\n`));
    for (const m of action.matchAll(/uses:\s*(\S+)/g)) expect(m[1], m[1]).toMatch(/@[0-9a-f]{40}$/);
    for (const m of action.matchAll(/^\s*run:(.*)$/gm)) expect(m[1], 'a run: line').not.toContain('${{');   // inputs reach the script as env only
    expect(action).toContain('run: bash "$GITHUB_ACTION_PATH/action/run.sh"');
  });
  it('pre-commit hooks run this version and match the config files they claim to', () => {
    const hooks = readFileSync(join(root, '.pre-commit-hooks.yaml'), 'utf8');
    expect(hooks.match(/@aimarket\/warden@[\d.]+/g)!.every(v => v === `@aimarket/warden@${version}`)).toBe(true);
    const files = new RegExp(/files: (.+)\n/.exec(hooks)![1]!);
    for (const f of ['.mcp.json', 'sub/.cursor/mcp.json', '.vscode/mcp.json', 'claude_desktop_config.json', 'x/mcp_config.json']) expect(files.test(f), f).toBe(true);
    for (const f of ['package.json', 'mcp.jsonc', 'notmcp.json']) expect(files.test(f), f).toBe(false);
  });
});
