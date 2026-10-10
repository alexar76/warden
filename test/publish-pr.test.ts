import { fileURLToPath } from 'node:url';
import { it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

it('Gitea PR mode retains gates, preserves the base branch and encodes a body file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'warden-pr-script-'));
  try {
    const scripts = join(dir, 'scripts'), bin = join(dir, 'bin'), trace = join(dir, 'trace');
    mkdirSync(scripts); mkdirSync(bin);
    const source = resolve(fileURLToPath(new URL(".", import.meta.url)), '../../scripts');
    if (!existsSync(join(source, 'push_gitea_monorepo.sh'))) return;
    for (const file of ['push_gitea_monorepo.sh', 'sanitize_git_commit_meta.py']) copyFileSync(join(source, file), join(scripts, file));
    writeFileSync(join(scripts, 'verify_whitepaper_links.sh'), '#!/bin/bash\nexit 0\n', { mode: 0o755 });
    writeFileSync(join(bin, 'git'), `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2); fs.appendFileSync(process.env.TRACE, JSON.stringify(args)+'\\n');
if (args[0] === 'branch') console.log('main');
if (args[0] === 'rev-parse' || args[0] === 'rev-list') console.log('a'.repeat(40));
if (args[0] === 'log' && args.some(a => a.includes('%an'))) console.log('a'.repeat(40)+'\\taleksandr.artamokhov\\talexar76@rambler.ru');
else if (args[0] === 'log') console.log('Add WARDEN wrap proxy');
`, { mode: 0o755 });
    const body = join(dir, 'body.md'); writeFileSync(body, 'Summary\n\nLiteral `code` and $(not-a-command).\n');
    const cmd = join(scripts, 'push_gitea_monorepo.sh');
    const args = ['--branch', 'codex/warden-wrap', '--pr', 'main', '--title', 'WARDEN wrap', '--body-file', body];
    const env = { ...process.env, PATH: bin + ':' + process.env.PATH, TRACE: trace, GITEA_TOKEN: '', SKIP_AUTHOR_GATE: '', SKIP_TRAILER_GATE: '', SKIP_LINK_GATE: '' };
    execFileSync('bash', [cmd, ...args, '--dry-run'], { env });
    expect(readFileSync(trace, 'utf8')).not.toContain('"push"');
    writeFileSync(trace, '');
    const output = execFileSync('bash', [cmd, ...args], { env, encoding: 'utf8' });
    expect(output).toContain('author gate clean'); expect(output).toContain('Co-authored-by gate clean'); expect(output).toContain('satellite link gate clean');
    const commands = readFileSync(trace, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    const push = commands.filter(c => c[0] === 'push');
    expect(push).toEqual([['push', 'ssh://git@gitea2/alexar76/aicom.git', 'codex/warden-wrap:refs/for/main/codex/warden-wrap', '-o', 'title=WARDEN wrap', '-o', 'description=Summary\\n\\nLiteral `code` and $(not-a-command).\\n']]);
    expect(commands.some(c => c[0] === 'fetch')).toBe(false);
    const invalid = spawnSync('bash', [cmd, '--pr', 'main'], { env, encoding: 'utf8' });
    expect(invalid.status).toBe(2); expect(invalid.stderr).toContain('--body-file');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
