import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, references, releasedVersions } from '../scripts/check-doc-versions.mjs';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function repo(files: Record<string, string>, version = '0.25.0'): string {
  const dir = mkdtempSync(join(tmpdir(), 'warden-versions-')); dirs.push(dir);
  mkdirSync(join(dir, 'docs'));
  const all: Record<string, string> = {
    'package.json': JSON.stringify({ version }),
    'CHANGELOG.md': '# Changelog\n\n## Unreleased\n\n## 0.25.0 — 2026-11-10\n\n## 0.24.0 — 2026-11-08 (Codex)\n\n## 0.23.1-dev.20261108 — local\n',
    'README.md': 'npx -y @aimarket/warden@0.25.0 scan\n',
    ...files,
  };
  for (const [name, text] of Object.entries(all)) writeFileSync(join(dir, name), text);
  return dir;
}

describe('version numbers in the docs', () => {
  it('the repository itself passes', () => {
    expect(check()).toEqual([]);
  });

  it('released means a dated CHANGELOG heading without a suffix', () => {
    expect([...releasedVersions('## 0.25.0 — 2026-11-10\n## 0.23.1-dev.1 — local\n## Unreleased\n')]).toEqual(['0.25.0']);
  });

  it('catches a promised version that does not exist (the 0.24.1 that came out as 0.25.0)', () => {
    const base = repo({ 'docs/codex.ru.md': 'Всё это войдёт в `@aimarket/warden@0.24.1`.\n**Статус: в npm начиная с 0.24.1.**\n' });
    expect(check({ base })).toEqual([
      'docs/codex.ru.md:1: 0.24.1 is not a released version (no "## 0.24.1 — " in CHANGELOG)',
      'docs/codex.ru.md:2: 0.24.1 is not a released version (no "## 0.24.1 — " in CHANGELOG)',
    ]);
  });

  it('catches development pins and accepts released and current versions in all five languages', () => {
    expect(check({ base: repo({ 'docs/a.md': 'npx @aimarket/warden@0.23.1-dev.20261108 scan\n' }) })[0]).toMatch(/0\.23\.1-dev\.20261108 is not a released version/);
    const ok = repo({ 'docs/codex.md': 'in npm from 0.24.0', 'docs/codex.es.md': 'en npm desde la 0.24.0', 'docs/codex.fr.md': 'dans npm depuis la 0.24.0',
      'docs/codex.zh.md': '自 0.24.0 起已在 npm', 'docs/b.md': 'Released: npm 0.25.0. Node 22.0.0 and pkg 0.0.1 are not ours.' });
    expect(check({ base: ok })).toEqual([]);
  });

  it('on release, every install pin must be the version being published', () => {
    const stale = repo({ 'README.md': 'npx -y @aimarket/warden@0.24.0 scan\n', '.pre-commit-hooks.yaml': 'entry: npx --yes @aimarket/warden@0.25.0 scan\n' });
    expect(check({ base: stale })).toEqual([]);
    expect(check({ base: stale, release: true })).toEqual(['README.md:1: install pin @aimarket/warden@0.24.0, releasing 0.25.0']);
    expect(check({ base: repo({}, '0.26.0'), release: true })).toContain('package.json 0.26.0 has no "## 0.26.0 — date" heading in CHANGELOG');
  });

  it('finds pins and phrases, not other packages', () => {
    expect(references('npx @aimarket/warden@0.25.0 and @aimarket/warden@0.23.1-dev.1').map(r => r.version + r.suffix)).toEqual(['0.25.0', '0.23.1-dev.1']);
    expect(references('pip install foo==0.1.5; uses Node 22.0.0')).toEqual([]);
  });
});

describe('release pins versus history', () => {
  it('a pinned version in prose is history; in a command or a code block it is an install pin', () => {
    const base = repo({ 'README.md': 'On 2026-11-01, checked with npm `@aimarket/warden@0.24.0`.\n\n```bash\nnpx -y @aimarket/warden@0.24.0 scan\n```\nRun `npx -y @aimarket/warden@0.24.0 scan --project`.\n' });
    expect(check({ base, release: true })).toEqual([
      'README.md:4: install pin @aimarket/warden@0.24.0, releasing 0.25.0',
      'README.md:6: install pin @aimarket/warden@0.24.0, releasing 0.25.0',
    ]);
  });
});
