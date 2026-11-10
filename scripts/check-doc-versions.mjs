#!/usr/bin/env node
// Номера версий в документации — только проверенные.
//
//   node scripts/check-doc-versions.mjs            всегда (в тестах): документация не ссылается на невыпущенную версию
//   node scripts/check-doc-versions.mjs --release  при публикации: все закрепления для установки = версии из package.json
//
// «Выпущенная» — версия с заголовком `## X.Y.Z — дата` в CHANGELOG (без -dev и прочих суффиксов). Ссылка на версию —
// `@aimarket/warden@X.Y.Z` или номер вида 0.Y.Z рядом со словом npm / WARDEN. До выпуска пишите «в следующем
// выпуске», а не номер: так мы однажды пообещали `0.24.1`, а вышла `0.25.0`.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Файлы, где закреплена версия для установки; при выпуске все закрепления в них = версии пакета. */
export const PIN_FILES = ['README.md', 'README-ru.md', 'README-es.md', 'README-fr.md', 'README-zh.md', '.pre-commit-hooks.yaml',
  'action.yml', 'claude-plugin/hooks/hooks.json', 'claude-plugin/skills/scan/SKILL.md', 'claude-plugin/.claude-plugin/plugin.json',
  'server.json', 'docs/teams.md', 'examples/github-org/.github/workflows/mcp-servers.yml', 'examples/scan-demo/README.md',
  ...['', '.ru', '.es', '.fr', '.zh'].flatMap(l => [`docs/flow-guard${l}.md`, `docs/scan${l}.md`])];

export function releasedVersions(changelog) {
  return new Set([...changelog.matchAll(/^## (\d+\.\d+\.\d+) — /gm)].map(m => m[1]));
}

/** Документы, в которых номер версии — обещание читателю: README, docs/*.md, примеры. */
export function docFiles(base = root) {
  const out = readdirSync(base).filter(n => /^README.*\.md$|^GOVERNANCE\.md$|^SECURITY\.md$/.test(n));
  out.push(...readdirSync(join(base, 'docs')).filter(n => n.endsWith('.md')).map(n => `docs/${n}`));
  for (const ex of ['examples/scan-demo/README.md']) if (existsSync(join(base, ex))) out.push(ex);
  return out;
}

const PIN = /@aimarket\/warden@(\d+\.\d+\.\d+)([A-Za-z0-9.+-]*)/g;
// Фразы о статусе выпуска на пяти языках документации: «in npm from 0.24.0», «в npm начиная с 0.24.0»,
// «en npm desde la 0.24.0», «dans npm depuis la 0.24.0», «自 0.24.0 起已在 npm», «npm 0.24.0», «Released: npm 0.24.0».
const NEAR_NPM = /\bnpm\s+(?:from|начиная с|desde(?: la)?|depuis(?: la)?)\s+`?(\d+\.\d+\.\d+)\b|\bnpm\s+`?(\d+\.\d+\.\d+)`?(?![\d.])|自\s*(\d+\.\d+\.\d+)\s*起已在\s*npm/g;

/** Ссылки на версии в тексте: [версия, суффикс, строка]. */
export function references(text) {
  const refs = [];
  text.split('\n').forEach((line, i) => {
    for (const m of line.matchAll(PIN)) refs.push({ version: m[1], suffix: m[2], line: i + 1, pin: true });
    for (const m of line.matchAll(NEAR_NPM)) refs.push({ version: m[1] ?? m[2] ?? m[3], suffix: '', line: i + 1, pin: false });
  });
  return refs;
}

/**
 * Строки, где закрепление — инструкция по установке: в блоке кода или в команде (`npx`, `npm i`, `entry:`, `"args"`,
 * `version:`). Закрепление в обычном тексте — история («1 ноября проверено на 0.22.2»), его выпуск не меняет.
 * В файлах настроек (yaml, json) — все строки.
 */
export function installLines(text, wholeFile = false) {
  const out = new Set();
  let fenced = false;
  text.split('\n').forEach((line, i) => {
    if (/^\s*```/.test(line)) { fenced = !fenced; out.add(i + 1); return; }
    if (wholeFile || fenced || /\bnpx\b|\bnpm (?:i|install)\b|\bentry:|"args"|^\s*version:/.test(line)) out.add(i + 1);
  });
  return out;
}

export function check({ base = root, release = false } = {}) {
  const released = releasedVersions(readFileSync(join(base, 'CHANGELOG.md'), 'utf8'));
  const version = JSON.parse(readFileSync(join(base, 'package.json'), 'utf8')).version;
  const problems = [];
  for (const file of docFiles(base)) {
    for (const r of references(readFileSync(join(base, file), 'utf8'))) {
      if (r.suffix) problems.push(`${file}:${r.line}: @aimarket/warden@${r.version}${r.suffix} is not a released version`);
      else if (!released.has(r.version) && r.version !== version) problems.push(`${file}:${r.line}: ${r.version} is not a released version (no "## ${r.version} — " in CHANGELOG)`);
    }
  }
  if (release) {
    if (!released.has(version)) problems.push(`package.json ${version} has no "## ${version} — date" heading in CHANGELOG`);
    for (const file of PIN_FILES.filter(f => existsSync(join(base, f)))) {
      const text = readFileSync(join(base, file), 'utf8');
      const lines = installLines(text, !file.endsWith('.md'));
      for (const r of references(text).filter(r => r.pin && lines.has(r.line))) {
        if (r.version + r.suffix !== version) problems.push(`${file}:${r.line}: install pin @aimarket/warden@${r.version}${r.suffix}, releasing ${version}`);
      }
    }
  }
  return problems.map(p => p.replace(base + '/', ''));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const release = process.argv.includes('--release');
  const problems = check({ release });
  for (const p of problems) console.error(p);
  console.log(problems.length ? `${problems.length} version reference problem(s)` : `version references OK${release ? ' for release' : ''}`);
  process.exit(problems.length ? 1 : 0);
}
