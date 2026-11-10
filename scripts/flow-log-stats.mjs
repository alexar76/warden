#!/usr/bin/env node
// Сводка журнала стража потоков для замера ложных срабатываний на реальной установке.
//
//   node scripts/flow-log-stats.mjs [state-dir] [--since 2026-11-10T00:00:00Z] [--json]
//
// state-dir — WARDEN_STATE_DIR (по умолчанию ~/.local/state/warden). Читает журналы сессий
// <state-dir>/claude-code/flow/*.log и считает: сессии, заражённые сессии (прочитан внешний текст), решения по
// режиму, исходу, причине и инструменту. Для сессий в `audit` показывает, что отклонил бы `deny`: в `deny` отказ —
// и `deny`, и `ask` (нет человека, чтобы ответить). Число всех вызовов инструментов в журнал стража не пишется —
// знаменатель для доли ложных срабатываний берите из журналов прогонов (Multica, CI).
//
// Только чтение; содержимое вызовов в журнале и так не хранится, только инструмент, причина и решение.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function readLogs(stateDir, since) {
  const dir = join(stateDir, 'claude-code', 'flow');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter(n => n.endsWith('.log')).map(name => {
    const events = [];
    for (const line of readFileSync(join(dir, name), 'utf8').split('\n')) {
      if (!line.trim()) continue;
      let e;
      try { e = JSON.parse(line); } catch { continue; }
      if (since && String(e.at ?? '') < since) continue;
      events.push(e);
    }
    return { session: name.slice(0, 12), events };
  }).filter(s => s.events.length);
}

const inc = (o, k) => { o[k] = (o[k] ?? 0) + 1; };

export function stats(sessions) {
  const out = { sessions: sessions.length, tainted: 0, decisions: 0, byMode: {}, byDisposition: {}, byReason: {}, byTool: {},
    auditWouldRefuseInDeny: 0, adapterResolutions: {}, perSession: [] };
  for (const s of sessions) {
    let decisions = 0, refused = 0, wouldRefuse = 0;
    const tainted = s.events.some(e => e.event === 'taint');
    if (tainted) out.tainted++;
    for (const e of s.events) {
      if (e.event === 'pre' && e.decision && e.decision !== 'allow') {
        decisions++; out.decisions++;
        inc(out.byMode, e.mode ?? '?'); inc(out.byDisposition, e.disposition ?? '?');
        inc(out.byReason, e.reason ?? '?'); inc(out.byTool, e.tool ?? '?');
        if (e.disposition === 'refused') refused++;
        if (e.disposition === 'audit_only') { wouldRefuse++; out.auditWouldRefuseInDeny++; }
      }
      // Адаптеры без человека (OpenCode, Codex) пишут, чем стал вопрос: refused или allowed_unattended.
      if ((e.event === 'opencode' || e.event === 'codex') && e.resolution) inc(out.adapterResolutions, `${e.event}:${e.resolution}`);
    }
    out.perSession.push({ session: s.session, tainted, decisions, refused, auditWouldRefuseInDeny: wouldRefuse,
      first: s.events[0]?.at ?? null, last: s.events.at(-1)?.at ?? null });
  }
  return out;
}

function table(obj) {
  return Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, v]) => `  ${String(v).padStart(5)}  ${k}`).join('\n') || '  —';
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const sinceAt = args.indexOf('--since');
  const since = sinceAt >= 0 ? args[sinceAt + 1] : undefined;
  const dir = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--since')
    ?? process.env.WARDEN_STATE_DIR ?? join(process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'warden');
  const s = stats(readLogs(dir, since));
  if (args.includes('--json')) { process.stdout.write(JSON.stringify(s, null, 2) + '\n'); process.exit(0); }
  console.log(`WARDEN flow log: ${dir}${since ? ` since ${since}` : ''}`);
  console.log(`sessions ${s.sessions}, tainted by outside text ${s.tainted}, guard decisions ${s.decisions}`);
  console.log(`audit sessions: ${s.auditWouldRefuseInDeny} decisions would be refused in deny`);
  console.log(`\nby mode\n${table(s.byMode)}\n\nby disposition\n${table(s.byDisposition)}\n\nby reason\n${table(s.byReason)}\n\nby tool\n${table(s.byTool)}`);
  if (Object.keys(s.adapterResolutions).length) console.log(`\nunattended adapters\n${table(s.adapterResolutions)}`);
  console.log('\nper session (tainted, decisions, refused, would refuse in deny)');
  for (const p of s.perSession) console.log(`  ${p.session}  ${p.tainted ? 'T' : '-'}  ${p.decisions}  ${p.refused}  ${p.auditWouldRefuseInDeny}  ${p.first ?? ''}`);
}
