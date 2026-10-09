import { createHash } from 'node:crypto';
import { relative, isAbsolute, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { displaySafe } from './sanitize.js';
import type { ScanReport, ScanServerResult } from './scan.js';
import type { Severity, ToolDef, WardenFinding } from './types.js';

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Short, fixed descriptions; the finding message carries the specifics. */
export const CODE_TEXT: Record<string, string> = {
  TOOL_DEF_INJECTION: 'Tool definition carries prompt-injection phrasing',
  TOOL_DEF_SECRET_REQUEST: 'Tool definition asks for a private key, seed phrase or SSH key',
  TOOL_DEF_SECRET_HARVEST: 'Tool whose stated job is to read or reveal secrets',
  TOOL_DEF_EXFIL: 'Tool definition instructs sending data to an outside destination',
  TOOL_DEF_HIDDEN_UNICODE: 'Invisible or bidirectional characters in a tool definition',
  TOOL_DEF_BASE64_BLOB: 'Long base64 run in a tool definition',
  TOOL_DEF_DATA_URL: 'data: or javascript: URL in a tool definition',
  TOOL_DEF_CREDENTIAL_PARAM: 'Tool asks for a credential as a parameter',
  TOOL_DEF_ENV_REFERENCE: 'Tool definition refers to environment files or variables',
  TOOL_DEF_SECRET_EXFIL: 'A secret store and a destination named close together',
  TOOL_DEF_IMPERATIVE: 'Prompt-shaped imperative phrasing',
  TOOL_DEF_DRIFT: 'Tool definitions changed since they were approved',
  TOOL_DEF_UNPINNED: 'No approved snapshot of the tool definitions yet',
  TOOL_DEF_UNCANONICAL: 'Tool definitions have no canonical form to pin',
  SERVER_IDENTITY_DRIFT: 'The command or URL behind an approved server changed',
  PIN_FORMAT_UPGRADE_REQUIRED: 'Approval predates extended tool fields; re-approve',
  SERVER_UNDECLARED: 'Server came from a catalog, not from the operator',
  LOCK_MISSING: 'Server is not in the reviewed lock file',
  HISTOR_UNSEEN_TOOLSET: 'HISTOR never observed the tool set this server served',
  HISTOR_OLDER_TOOLSET: 'This server served a tool set HISTOR saw earlier, not the current one',
  GATE_ERROR: 'A WARDEN gate failed to complete',
};

function codeText(code: string): string {
  return CODE_TEXT[code] ?? (code.startsWith('THREAT_') ? 'Matches a known-bad record in the threat feed' : code);
}

/** JSON report without the raw tool definitions (they are in the lock when they matter). */
export function toJson(report: ScanReport): string {
  return JSON.stringify({ ...report, servers: report.servers.map(({ tools: _tools, ...rest }) => rest) }, null, 2);
}

function displayPath(path: string, cwd: string): string {
  const rel = relative(cwd, path);
  if (rel && !rel.startsWith('..') && !isAbsolute(rel)) return rel;
  const home = homedir();
  return path.startsWith(home + sep) ? '~' + path.slice(home.length) : path;
}

function findingLabel(f: WardenFinding): string {
  return `${displaySafe(f.code, 60)}${f.tool ? `(${displaySafe(f.tool, 60)})` : ''}`;
}

/** The terminal table. Every untrusted string goes through displaySafe. */
export function toTable(report: ScanReport, cwd: string, color: boolean): string {
  const c = (code: string, text: string) => color ? `\x1b[${code}m${text}\x1b[0m` : text;
  const lines: string[] = [];
  const r = report.ruleset;
  lines.push(`WARDEN scan ${report.version} · ruleset ${r.version} ${r.digest.slice(0, 19)}… · block at ${report.policy.blockAtSeverity}`);
  if (!report.sources.length) lines.push('No MCP client config found. Pass a file, or run where .mcp.json lives.');
  for (const s of report.sources) lines.push(`  ${s.error ? c('31', 'unreadable') : 'read'} ${displayPath(s.path, cwd)} (${s.client}, ${s.servers} server${s.servers === 1 ? '' : 's'})${s.error ? ': ' + displaySafe(s.error, 200) : ''}`);
  lines.push('');
  const width = Math.min(28, Math.max(6, ...report.servers.map(s => displaySafe(s.key, 28).length)));
  for (const s of report.servers) {
    const mark = s.allow === false ? c('31;1', '✗ BLOCK ') : s.status === 'error' ? c('33', '! error ') : s.status === 'skipped' ? c('2', '- skip  ')
      : s.status === 'launch-only' ? c('36', '~ launch') : c('32', '✓ allow ');
    const name = displaySafe(s.key, 28).padEnd(width);
    let detail: string;
    if (s.status === 'skipped') detail = displaySafe(s.skipped ?? '', 120);
    else if (s.status === 'error') detail = displaySafe(s.error ?? '', 200);
    else {
      const blockingFindings = s.findings.filter(f => !f.advisory && SEVERITY_ORDER.indexOf(f.severity) >= SEVERITY_ORDER.indexOf(report.policy.blockAtSeverity));
      const labels = [...new Set((s.allow === false ? blockingFindings : s.findings.filter(f => !f.advisory)).map(findingLabel))];
      const shown = labels.slice(0, 4);
      const parts: string[] = [];
      if (s.status === 'launch-only') parts.push('not started (--no-launch): launch line vetted only');
      if (s.toolCount !== undefined) parts.push(`${s.toolCount} tool${s.toolCount === 1 ? '' : 's'}`);
      if (s.score !== undefined && s.status === 'scanned') parts.push(`score ${s.score.toFixed(2)}`);
      if (shown.length) parts.push(shown.join(' '));
      const more = labels.length - shown.length;
      if (more > 0) parts.push(`+${more} more`);
      if (s.lock) parts.push(`lock: ${s.lock.state}`);
      if (s.histor) parts.push(`histor: ${displaySafe(s.histor.match ?? (s.histor.notSent ? 'not sent' : 'unavailable'), 40)}`);
      detail = parts.join(' · ');
    }
    lines.push(`  ${mark}  ${name}  ${c('2', s.client.padEnd(14))} ${detail}`);
  }
  const m = report.summary;
  lines.push('');
  lines.push(`${m.servers} server${m.servers === 1 ? '' : 's'}: ${m.allowed} allowed, ${m.blocked} blocked, ${m.errors} not checked, ${m.skipped} skipped${m.launchOnly ? `, ${m.launchOnly} not started` : ''}.`);
  if (report.lock) {
    if (report.lock.written) lines.push(`Lock written: ${displayPath(report.lock.path, cwd)}. Commit it; the diff is the review.`);
    if (report.lock.stale.length) lines.push(`In the lock but not in any config: ${report.lock.stale.map(id => displaySafe(id, 60)).join(', ')}`);
  }
  if (m.blocked) lines.push(`Details: warden-mcp scan --json, or --markdown FILE. To review a changed server: warden-mcp scan --lock warden.lock.json --update-lock.`);
  return lines.join('\n');
}

// ── SARIF 2.1.0 ──────────────────────────────────────────────────────────────

const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

function lineOf(path: string, key: string): number {
  try {
    const text = readFileSync(path, 'utf8');
    const needle = JSON.stringify(key);
    const at = text.indexOf(needle + ':') >= 0 ? text.indexOf(needle + ':') : text.indexOf(needle);
    return at < 0 ? 1 : text.slice(0, at).split('\n').length;
  } catch { return 1; }
}

function artifactUri(path: string, cwd: string): { uri: string; uriBaseId?: string } {
  const rel = relative(cwd, path);
  if (rel && !rel.startsWith('..') && !isAbsolute(rel)) return { uri: rel.split(sep).join('/'), uriBaseId: '%SRCROOT%' };
  return { uri: pathToFileURL(path).href };
}

/**
 * SARIF for GitHub code scanning. Advisory findings are left out on purpose: the
 * Security tab is for things that block, and TOOL_DEF_UNPINNED alone would put a
 * result on every server in every repository.
 */
export function toSarif(report: ScanReport, cwd: string): object {
  const rules = new Map<string, { severity: Severity }>();
  const results: object[] = [];
  for (const s of report.servers) {
    for (const f of s.findings) {
      if (f.advisory) continue;
      const known = rules.get(f.code);
      if (!known || SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(known.severity)) rules.set(f.code, { severity: f.severity });
      const fingerprint = createHash('sha256').update([s.client, s.key, f.code, f.tool ?? '', f.message].join('\u0000')).digest('hex');
      results.push({
        ruleId: f.code,
        level: LEVEL[f.severity],
        message: { text: `${displaySafe(s.key, 120)}: ${displaySafe(f.message, 1500)}` },
        locations: [{ physicalLocation: { artifactLocation: artifactUri(s.source, cwd), region: { startLine: lineOf(s.source, s.key) } } }],
        partialFingerprints: { 'wardenFinding/v1': fingerprint },
        properties: { server: displaySafe(s.key, 200), client: s.client, gate: f.gate, severity: f.severity, ...(f.tool ? { tool: displaySafe(f.tool, 200) } : {}) },
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'WARDEN', semanticVersion: report.version, informationUri: 'https://warden.modelmarket.dev/',
        rules: [...rules.entries()].sort(([a], [b]) => a < b ? -1 : 1).map(([id, r]) => ({
          id, name: id, shortDescription: { text: codeText(id) },
          helpUri: 'https://github.com/alexar76/warden/blob/main/docs/gates.md',
          defaultConfiguration: { level: LEVEL[r.severity] },
          properties: { tags: ['security', 'mcp', 'prompt-injection'], 'security-severity': SECURITY_SEVERITY[r.severity] },
        })),
      } },
      results,
      properties: { ruleset: report.ruleset, blockAtSeverity: report.policy.blockAtSeverity },
    }],
  };
}

// ── Markdown (GitHub step summary, PR comment) ───────────────────────────────

/** Inline code that untrusted text cannot break out of. */
export function mdCode(text: string, max = 80): string {
  const t = displaySafe(text, max).replace(/[\r\n]+/g, ' ').replace(/\|/g, '¦');
  const run = Math.max(0, ...[...t.matchAll(/`+/g)].map(m => m[0].length));
  const fence = '`'.repeat(run + 1);
  return `${fence}${run ? ' ' : ''}${t}${run ? ' ' : ''}${fence}`;
}

/** A fenced block that untrusted text cannot close. */
export function mdBlock(text: string, lang = ''): string {
  const run = Math.max(2, ...[...text.matchAll(/`+/g)].map(m => m[0].length));
  const fence = '`'.repeat(run + 1);
  return `${fence}${lang}\n${text}\n${fence}`;
}

function toolText(t: ToolDef | undefined): string[] {
  if (!t) return [];
  const lines = [`name: ${t.name}`];
  if (t.title) lines.push(`title: ${t.title}`);
  for (const l of String(t.description ?? '').split(/\r?\n/)) lines.push(`description: ${l}`);
  lines.push(`inputSchema: ${JSON.stringify(t.inputSchema ?? {})}`);
  for (const k of Object.keys(t).filter(k => !['name', 'title', 'description', 'inputSchema'].includes(k)).sort()) lines.push(`${k}: ${JSON.stringify(t[k])}`);
  return lines.map(l => displaySafe(l, 4000));
}

/** Line diff, small and dependency-free: common prefix/suffix, then the middle as -/+. */
export function lineDiff(before: string[], after: string[]): string[] {
  let start = 0;
  while (start < before.length && start < after.length && before[start] === after[start]) start++;
  let endA = before.length, endB = after.length;
  while (endA > start && endB > start && before[endA - 1] === after[endB - 1]) { endA--; endB--; }
  return [
    ...before.slice(Math.max(0, start - 1), start).map(l => '  ' + l),
    ...before.slice(start, endA).map(l => '- ' + l),
    ...after.slice(start, endB).map(l => '+ ' + l),
    ...after.slice(endB, endB + 1).map(l => '  ' + l),
  ];
}

export function toMarkdown(report: ScanReport, cwd: string): string {
  const m = report.summary;
  const out: string[] = [];
  out.push(`## WARDEN · MCP server scan`);
  out.push('');
  out.push(`${m.blocked ? '❌' : '✅'} **${m.blocked} blocked**, ${m.allowed} allowed, ${m.errors} not checked, ${m.skipped} skipped${m.launchOnly ? `, ${m.launchOnly} not started` : ''} · ruleset ${mdCode(report.ruleset.version)} · block at ${mdCode(report.policy.blockAtSeverity)}`);
  out.push('');
  if (!report.servers.length) { out.push('No MCP servers found in the scanned config files.'); return out.join('\n') + '\n'; }
  out.push('| | Server | Config | Tools | Findings | Lock |');
  out.push('|---|---|---|---|---|---|');
  for (const s of report.servers) {
    const mark = s.allow === false ? '❌' : s.status === 'error' ? '⚠️' : s.status === 'skipped' ? '➖' : s.status === 'launch-only' ? '🔸' : '✅';
    const findings = s.status === 'error' ? `not checked: ${mdCode(s.error ?? '', 100)}`
      : s.status === 'skipped' ? mdCode(s.skipped ?? '', 80)
      : [...new Set(s.findings.filter(f => !f.advisory).map(f => f.code + (f.tool ? `(${f.tool})` : '')))].slice(0, 5).map(l => mdCode(l, 70)).join(' ') || (s.status === 'launch-only' ? 'launch line only (not started)' : '—');
    out.push(`| ${mark} | ${mdCode(s.key, 50)} | ${mdCode(displayPath(s.source, cwd), 60)} | ${s.toolCount ?? '—'} | ${findings} | ${s.lock ? mdCode(s.lock.state) : '—'} |`);
  }
  const blocked = report.servers.filter(s => s.allow === false);
  for (const s of blocked) {
    out.push('');
    out.push(`<details><summary>❌ ${mdCode(s.key, 60)} — why it was blocked</summary>`);
    out.push('');
    out.push(mdBlock(s.findings.filter(f => !f.advisory).map(f => `[${f.severity}] ${f.code}${f.tool ? ` (${f.tool})` : ''}: ${f.message}`).map(l => displaySafe(l, 1500)).join('\n')));
    out.push('');
    out.push('</details>');
  }
  const changed = report.servers.filter(s => s.lock?.changes?.length);
  for (const s of changed) {
    out.push('');
    out.push(`<details${s.lock!.state === 'drift' || s.lock!.state === 'missing' ? ' open' : ''}><summary>${s.lock!.state === 'missing' ? 'New server' : 'Changed tool definitions'}: ${mdCode(s.key, 60)} (${s.lock!.changes!.length} tool${s.lock!.changes!.length === 1 ? '' : 's'})</summary>`);
    out.push('');
    const diff: string[] = [];
    for (const ch of s.lock!.changes!.slice(0, 40)) {
      diff.push(`@@ ${ch.kind} ${displaySafe(ch.tool, 120)} @@`);
      diff.push(...lineDiff(toolText(ch.before), toolText(ch.after)));
    }
    if (s.lock!.changes!.length > 40) diff.push(`… ${s.lock!.changes!.length - 40} more tools`);
    out.push(mdBlock(diff.join('\n').slice(0, 60_000), 'diff'));
    out.push('');
    out.push('</details>');
  }
  if (report.lock?.stale.length) {
    out.push('');
    out.push(`In the lock but no longer in any config: ${report.lock.stale.map(id => mdCode(id, 60)).join(', ')}`);
  }
  out.push('');
  out.push(`<sub>@aimarket/warden ${displaySafe(report.version, 20)} · ${mdCode(report.ruleset.digest, 60)} · tool descriptions are shown as code; they are untrusted text from the servers.</sub>`);
  return out.join('\n') + '\n';
}
