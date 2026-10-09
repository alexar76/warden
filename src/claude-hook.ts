import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readdir, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { defaultStateDir, readState, writeState } from './state.js';
import { runScan, parseScanArgs, type ScanReport, type ScanDeps } from './scan.js';
import { displaySafe } from './sanitize.js';

/**
 * Claude Code hooks.
 *
 * `hook session-start` scans the MCP servers Claude Code starts for this project
 * (project `.mcp.json`, and the user's and this project's entries in
 * `~/.claude.json`), records the verdicts for the session, and tells both the
 * user and the model which servers were blocked — by server name, finding code
 * and tool name only. A blocked tool's description is never echoed into the
 * model's context: that text is the attack.
 *
 * `hook pre-tool-use` denies a call to an `mcp__<server>__<tool>` tool when the
 * session-start scan blocked that server or that tool. It reads one small file
 * and starts nothing, so it adds no network or process cost to a tool call.
 *
 * What this does not do: catch a server that changes its tools after the
 * session started (use `warden-mcp wrap` for that — it re-checks before every
 * call), or vet servers that plugins and claude.ai connectors provide (they are
 * not in these files; calls to them get no decision unless WARDEN_HOOK_STRICT=1,
 * which asks the user instead).
 */
export const SESSION_TTL_MS = 14 * 24 * 3600 * 1000;
const STDIN_BYTES = 1_048_576;

export interface SessionVerdicts {
  version: 1;
  scannedAt: string;
  cwd: string;
  servers: Array<{ key: string; normalized: string; allow: boolean | null; status: string; codes: string[]; blockedTools: string[] }>;
}

/** Claude Code's form of a server or tool name inside `mcp__<server>__<tool>`. */
export function normalizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, '_');
}

/** A tool or server name safe to place in the model's context: short, plain, or withheld. */
export function contextSafeName(name: string): string {
  return /^[A-Za-z0-9_.:-]{1,64}$/.test(name) ? name : '(name withheld)';
}

export function sessionPath(stateDir: string, sessionId: string): string {
  return join(stateDir, 'claude-code', 'sessions', createHash('sha256').update(sessionId).digest('hex') + '.json');
}

async function readStdinJson(): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    total += (chunk as Buffer).length;
    if (total > STDIN_BYTES) throw new Error('hook input too large');
    chunks.push(chunk as Buffer);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('hook input is not an object');
  return value as Record<string, unknown>;
}

async function pruneOld(dir: string, now: number): Promise<void> {
  let names: string[];
  try { names = await readdir(dir); } catch { return; }
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    try { if (now - (await stat(join(dir, name))).mtimeMs > SESSION_TTL_MS) await unlink(join(dir, name)); } catch { /* raced */ }
  }
}

export function verdictsFrom(report: ScanReport, cwd: string): SessionVerdicts {
  return {
    version: 1, scannedAt: report.scannedAt, cwd,
    servers: report.servers.map(s => ({
      key: s.key, normalized: normalizeName(s.key), allow: s.allow, status: s.status,
      codes: [...new Set(s.findings.filter(f => !f.advisory).map(f => f.code))],
      blockedTools: s.blockedTools,
    })),
  };
}

export function sessionStartOutput(report: ScanReport): object | undefined {
  const blocked = report.servers.filter(s => s.allow === false);
  const unchecked = report.servers.filter(s => s.status === 'error');
  const partial = report.servers.filter(s => s.allow !== false && s.blockedTools.length);
  const n = report.summary.servers;
  if (!n) return undefined;
  const lines: string[] = [];
  for (const s of blocked) {
    const codes = [...new Set(s.findings.filter(f => !f.advisory).map(f => f.code))].slice(0, 6).join(', ');
    lines.push(`- MCP server "${contextSafeName(s.key)}" is BLOCKED by WARDEN (${codes}). Do not use its tools; calls to them will be denied. Tell the user if their task needs it.`);
  }
  for (const s of partial) {
    lines.push(`- MCP server "${contextSafeName(s.key)}": tools ${s.blockedTools.slice(0, 10).map(t => `"${contextSafeName(t)}"`).join(', ')} are blocked by WARDEN; calls to them will be denied.`);
  }
  const user = `WARDEN vetted ${n} MCP server${n === 1 ? '' : 's'}: ${blocked.length} blocked` +
    (partial.length ? `, ${partial.length} with blocked tools` : '') + (unchecked.length ? `, ${unchecked.length} could not be checked` : '') +
    (blocked.length ? ` (${blocked.map(s => displaySafe(s.key, 40)).join(', ')}). Run: warden-mcp scan` : '.');
  const out: Record<string, unknown> = { systemMessage: user };
  if (lines.length) out.hookSpecificOutput = { hookEventName: 'SessionStart', additionalContext: `WARDEN (MCP firewall) session check:\n${lines.join('\n')}` };
  return out;
}

export async function sessionStart(input: Record<string, unknown>, env: NodeJS.ProcessEnv = process.env, deps: ScanDeps = {}): Promise<object | undefined> {
  const sessionId = typeof input.session_id === 'string' ? input.session_id : '';
  const cwd = typeof input.cwd === 'string' && input.cwd ? input.cwd : process.cwd();
  if (!sessionId) throw new Error('hook input has no session_id');
  const stateDir = env.WARDEN_STATE_DIR || defaultStateDir();
  const args = ['--client', 'claude-code', '--cwd', cwd, '--timeout', env.WARDEN_HOOK_TIMEOUT_MS || '20000', '--state-dir', stateDir, '--no-color'];
  if (env.WARDEN_HOOK_NO_LAUNCH === '1') args.push('--no-launch');
  if (existsSync(join(cwd, 'warden.lock.json'))) args.push('--lock', join(cwd, 'warden.lock.json'));
  // Opt-in meaning-based check, configured the same way as for `scan` (key from WARDEN_CLASSIFIER_API_KEY).
  if (env.WARDEN_CLASSIFIER_URL && env.WARDEN_CLASSIFIER_MODEL) args.push('--classifier-url', env.WARDEN_CLASSIFIER_URL, '--classifier-model', env.WARDEN_CLASSIFIER_MODEL);
  if (env.WARDEN_CLASSIFIER_URL && env.WARDEN_CLASSIFIER_BLOCKS === '1') args.push('--classifier-blocks');
  const opts = await parseScanArgs(args, env);
  const report = await runScan(opts, deps);
  const path = sessionPath(stateDir, sessionId);
  await mkdir(join(stateDir, 'claude-code', 'sessions'), { recursive: true, mode: 0o700 });
  await pruneOld(join(stateDir, 'claude-code', 'sessions'), Date.now());
  await writeState(path, verdictsFrom(report, cwd));
  return sessionStartOutput(report);
}

export interface PreToolDecision { permissionDecision: 'deny' | 'ask'; permissionDecisionReason: string }

/** The decision for one tool call, given the session's verdicts. Pure; shared with the plugin's script by test. */
export function decide(toolName: string, verdicts: SessionVerdicts | undefined, strict: boolean): PreToolDecision | undefined {
  if (!toolName.startsWith('mcp__')) return undefined;
  if (!verdicts) return strict ? { permissionDecision: 'ask', permissionDecisionReason: 'WARDEN has no session-start scan for this session.' } : undefined;
  let best: SessionVerdicts['servers'][number] | undefined;
  for (const s of verdicts.servers) {
    if (toolName.startsWith(`mcp__${s.normalized}__`) && (!best || s.normalized.length > best.normalized.length)) best = s;
  }
  if (!best) return strict ? { permissionDecision: 'ask', permissionDecisionReason: 'WARDEN did not vet the MCP server behind this tool (it is not in .mcp.json or ~/.claude.json).' } : undefined;
  const tool = toolName.slice(`mcp__${best.normalized}__`.length);
  if (best.allow === false) {
    return { permissionDecision: 'deny', permissionDecisionReason: `WARDEN blocked MCP server "${contextSafeName(best.key)}" at session start (${best.codes.slice(0, 6).join(', ') || 'see warden-mcp scan'}). Review it with: warden-mcp scan` };
  }
  if (best.blockedTools.some(t => normalizeName(t) === tool)) {
    return { permissionDecision: 'deny', permissionDecisionReason: `WARDEN blocked this tool of MCP server "${contextSafeName(best.key)}" at session start. Review it with: warden-mcp scan` };
  }
  if (best.status === 'error' && strict) return { permissionDecision: 'ask', permissionDecisionReason: `WARDEN could not check MCP server "${contextSafeName(best.key)}" at session start.` };
  return undefined;
}

export async function preToolUse(input: Record<string, unknown>, env: NodeJS.ProcessEnv = process.env): Promise<object | undefined> {
  const toolName = typeof input.tool_name === 'string' ? input.tool_name : '';
  if (!toolName.startsWith('mcp__')) return undefined;
  const sessionId = typeof input.session_id === 'string' ? input.session_id : '';
  const stateDir = env.WARDEN_STATE_DIR || defaultStateDir();
  let verdicts: SessionVerdicts | undefined;
  try { verdicts = sessionId ? await readState<SessionVerdicts>(sessionPath(stateDir, sessionId)) : undefined; } catch { verdicts = undefined; }
  if (verdicts && verdicts.version !== 1) verdicts = undefined;
  const decision = decide(toolName, verdicts, env.WARDEN_HOOK_STRICT === '1');
  return decision ? { hookSpecificOutput: { hookEventName: 'PreToolUse', ...decision } } : undefined;
}

/** `warden-mcp hook session-start|pre-tool-use` reads the hook JSON on stdin. */
export async function runHookCli(argv: string[]): Promise<number> {
  const event = argv[0];
  if (event !== 'session-start' && event !== 'pre-tool-use') {
    process.stderr.write('Usage: warden-mcp hook session-start|pre-tool-use  (Claude Code hook; reads the hook JSON on stdin)\n');
    return 2;
  }
  try {
    const input = await readStdinJson();
    const out = event === 'session-start' ? await sessionStart(input) : await preToolUse(input);
    if (out) process.stdout.write(JSON.stringify(out) + '\n');
    return 0;
  } catch (err) {
    // A failing hook must not break the session: report on stderr, exit 0, no decision.
    process.stderr.write(`warden hook ${event}: ${displaySafe(err instanceof Error ? err.message : String(err), 500)}\n`);
    return 0;
  }
}

