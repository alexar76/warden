import { readFile } from 'node:fs/promises';
import { createHash, createPublicKey } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { join } from 'node:path';
import { asPolicy } from './mcp-tools.js';
import { defaultStateDir, readState, withStateLock, writeState } from './state.js';
import { FilePinStore, pinRevision } from './pin-store.js';
import { Warden, ThreatFeed, canonicalToolsHash, serverIdentityHash, displaySafe } from './index.js';
import { observationPath, observationRevision, describeReview } from './wrap-state.js';
import type { Observation } from './wrap-state.js';
import type { McpServerRef, WardenLogger, WardenPolicy } from './types.js';

export interface WrapOptions {
  mode: 'wrap' | 'pins'; action?: string; id?: string; command?: string; args: string[];
  stateDir: string; policy: WardenPolicy; feed?: string; feedKey?: string; verdictLog?: string; auditOnly: boolean;
}
export async function parseWrapArgs(argv: string[]): Promise<WrapOptions> {
  const mode = argv.shift();
  if (mode !== 'wrap' && mode !== 'pins') throw new Error('Usage: warden-mcp wrap [flags] -- command [args] | pins status|approve|revoke --id ID');
  const opts: WrapOptions = { mode, args: [], stateDir: defaultStateDir(), policy: asPolicy(undefined), auditOnly: false };
  if (mode === 'pins') {
    opts.action = argv.shift();
    if (!['status', 'approve', 'revoke'].includes(opts.action ?? '')) throw new Error('pins requires status, approve or revoke');
  }
  const seen = new Set<string>();
  while (argv.length) {
    const flag = argv.shift()!;
    if (flag === '--' && mode === 'wrap') { opts.command = argv.shift(); opts.args = argv; break; }
    if (seen.has(flag)) throw new Error(`Duplicate flag ${flag}`);
    seen.add(flag);
    if (flag === '--audit-only' && mode === 'wrap') { opts.auditOnly = true; continue; }
    const allowed = mode === 'wrap' ? ['--id', '--state-dir', '--policy', '--feed', '--feed-key', '--verdict-log'] : ['--id', '--state-dir', '--feed', '--feed-key'];
    if (!allowed.includes(flag)) throw new Error(`Unknown flag ${flag}`);
    const value = argv.shift();
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`);
    switch (flag) {
      case '--id':
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(value)) throw new Error('--id must be a slug (1–128 letters, digits, ., _ or -)');
        opts.id = value; break;
      case '--state-dir': opts.stateDir = value; break;
      case '--feed': opts.feed = value; break;
      case '--feed-key': opts.feedKey = value; break;
      case '--verdict-log': opts.verdictLog = value; break;
      case '--policy': {
        const raw = JSON.parse(await readFile(value, 'utf8'));
        // asPolicy preserves compatibility for MCP callers; CLI files must not silently repair bad types.
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('policy must be an object');
        for (const key of Object.keys(raw)) if (!['blockAtSeverity', 'pinToolDefs', 'allowUnknownServers', 'sensitiveToolPatterns'].includes(key)) throw new Error(`Unknown policy field ${key}`);
        for (const key of ['pinToolDefs', 'allowUnknownServers']) if (key in raw && typeof raw[key] !== 'boolean') throw new Error(`policy.${key} must be boolean`);
        if ('blockAtSeverity' in raw && typeof raw.blockAtSeverity !== 'string') throw new Error('policy.blockAtSeverity must be a severity');
        if ('sensitiveToolPatterns' in raw && (!Array.isArray(raw.sensitiveToolPatterns) || !raw.sensitiveToolPatterns.every((v: unknown) => typeof v === 'string'))) throw new Error('policy.sensitiveToolPatterns must be strings');
        opts.policy = asPolicy(raw); break;
      }
    }
  }
  if (mode === 'wrap' && !opts.command) throw new Error('wrap requires -- command [args]');
  if (mode === 'pins' && !opts.id) throw new Error('pins requires --id');
  if (opts.feed) {
    const url = new URL(opts.feed);
    if (!['https:', 'http:'].includes(url.protocol)) throw new Error('--feed requires an HTTP(S) URL');
  }
  if (opts.feedKey) {
    if (!/^(?:[a-fA-F0-9]{2})+$/.test(opts.feedKey) || createPublicKey({ key: Buffer.from(opts.feedKey, 'hex'), format: 'der', type: 'spki' }).asymmetricKeyType !== 'ed25519') throw new Error('--feed-key must be an Ed25519 SPKI DER hex key');
  }
  return opts;
}
export function wrapServer(opts: WrapOptions): McpServerRef {
  const id = opts.id ?? createHash('sha256').update(JSON.stringify([opts.command, opts.args])).digest('hex');
  return { id, name: id, transport: 'stdio', command: opts.command!, args: opts.args };
}
export function wrapLogger(auditOnly = false): WardenLogger {
  const write = (message: string) => process.stderr.write(`warden: ${auditOnly ? 'AUDIT-ONLY ' : ''}${displaySafe(message, 8192)}\n`);
  const logger: WardenLogger = { debug: () => {}, info: () => {}, warn: write, error: write, child: () => logger };
  return logger;
}
export async function loadWrapFeed(opts: WrapOptions): Promise<ThreatFeed> {
  const log = wrapLogger(opts.auditOnly);
  const feed = new ThreatFeed({ feedPublicKey: opts.feedKey, stateDir: opts.stateDir, log });
  await feed.load(opts.feed);
  if (opts.feed && feed.status.stale) log.warn('Remote feed unavailable or stale; using retained records and built-in floor');
  return feed;
}
export async function runPins(opts: WrapOptions): Promise<void> {
  if (!process.stdin.isTTY) throw new Error('pins requires a human terminal (TTY on stdin); refusing non-interactive review');
  const id = opts.id!, path = observationPath(opts.stateDir, id), store = new FilePinStore(join(opts.stateDir, 'pins'));
  const { previous, current } = await withStateLock(path, async () => ({ previous: await store.getPin(id), current: await readState<Observation>(path) }));
  process.stdout.write(describeReview(previous, current) + '\n');
  if (opts.action === 'status') return;
  if (opts.action === 'approve' && !current) throw new Error('No observed definitions; run wrap first');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  let answer: string;
  try { answer = await rl.question(`Type ${opts.action} ${id} to confirm: `); }
  finally { rl.close(); }
  if (answer !== `${opts.action} ${id}`) throw new Error('Not confirmed; pin unchanged');
  const feed = await loadWrapFeed(opts);
  await withStateLock(path, async () => {
    if (observationRevision(await readState<Observation>(path)) !== observationRevision(current)) throw new Error('Observed definitions changed since review; inspect status again');
    if (opts.action === 'revoke') {
      // Persist denial before deleting the pin, so a crash cannot accidentally enable TOFU.
      if (current) await writeState(path, { ...current, revoked: true });
      await store.replace(id, pinRevision(previous));
    } else {
      const tools = current!.tools ?? previous?.tools;
      if (!tools) throw new Error('No reviewed tool snapshot available');
      const policy = asPolicy(current!.policy);
      // Re-approval removes only pin drift; the other gates still have to pass.
      const warden = Warden.create({ policy, threatFeed: feed, store: { getPin: async () => undefined, putPin: async () => {} } });
      const verdict = await warden.vet(current!.server, tools);
      if (!verdict.allow) throw new Error(`Approval blocked: ${verdict.findings.map(f => f.code).join(', ')}`);
      await store.replace(id, pinRevision(previous), { serverId: id, tools, toolsHash: canonicalToolsHash(tools), toolsHashVersion: 2,
        identityHash: serverIdentityHash(current!.server), toolNames: tools.map(t => t.name).sort(), approvedAt: new Date().toISOString() });
      await writeState(path, { ...current, revoked: false });
    }
  });
  process.stdout.write(`${opts.action}: ${displaySafe(id)}\n`);
}
