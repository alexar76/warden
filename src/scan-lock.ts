import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { pinToolsHash, serverIdentityHash } from './pinning.js';
import { displaySafe } from './sanitize.js';
import type { McpServerRef, PinStore, PinnedServer, RulesetRef, ToolDef } from './types.js';

/**
 * `warden.lock.json` — reviewed tool definitions committed next to the MCP config.
 *
 * The lock is the pull-request form of a pin. Whoever adds or changes a server
 * runs `scan --update-lock`; the diff of this file is what reviewers read — the
 * tool descriptions that will reach the model, not just the command line. CI then
 * runs `scan --lock` and fails when the config starts a server the lock does not
 * know, starts it differently, or the server now advertises different tools.
 *
 * Stored entries are ordinary {@link PinnedServer} records (plus the MTL/1 digest
 * HISTOR keys tool sets by), so the same {@link PinningGate} decides drift for
 * `wrap` and for `scan`.
 */
export const LOCK_VERSION = 1;

export interface LockEntry extends PinnedServer {
  /** MTL/1 digest (HISTOR's key); absent when the set has no MTL/1 form. */
  mtlDigest?: string;
}

export interface LockFile {
  lockfileVersion: number;
  generatedBy: string;
  ruleset: RulesetRef;
  servers: Record<string, LockEntry>;
}

export class LockStore implements PinStore {
  readonly entries: Map<string, LockEntry>;
  constructor(entries: Record<string, LockEntry> = {}) { this.entries = new Map(Object.entries(entries)); }
  async getPin(id: string): Promise<PinnedServer | undefined> { return this.entries.get(id); }
  async putPin(): Promise<void> { /* the lock changes only through --update-lock */ }
}

function validEntry(id: string, e: unknown): e is LockEntry {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return false;
  const p = e as LockEntry;
  return p.serverId === id && typeof p.toolsHash === 'string' && /^(?:rfc8785:)?[a-f0-9]{64}$/.test(p.toolsHash) &&
    typeof p.approvedAt === 'string' && Array.isArray(p.toolNames) && p.toolNames.every(n => typeof n === 'string') &&
    (p.identityHash === undefined || /^[a-f0-9]{64}$/.test(p.identityHash)) &&
    (p.tools === undefined || Array.isArray(p.tools));
}

/** Read a lock. A missing file is an empty lock; a malformed one is an error, never "empty". */
export async function readLock(path: string): Promise<LockFile | undefined> {
  if (!existsSync(path)) return undefined;
  let raw: unknown;
  try { raw = JSON.parse(await readFile(path, 'utf8')); }
  catch (err) { throw new Error(`${path}: not JSON (${err instanceof Error ? err.message : String(err)})`); }
  const lock = raw as LockFile;
  if (!lock || typeof lock !== 'object' || lock.lockfileVersion !== LOCK_VERSION || !lock.servers || typeof lock.servers !== 'object' || Array.isArray(lock.servers)) {
    throw new Error(`${path}: not a WARDEN lock file (lockfileVersion ${LOCK_VERSION})`);
  }
  for (const [id, entry] of Object.entries(lock.servers)) {
    if (!validEntry(id, entry)) throw new Error(`${path}: entry ${displaySafe(JSON.stringify(id), 140)} is malformed; refusing to read the lock as partly empty`);
  }
  return lock;
}

/** Recursively sort object keys so the committed file diffs line by line, not reorder by reorder. */
export function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) out[key] = sortKeys((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

export function lockEntryFor(server: McpServerRef, tools: ToolDef[], mtlDigest: string | undefined, previous: LockEntry | undefined, now: string): LockEntry {
  const toolsHash = pinToolsHash(tools), identityHash = serverIdentityHash(server);
  const unchanged = previous && previous.toolsHash === toolsHash && previous.identityHash === identityHash;
  const sorted = [...tools].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  return {
    serverId: server.id,
    toolsHash, toolsHashVersion: 2, identityHash,
    // An unchanged entry keeps its date, so re-running --update-lock produces no diff.
    approvedAt: unchanged ? previous.approvedAt : now,
    toolNames: sorted.map(t => t.name),
    tools: structuredClone(sorted),
    ...(mtlDigest ? { mtlDigest } : {}),
  };
}

export async function writeLock(path: string, lock: LockFile): Promise<void> {
  const text = JSON.stringify(sortKeys(lock), null, 2) + '\n';
  // Pretty, sorted and atomic: the lock is read in a diff, and a failed write keeps the old one.
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  try { await writeFile(temp, text, { mode: 0o644 }); await rename(temp, path); }
  finally { await unlink(temp).catch(() => {}); }
}

export interface ToolChange { tool: string; kind: 'added' | 'removed' | 'changed'; before?: ToolDef; after?: ToolDef }

/** What changed between the reviewed tools and the ones served now, tool by tool. */
export function diffTools(before: readonly ToolDef[] | undefined, after: readonly ToolDef[]): ToolChange[] {
  const old = new Map((before ?? []).map(t => [t.name, t])), now = new Map(after.map(t => [t.name, t]));
  const names = [...new Set([...old.keys(), ...now.keys()])].sort();
  const changes: ToolChange[] = [];
  for (const name of names) {
    const a = old.get(name), b = now.get(name);
    if (!a && b) changes.push({ tool: name, kind: 'added', after: b });
    else if (a && !b) changes.push({ tool: name, kind: 'removed', before: a });
    else if (a && b && pinToolsHash([a]) !== pinToolsHash([b])) changes.push({ tool: name, kind: 'changed', before: a, after: b });
  }
  return changes;
}
