import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { FilePinStore, pinRevision } from './pin-store.js';
import { readState, writeState, withStateLock } from './state.js';
import { Warden, canonicalToolsHash, serverIdentityHash, displaySafe } from './index.js';
import type { McpServerRef, ToolDef, WardenPolicy, WardenVerdict } from './types.js';
import type { ThreatFeed } from './threat-feed.js';

export interface Observation {
  server: McpServerRef;
  /** Absent when vetLaunch refused to start the new command. */
  tools?: ToolDef[];
  policy: WardenPolicy;
  revoked?: boolean;
}
export function observationPath(dir: string, id: string): string {
  return join(dir, 'wrap', createHash('sha256').update(id).digest('hex') + '.json');
}
export function observationRevision(value: Observation | undefined): string {
  return createHash('sha256').update(JSON.stringify(value) ?? 'null').digest('hex');
}
export async function observe(dir: string, value: Observation): Promise<void> {
  const path = observationPath(dir, value.server.id);
  await withStateLock(path, async () => {
    const previous = await readState<Observation>(path);
    const tools = value.tools ?? (previous?.revoked && serverIdentityHash(previous.server) === serverIdentityHash(value.server) ? previous.tools : undefined);
    await writeState(path, { ...value, tools, revoked: previous?.revoked });
  });
}

/** One lock spans TOFU's read/vet/approve, as well as human review's final CAS. */
export async function vetAndPin(dir: string, server: McpServerRef, tools: ToolDef[], policy: WardenPolicy,
  store: FilePinStore, warden: Warden, feed: ThreatFeed, auditOnly: boolean, isCurrent: () => boolean, record: (v: WardenVerdict) => void): Promise<WardenVerdict> {
  const path = observationPath(dir, server.id);
  return withStateLock(path, async () => {
    const previous = await readState<Observation>(path);
    await writeState(path, { server, tools, policy, revoked: previous?.revoked });
    const verdict = await warden.vet(server, tools);
    record(verdict);
    if (!auditOnly && !isCurrent()) throw new Error('tools changed, blocked by WARDEN during verification');
    if (previous?.revoked && !auditOnly) throw new Error('Approval revoked; inspect pins status and approve before reconnecting');
    if (!auditOnly && verdict.allow && policy.pinToolDefs && !previous?.revoked && !await store.getPin(server.id)) {
      // Use the published approve API with a CAS adapter: other hosts may share this store.
      const firstContact = Warden.create({ policy, threatFeed: feed,
        store: { getPin: id => store.getPin(id), putPin: pin => store.replace(server.id, null, pin) } });
      await firstContact.approve(server, tools);
    }
    return verdict;
  });
}

export function describeReview(previous: Awaited<ReturnType<FilePinStore['getPin']>>, current: Observation | undefined): string {
  const oldTools = previous?.tools ?? [];
  const newTools = current?.tools ?? oldTools;
  const lines = [`Previous identity: ${previous?.identityHash ?? '(none)'}`,
    `Observed identity: ${current ? serverIdentityHash(current.server) : '(none)'}`,
    `Launch: ${current ? JSON.stringify(current.server) : '(none)'}`];
  if (current && !current.tools) lines.push('Launch was blocked; tool definitions below are the PREVIOUS snapshot, not fetched from the new command.');
  for (const name of new Set([...oldTools, ...newTools].map(t => t.name))) {
    const old = oldTools.find(t => t.name === name), next = newTools.find(t => t.name === name);
    if (JSON.stringify(old) !== JSON.stringify(next)) {
      if (old) lines.push('- ' + JSON.stringify(old));
      if (next) lines.push('+ ' + JSON.stringify(next));
    }
  }
  lines.push(`Previous tools: ${previous?.toolsHash ?? '(none)'}`, `Observed tools: ${canonicalToolsHash(newTools)}`,
    `Revoked: ${current?.revoked === true}`);
  return lines.map(line => displaySafe(line, 2_000_000)).join('\n');
}
export { pinRevision };
