import { it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { FilePinStore, pinRevision } from '../src/pin-store.js';
import { Warden, ThreatFeed } from '../src/index.js';
const server = { id: '../../persistent-test', name: 'demo', transport: 'stdio' as const, command: 'node' };
const tools = [{ name: 'add', description: 'Add two integers.', inputSchema: {} }];
function rpc(name: string, args: object, enabled = true): any {
  const child = spawnSync(process.execPath, ['dist/mcp-server.js'], { encoding: 'utf8',
    env: { ...process.env, WARDEN_ALLOW_PIN_CHANGES: enabled ? '1' : '0' },
    input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) + '\n' });
  expect(child.status, child.stderr).toBe(0);
  return JSON.parse(child.stdout).result;
}
it('requires operator opt-in and exact reviewed payload, persists approval across real process restarts, then revokes', () => {
  const status = rpc('status_mcp_server', { server, tools }).structuredContent;
  expect(status.previous).toBeNull();
  const approval = { server, tools, previous_pin_revision: null, reviewed_tools_hash: status.currentToolsHash,
    reviewed_identity_hash: status.currentIdentityHash };
  expect(rpc('approve_mcp_server', approval, false).isError).toBe(true);
  expect(rpc('approve_mcp_server', { ...approval, reviewed_identity_hash: 'wrong' }).isError).toBe(true);
  expect(rpc('approve_mcp_server', approval).structuredContent.approved).toBe(true);
  expect(rpc('vet_mcp_server', { server, tools }).structuredContent.findings).toEqual([]);
  const changed = [{ ...tools[0], description: 'Add three integers.' }];
  expect(rpc('vet_mcp_server', { server, tools: changed }).structuredContent.allow).toBe(false);
  expect(rpc('approve_mcp_server', approval).isError).toBe(true); // stale review
  const current = rpc('status_mcp_server', { server, tools: changed }).structuredContent;
  expect(current.changed).toBe(true);
  expect(rpc('revoke_mcp_server', { server, previous_pin_revision: current.previousRevision }).structuredContent.revoked).toBe(true);
  expect(rpc('status_mcp_server', { server, tools }).structuredContent.previous).toBeNull();
});
it('compares the entire previous approval, including launch identity, across store instances', async () => {
  const store = new FilePinStore();
  const w = Warden.create({ store, threatFeed: new ThreatFeed(), policy: { blockAtSeverity: 'high', sensitiveToolPatterns: [], allowUnknownServers: true, pinToolDefs: true } });
  await w.approve(server, tools);
  const pin = (await store.getPin(server.id))!;
  await w.approve({ ...server, command: 'different' }, tools);
  await expect(new FilePinStore().replace(server.id, pinRevision(pin))).rejects.toThrow(/changed since review/);
});
