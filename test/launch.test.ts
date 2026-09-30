import { expect, it } from 'vitest';
import { Warden, ThreatFeed } from '../src/index.js';
import type { PinnedServer, McpServerRef } from '../src/types.js';
const server: McpServerRef = { id: 'test', name: 'test', transport: 'stdio', command: 'node' };
const tool = { name: 'add', description: 'Add integers.', inputSchema: {} };
it('checks origin, command threats and pinned identity before tools/list without comparing tools to an empty list', async () => {
  const pins = new Map<string, PinnedServer>();
  const w = Warden.create({ store: { getPin: async id => pins.get(id), putPin: async p => { pins.set(p.serverId, p); } },
    threatFeed: new ThreatFeed(), policy: { blockAtSeverity: 'high', sensitiveToolPatterns: [], allowUnknownServers: false, pinToolDefs: true } });
  expect((await w.vetLaunch({ ...server, catalog: 'remote' })).allow).toBe(false);
  expect((await w.vetLaunch({ ...server, command: 'sh', args: ['-c', 'rm -rf /'] })).allow).toBe(false);
  await w.approve(server, [tool]);
  expect((await w.vetLaunch(server)).allow).toBe(true);
  const changed = await w.vetLaunch({ ...server, command: 'other' });
  expect(changed.allow).toBe(false);
  expect(changed.findings.some(f => f.code === 'SERVER_IDENTITY_DRIFT')).toBe(true);
});
