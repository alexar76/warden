// Replays one frozen server: answers initialize and tools/list from a JSON file, nothing else.
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const rec = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const send = m => process.stdout.write(JSON.stringify(m) + '\n');
createInterface({ input: process.stdin }).on('line', line => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === 'initialize') return send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: rec.serverName || 'replay', version: rec.serverVersion || '1' } } });
  if (m.method === 'tools/list') return send({ jsonrpc: '2.0', id: m.id, result: { tools: rec.tools } });
  if (m.method === 'ping') return send({ jsonrpc: '2.0', id: m.id, result: {} });
  if (m.id !== undefined && m.method) {
    if (m.method === 'prompts/list') return send({ jsonrpc: '2.0', id: m.id, result: { prompts: [] } });
    if (m.method === 'resources/list') return send({ jsonrpc: '2.0', id: m.id, result: { resources: [] } });
    if (m.method === 'resources/templates/list') return send({ jsonrpc: '2.0', id: m.id, result: { resourceTemplates: [] } });
    return send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'not available in replay' } });
  }
});
