// The smallest MCP server that `warden-mcp scan` can read: JSON-RPC 2.0, one message per line
// on stdin/stdout, answering `initialize`, `tools/list` and `tools/call`. No dependencies.
// Shared by notes.mjs (benign) and poisoned-notes.mjs (poisoned description).
import { createInterface } from 'node:readline';

export function serve({ name, version, tools }) {
  const out = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let req;
    try { req = JSON.parse(line); } catch { return; }
    if (req.id === undefined) return;                      // a notification: nothing to answer
    const reply = (result) => out({ jsonrpc: '2.0', id: req.id, result });
    switch (req.method) {
      case 'initialize':
        return reply({
          protocolVersion: req.params?.protocolVersion ?? '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name, version },
        });
      case 'ping':
        return reply({});
      case 'tools/list':
        return reply({ tools });
      case 'tools/call':
        return reply({ content: [{ type: 'text', text: `(demo) ${name}: nothing was saved.` }], isError: false });
      default:
        return out({ jsonrpc: '2.0', id: req.id, error: { code: -32601, message: `Method not found: ${req.method}` } });
    }
  });
  rl.on('close', () => process.exit(0));
}
