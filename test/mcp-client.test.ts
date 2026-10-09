import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fetchServer, fetchStdio, isNonPublicAddress, SseParser, McpClientError } from '../src/mcp-client.js';
import type { McpServerRef } from '../src/types.js';

const servers: Server[] = [], dirs: string[] = [];
afterEach(async () => {
  for (const s of servers.splice(0)) await new Promise(r => { s.closeAllConnections(); s.close(r); });
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const opts = { timeoutMs: 5000, clientVersion: 'test' };
const tool = (name: string) => ({ name, description: `Tool ${name}.`, inputSchema: { type: 'object' } });

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
}
function reply(msg: any) {
  if (msg.method === 'initialize') return { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18', serverInfo: { name: 'http-fixture', version: '2' }, capabilities: { tools: {} }, instructions: 'Be nice.' } };
  if (msg.method === 'tools/list') {
    const page = msg.params?.cursor ? 2 : 1;
    return { jsonrpc: '2.0', id: msg.id, result: { tools: [tool(`t${page}`)], ...(page === 1 ? { nextCursor: 'p2' } : {}) } };
  }
  return undefined;
}
async function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const s = createServer(handler); servers.push(s);
  await new Promise<void>(r => s.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(s.address() as { port: number }).port}`;
}
const ref = (url: string, transport: 'http' | 'sse' = 'http'): McpServerRef => ({ id: 'x', name: 'x', transport, url });

describe('MCP client: streamable HTTP', () => {
  it('JSON replies, a session id, and every page of tools', async () => {
    const seen: string[] = [];
    const base = await listen(async (req, res) => {
      if (req.method === 'GET') { res.writeHead(405).end(); return; }
      const msg = await body(req);
      seen.push(`${msg.method}:${req.headers['mcp-session-id'] ?? '-'}`);
      const r = reply(msg);
      if (!r) { res.writeHead(202).end(); return; }
      res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'sess-1' }).end(JSON.stringify(r));
    });
    const out = await fetchServer(ref(base + '/mcp'), opts);
    expect(out.tools.map(t => t.name)).toEqual(['t1', 't2']);
    expect(out.serverInfo).toEqual({ name: 'http-fixture', version: '2' });
    expect(out.instructions).toBe('Be nice.');
    expect(seen).toEqual(['initialize:-', 'notifications/initialized:sess-1', 'tools/list:sess-1', 'tools/list:sess-1']);
  });

  it('SSE replies, skipping notifications that arrive first', async () => {
    const base = await listen(async (req, res) => {
      if (req.method === 'GET') { res.writeHead(405).end(); return; }
      const msg = await body(req), r = reply(msg);
      if (!r) { res.writeHead(202).end(); return; }
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: {} })}\n\n`);
      res.write(`data: ${JSON.stringify(r)}\n\n`);
    });
    expect((await fetchServer(ref(base), opts)).tools).toHaveLength(2);
  });

  it('names an auth wall, and does not follow redirects', async () => {
    const auth = await listen((_req, res) => { res.writeHead(401).end(); });
    await expect(fetchServer(ref(auth), opts)).rejects.toThrow(/401.*credentials/);
    const moved = await listen((_req, res) => { res.writeHead(302, { location: 'http://169.254.169.254/' }).end(); });
    await expect(fetchServer(ref(moved), opts)).rejects.toThrow(/redirect \(not followed\)/);
  });

  it('refuses an oversized answer', async () => {
    const big = await listen(async (req, res) => {
      const msg = await body(req);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { pad: 'x'.repeat(17 * 1024 * 1024) } }));
    });
    await expect(fetchServer(ref(big), opts)).rejects.toThrow(/exceeds/);
  });

  it('--public-only refuses loopback, by literal and by name', async () => {
    const base = await listen((_req, res) => { res.writeHead(500).end(); });
    await expect(fetchServer(ref(base), { ...opts, publicOnly: true })).rejects.toMatchObject({ kind: 'refused' });
    await expect(fetchServer(ref(base.replace('127.0.0.1', 'localhost')), { ...opts, publicOnly: true })).rejects.toMatchObject({ kind: 'refused' });
  });
});

describe('MCP client: legacy HTTP+SSE', () => {
  it('follows the endpoint event and reads replies from the stream', async () => {
    let stream: ServerResponse | undefined;
    const base = await listen(async (req, res) => {
      if (req.method === 'GET') {
        stream = res;
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write('event: endpoint\ndata: /messages?sessionId=abc\n\n');
        return;
      }
      const msg = await body(req);
      res.writeHead(202).end();
      const r = reply(msg);
      if (r) stream!.write(`event: message\ndata: ${JSON.stringify(r)}\n\n`);
    });
    const out = await fetchServer(ref(base + '/sse', 'sse'), opts);
    expect(out.tools.map(t => t.name)).toEqual(['t1', 't2']);
  });

  it('refuses an endpoint event that points at another origin', async () => {
    const base = await listen((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('event: endpoint\ndata: https://elsewhere.example/messages\n\n');
    });
    await expect(fetchServer(ref(base, 'sse'), opts)).rejects.toThrow(/another origin/);
  });
});

describe('MCP client: stdio', () => {
  it('times out a server that never answers, and answers roots/list for one that asks', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-client-')); dirs.push(dir);
    writeFileSync(join(dir, 'silent.mjs'), 'setInterval(() => {}, 1000);');
    await expect(fetchStdio({ id: 's', name: 's', transport: 'stdio', command: process.execPath, args: [join(dir, 'silent.mjs')] }, { ...opts, timeoutMs: 500 })).rejects.toMatchObject({ kind: 'timeout' });
    writeFileSync(join(dir, 'asks.mjs'), `
      import { createInterface } from 'node:readline';
      const send = m => process.stdout.write(JSON.stringify(m) + '\\n');
      let initId;
      createInterface({ input: process.stdin }).on('line', l => {
        const m = JSON.parse(l);
        if (m.method === 'initialize') { initId = m.id; send({ jsonrpc: '2.0', id: 'ask', method: 'roots/list' }); return; }
        if (m.id === 'ask') { send({ jsonrpc: '2.0', id: initId, result: { protocolVersion: '2025-06-18', serverInfo: { name: 'asks' }, capabilities: {} } }); return; }
        if (m.method === 'tools/list') send({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'a', description: 'A.', inputSchema: { type: 'object' } }] } });
      });`);
    const out = await fetchStdio({ id: 'a', name: 'a', transport: 'stdio', command: process.execPath, args: [join(dir, 'asks.mjs')] }, opts);
    expect(out.tools.map(t => t.name)).toEqual(['a']);
  });

  it('reports a server that exits with its last stderr line', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-client-')); dirs.push(dir);
    writeFileSync(join(dir, 'dies.mjs'), 'console.error("missing GITHUB_TOKEN"); process.exit(1);');
    await expect(fetchStdio({ id: 'd', name: 'd', transport: 'stdio', command: process.execPath, args: [join(dir, 'dies.mjs')] }, opts)).rejects.toThrow(/missing GITHUB_TOKEN/);
  });
});

describe('address policy and SSE parsing', () => {
  it('classifies non-public addresses', () => {
    for (const a of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fd00:ec2::254', 'fe80::1', '::ffff:10.0.0.1']) expect(isNonPublicAddress(a), a).toBe(true);
    for (const a of ['8.8.8.8', '1.1.1.1', '2606:4700::1111']) expect(isNonPublicAddress(a), a).toBe(false);
  });
  it('parses multi-line data, CRLF and comments', () => {
    const p = new SseParser();
    expect(p.push(': hi\r\nevent: x\r\ndata: a\r\ndata: b\r\n\r\n')).toEqual([{ event: 'x', data: 'a\nb' }]);
    expect(p.push('data: tail')).toEqual([]);
    expect(p.end()).toEqual([{ event: 'message', data: 'tail' }]);
  });
  it('error kinds are typed', () => { expect(new McpClientError('timeout', 'x').kind).toBe('timeout'); });
});
