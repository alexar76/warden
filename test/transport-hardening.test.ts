import { it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { handleRpc, consumeLsp, MAX_FRAME_BYTES } from '../src/mcp-rpc.js';
it('rejects malformed envelopes and parameters without throwing', async () => {
  for (const value of [null, [], 1, { jsonrpc: '2.0', id: 1, method: 42 }]) {
    expect((await handleRpc(value))?.error?.code).toBe(-32600);
  }
  expect((await handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: null }))?.error?.code).toBe(-32602);
  expect((await handleRpc({ jsonrpc: '2.0', id: 2, method: 'ping' }))?.result).toEqual({});
});
it('rejects oversized framing before receiving or parsing its body', () => {
  expect(() => consumeLsp(Buffer.from(`Content-Length: ${MAX_FRAME_BYTES + 1}\r\n\r\n`))).toThrow(/large/);
  expect(() => consumeLsp(Buffer.alloc(8193, 65))).toThrow(/large/);
});
it('preserves UTF-8 split between stdin writes and survives a null request', async () => {
  const child = spawn(process.execPath, ['dist/mcp-server.js'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; let errors = '';
  child.stdout.on('data', c => { output += c; });
  child.stderr.on('data', c => { errors += c; });
  const done = once(child, 'close');
  try {
    child.stdin.write('null\n');
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'canonicalize_json', arguments: { value: { label: 'ёж' } } } }) + '\n');
    const cut = body.indexOf(Buffer.from('ё')) + 1;
    child.stdin.write(body.subarray(0, cut));
    await new Promise(r => setTimeout(r, 100));
    child.stdin.end(body.subarray(cut));
    const [code] = await done;
    expect(code, errors).toBe(0);
    const replies = output.trim().split('\n').map(line => JSON.parse(line));
    expect(replies[0].error.code).toBe(-32600);
    expect(replies[1].result.structuredContent.canonical).toBe('{"label":"ёж"}');
  } finally { child.kill(); }
});
