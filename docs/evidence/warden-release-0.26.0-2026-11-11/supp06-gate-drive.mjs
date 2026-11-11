// Drives `warden wrap` over stdio: initialize, tools/list, tools/call; prints what came back for the call.
import { spawn } from 'node:child_process';
const [bin, name, stateDir] = process.argv.slice(2);
const child = spawn(bin, ['wrap', '--id', 'histor-e2e', '--state-dir', stateDir, '--histor-revision', name,
  '--histor-revision-all', '--', 'uvx', '--from', 'aimarket-histor==0.7.0', 'aimarket-histor'],
  { stdio: ['pipe', 'pipe', 'pipe'] });
let buf = ''; const waiting = new Map(); let err = '';
child.stderr.on('data', d => { err += d; });
child.stdout.on('data', d => {
  buf += d; let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); }
  }
});
const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
const req = (id, method, params) => new Promise((res, rej) => {
  waiting.set(id, res); send({ jsonrpc: '2.0', id, method, params });
  setTimeout(() => rej(new Error(`timeout on ${method}; stderr: ${err.slice(-400)}`)), 90_000);
});
try {
  await req(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const list = await req(2, 'tools/list', {});
  const names = (list.result?.tools ?? []).map(t => t.name).sort();
  const call = await req(3, 'tools/call', { name: 'histor_server', arguments: { id: '7c3248da987439aa' } });
  const text = JSON.stringify(call.error ?? call.result).slice(0, 300);
  console.log(JSON.stringify({ revisionName: name, tools: names, callError: !!call.error || !!call.result?.isError, call: text }));
} catch (e) { console.log('ERROR', e.message); }
child.kill();
process.exit(0);
