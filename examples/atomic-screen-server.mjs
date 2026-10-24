#!/usr/bin/env node
// A runnable SERVER-OWNED virtual surface. No OS clicks, browser, mail, payment or network.
// Production backends must provide the same synchronous ownership/transaction guarantee.
import { createInterface } from 'node:readline';
import { AtomicScreenServer, ATOMIC_SCREEN_PREPARE, ATOMIC_SCREEN_COMMIT, ATOMIC_SCREEN_CANCEL } from '../dist/atomic-screen.js';

let submitted = 0;
const snapshot = () => ({ content: [{ type: 'text', text: JSON.stringify({ applicationId: 'dev.warden.atomic-example', title: 'Local virtual form', submitted,
  elements: [{ index: 3, role: 'button', name: 'Send', accessibilityIdentifier: 'example.submit', bounds: { x: 10, y: 10, width: 80, height: 30 } }],
}) }] });
const surface = new AtomicScreenServer({ observation: { name: 'screenshot', arguments: {} }, actions: ['click'], snapshot: snapshot(), apply: (action, target) => {
  // This is the actual effect on the model owned by this server, in the same JS turn as CAS.
  // Never replace this with an awaited/queued coordinate click on an externally mutable desktop.
  if (action.name !== 'click' || target !== '3') throw new Error('Unsupported target');
  submitted++;
  return { result: { content: [{ type: 'text', text: `Virtual form submitted ${submitted} time(s). Nothing was sent externally.` }] }, snapshot: snapshot() };
} });
const tools = [
  { name: 'screenshot', description: 'Observe the local virtual form.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'click', description: 'Activate an element of the local virtual form through atomic approval.', inputSchema: { type: 'object', properties: { index: { type: 'integer' } }, required: ['index'], additionalProperties: false } },
];
const send = value => process.stdout.write(JSON.stringify(value) + '\n');
createInterface({ input: process.stdin }).on('line', line => {
  let msg;
  try {
    if (Buffer.byteLength(line) > 65_536) throw new Error('Oversized request');
    msg = JSON.parse(line);
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') throw new Error('Invalid request');
    const ok = result => { if (msg.id !== undefined) send({ jsonrpc: '2.0', id: msg.id, result }); };
    if (msg.method === ATOMIC_SCREEN_CANCEL) { surface.cancel(msg.params); return ok({}); }
    if (msg.id === undefined) return;
    if (msg.method === 'initialize') return ok({ protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'warden-atomic-example', version: '1' } });
    if (msg.method === 'tools/list') return ok({ tools });
    if (msg.method === ATOMIC_SCREEN_PREPARE) return ok(surface.prepare(msg.params));
    if (msg.method === ATOMIC_SCREEN_COMMIT) return ok(surface.commit(msg.params));
    if (msg.method === 'tools/call' && msg.params?.name === 'screenshot' && Object.keys(msg.params.arguments ?? {}).length === 0) return ok(surface.read());
    // Raw GUI dispatch is deliberately absent, even for direct clients.
    throw new Error('Unsupported method or raw effect; atomic commit required');
  } catch {
    if (msg?.id !== undefined) send({ jsonrpc: '2.0', id: msg.id, error: { code: -32041, message: 'Atomic example refused or outcome is uncertain; no automatic retry' } });
  }
});
