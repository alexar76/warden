#!/usr/bin/env node
// Host integration: read structured proposals from stdin; output only a verified final result or withholding notice.
// No model API, keys, network, tool calls or effects. Integrators supply their own bounded model callback instead.
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { createAnswerGate } from '../dist/index.js';

const controller = new AbortController();
process.once('SIGINT', () => controller.abort());
// stdout failures are uncertain delivery, never a reason to resend.
process.stdout.on('error', () => {});
let lines;
try {
  if (process.argv.length !== 4 || process.argv[2] !== '--contract') throw new Error('usage');
  const bytes = readFileSync(process.argv[3]);
  if (bytes.length > 262_144) throw new Error('contract too large');
  const gate = createAnswerGate(JSON.parse(bytes.toString('utf8')));
  lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const iterator = lines[Symbol.asyncIterator]();
  const result = await gate.run({ signal: controller.signal, maxCorrections: 2, timeoutMs: 30_000,
    generate: async request => {
      process.stderr.write('WARDEN_REQUEST ' + JSON.stringify({ attempt: request.attempt, catalog: request.catalog, feedback: request.feedback ?? null }) + '\n');
      const next = await iterator.next();
      if (next.done) throw new Error('No structured proposal');
      return next.value;
    },
    emit: rendered => new Promise((resolve, reject) => process.stdout.write(rendered, error => error ? reject(error) : resolve())),
  });
  process.exitCode = result.status === 'delivered' ? 0 : result.status === 'withheld' ? 2 : result.status === 'cancelled' ? 130 : 3;
} catch {
  process.stderr.write('WARDEN_HOST_ERROR: provide --contract with normalized host-owned facts. No candidate forwarded.\n');
  process.exitCode = 1;
} finally { lines?.close(); }
