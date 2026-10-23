#!/usr/bin/env node
// JSONL bridge for the AgentDojo harness: one request per line, {"event":"pre|post|prompt|stop","input":{...hook input}},
// one reply per line, {"out": <hook output JSON or null>}. Runs the same compiled guard the plugin runs.
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const guardPath = process.env.WARDEN_FLOW_GUARD || new URL('../../dist/flow-guard.js', import.meta.url).pathname;
const { runFlowHook } = await import(pathToFileURL(guardPath).href);
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  let reply;
  try {
    const { event, input } = JSON.parse(line);
    const out = runFlowHook(event, JSON.stringify(input));
    reply = { out: out ? JSON.parse(out) : null };
  } catch (err) {
    reply = { error: err instanceof Error ? err.message : String(err) };
  }
  process.stdout.write(JSON.stringify(reply) + '\n');
}
