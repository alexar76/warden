#!/usr/bin/env node
// WARDEN flow guard for Codex: one entry for every hook event (pre-tool-use, post-tool-use, user-prompt-submit, stop).
// Logic lives in flow-guard-codex.mjs (generated from the package). Codex RUNS the tool when a PreToolUse hook fails,
// so even a missing or broken guard file must print a deny here instead of crashing.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
const event = process.argv[2] || '';
try {
  const { codexHookMain } = await import('./flow-guard-codex.mjs');
  codexHookMain(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`warden codex hook: ${err instanceof Error ? err.message : String(err)}\n`);
  if (event === 'pre-tool-use') {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
      permissionDecisionReason: 'WARDEN flow guard could not load. Refused; repair the guard installation.' } }) + '\n');
  }
  if (event === 'post-tool-use') {
    try {
      let sessionId;
      try {
        const input = JSON.parse(readFileSync(0, 'utf8'));
        if (typeof input?.session_id === 'string' && input.session_id) sessionId = `codex:${input.session_id}`;
      } catch { /* an unreadable result has no trustworthy session id */ }
      const root = process.env.WARDEN_STATE_DIR || join(process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'warden');
      const dir = join(root, 'codex', 'broken');
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const key = sessionId ? createHash('sha256').update(sessionId).digest('hex') : '_unknown';
      writeFileSync(join(dir, key), new Date().toISOString() + '\n', { mode: 0o600 });
    } catch (fenceError) {
      process.stderr.write(`warden codex hook could not persist the result-failure fence: ${fenceError instanceof Error ? fenceError.message : String(fenceError)}\n`);
    }
  }
}
