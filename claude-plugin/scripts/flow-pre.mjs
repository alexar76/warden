#!/usr/bin/env node
// WARDEN flow guard, PreToolUse: asks or denies a call that could send data out after the session read
// outside text. Logic lives in flow-guard.mjs (generated from the package).
//
// On its own failure (a missing or broken guard file, an unexpected exception) it decides nothing for a person at the
// keyboard, so a broken install does not lock them out. With `"mode": "deny"` nobody is there: Claude Code runs a call
// whose hook crashed, so the failure must be a refusal. The mode is read here with Node built-ins only, because the
// guard's own files may be what failed to load.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function denyMode() {
  if (process.env.WARDEN_FLOW_MODE) return process.env.WARDEN_FLOW_MODE === 'deny';
  const state = process.env.WARDEN_STATE_DIR || join(process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'warden');
  try { return JSON.parse(readFileSync(process.env.WARDEN_FLOW_POLICY || join(state, 'flow-policy.json'), 'utf8'))?.mode === 'deny'; }
  catch { return false; }
}

try {
  const { flowGuardMain } = await import('./flow-guard.mjs');
  flowGuardMain(['pre']);
} catch (err) {
  process.stderr.write(`warden flow guard: ${err instanceof Error ? err.message : String(err)}\n`);
  if (denyMode()) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny',
      permissionDecisionReason: 'WARDEN flow guard could not run, and the flow policy is "deny". Refused; repair the guard installation.' } }) + '\n');
  }
}
