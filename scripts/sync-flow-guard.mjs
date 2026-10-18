#!/usr/bin/env node
// Copies the compiled flow guard (dist/flow-guard.js) into the Claude Code plugin, which runs it on
// every tool call without installing the package. `npm run build` calls this; test/flow-guard.test.ts
// fails if the copy and the build differ, so the plugin can never run logic the package does not.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
export function pluginCopy(compiled) {
  const body = compiled.replace(/\n\/\/# sourceMappingURL=.*\s*$/, '\n');
  if (/^\s*import\s.+from\s+['"](?!node:)/m.test(body)) throw new Error('flow-guard.js must import node: built-ins only');
  return '// GENERATED from src/flow-guard.ts by scripts/sync-flow-guard.mjs. Do not edit; run npm run build.\n' + body;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const out = pluginCopy(readFileSync(join(root, 'dist/flow-guard.js'), 'utf8'));
  writeFileSync(join(root, 'claude-plugin/scripts/flow-guard.mjs'), out);
  console.log('claude-plugin/scripts/flow-guard.mjs updated');
}
