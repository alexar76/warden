#!/usr/bin/env node
// Copies the compiled flow guard (dist/flow-guard.js and its parts, dist/flow-guard-*.js) into the Claude Code
// plugin, which runs it on every tool call without installing the package. `npm run build` calls this;
// test/flow-guard.test.ts fails if a copy and the build differ, so the plugin can never run logic the package does not.
import { existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = /^flow-guard(?:-[a-z]+)?\.ts$/;
const PLUGIN = /^flow-guard(?:-[a-z]+)?\.mjs$/;

export function pluginCopy(compiled, source = 'src/flow-guard.ts') {
  // The parts import each other as ./flow-guard-*.js; in the plugin they are .mjs files next to each other.
  const body = compiled.replace(/\n\/\/# sourceMappingURL=.*\s*$/, '\n')
    .replace(/(\bfrom\s+['"]\.\/flow-guard(?:-[a-z]+)?)\.js(['"])/g, '$1.mjs$2');
  const specifiers = [...body.matchAll(/^\s*(?:import|export)\b[^;'"]*\bfrom\s+['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gm)];
  if (specifiers.some(m => !/^(?:node:|\.\/flow-guard(?:-[a-z]+)?\.mjs$)/.test(m[1] ?? m[2]))) {
    throw new Error(`${source} must import node: built-ins and flow-guard parts only`);
  }
  return `// GENERATED from ${source} by scripts/sync-flow-guard.mjs. Do not edit; run npm run build.\n` + body;
}

/** Every plugin file the build should produce: one per src/flow-guard*.ts, from its compiled dist file. */
export function pluginFiles(base = root) {
  return readdirSync(join(base, 'src')).filter(n => SOURCE.test(n)).sort().map(n => {
    const js = n.replace(/\.ts$/, '.js');
    return { name: js.replace(/\.js$/, '.mjs'), text: pluginCopy(readFileSync(join(base, 'dist', js), 'utf8'), `src/${n}`) };
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const scripts = join(root, 'claude-plugin/scripts');
  const files = pluginFiles();
  for (const f of files) writeFileSync(join(scripts, f.name), f.text);
  // A part that no longer exists must not stay behind in the plugin.
  for (const n of readdirSync(scripts)) if (PLUGIN.test(n) && !files.some(f => f.name === n) && existsSync(join(scripts, n))) unlinkSync(join(scripts, n));
  console.log(`claude-plugin/scripts: ${files.map(f => f.name).join(', ')} updated`);
}
