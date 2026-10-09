// Run one @aimarket/warden build's gate chain over a replay set, without starting any server.
//
//   node warden_gates.mjs <path to a warden package or dist/index.js> <set-config.json> <out.json>
//
// Reads each replay file named in the config and runs the same chain `scan` runs (static scan,
// built-in threat floor, origin, pinning with no prior pin), so a published release that predates
// `scan` — 0.8.2, ruleset v8 — can be measured on the same sets. Output has the shape of
// `scan --json-file`, reduced to what normalize.py reads.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [lib, cfgPath, out] = process.argv.slice(2);
const entry = existsSync(join(lib, 'dist', 'index.js')) ? join(lib, 'dist', 'index.js') : resolve(lib);
const { Warden, ThreatFeed, staticScanRulesetRef } = await import(pathToFileURL(entry).href);
const policy = { blockAtSeverity: 'high', sensitiveToolPatterns: [], allowUnknownServers: true, pinToolDefs: true };
const servers = JSON.parse(readFileSync(cfgPath, 'utf8')).mcpServers;
const report = { ruleset: staticScanRulesetRef(), servers: [] };
for (const [key, entryCfg] of Object.entries(servers)) {
  const tools = JSON.parse(readFileSync(entryCfg.args[1], 'utf8')).tools.map(t => ({ ...t, description: t.description ?? '', inputSchema: t.inputSchema ?? { type: 'object' } }));
  const w = Warden.create({ policy, threatFeed: new ThreatFeed(), store: { getPin: async () => undefined, putPin: async () => {} } });
  const v = await w.vet({ id: key, name: key, transport: 'stdio', command: entryCfg.command, args: entryCfg.args }, tools);
  report.servers.push({ key, status: 'scanned', allow: v.allow, findings: v.findings });
}
writeFileSync(out, JSON.stringify(report));
console.log(`${report.ruleset.version} ${report.ruleset.digest}: ${report.servers.filter(s => s.allow === false).length} blocked of ${report.servers.length}`);
