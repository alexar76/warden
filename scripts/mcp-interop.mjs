// Run in an isolated test container. Dependencies are installed separately in
// WARDEN_INTEROP_PACKAGES; this script never installs or downloads anything.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { pinToolsHash } from '../dist/index.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packages = resolve(process.env.WARDEN_INTEROP_PACKAGES ?? 'interop');
const out = resolve(process.argv[2] ?? 'interop-results');
const sdk = join(packages, 'node_modules/@modelcontextprotocol/sdk/dist/esm');
const { Client } = await import(pathToFileURL(join(sdk, 'client/index.js')));
const { StdioClientTransport } = await import(pathToFileURL(join(sdk, 'client/stdio.js')));
mkdirSync(out, { recursive: true });
const fsRoot = join(out, 'filesystem-fixture'); mkdirSync(fsRoot, { recursive: true });
writeFileSync(join(fsRoot, 'fixture.txt'), 'WARDEN interop fixture: ёж 🛡\n');
const targets = [
  { id: 'warden', entry: join(root, 'dist/mcp-server.js'), args: [],
    call: { name: 'canonicalize_json', arguments: { value: { z: 1, a: 'ёж 🛡' } } }, expected: '{"a":"ёж 🛡","z":1}' },
  { id: 'filesystem', entry: join(packages, 'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'), args: [fsRoot],
    call: { name: 'read_text_file', arguments: { path: join(fsRoot, 'fixture.txt') } }, expected: 'WARDEN interop fixture: ёж 🛡' },
  { id: 'memory', entry: join(packages, 'node_modules/@modelcontextprotocol/server-memory/dist/index.js'), args: [],
    call: { name: 'read_graph', arguments: {} }, expected: 'entities' },
  { id: 'sequential-thinking', entry: join(packages, 'node_modules/@modelcontextprotocol/server-sequential-thinking/dist/index.js'), args: [],
    call: { name: 'sequentialthinking', arguments: { thought: 'Verify an isolated synthetic fixture.', nextThoughtNeeded: false, thoughtNumber: 1, totalThoughts: 1 } }, expected: 'thoughtNumber' },
];
const report = { at: new Date().toISOString(), node: process.version,
  sdk: JSON.parse(readFileSync(join(packages, 'node_modules/@modelcontextprotocol/sdk/package.json'))).version,
  scope: 'Independent official SDK; actual server processes directly and through Warden; synthetic local tool calls only', servers: [] };
for (const target of targets) {
  const entry = { id: target.id, modes: [] };
  for (const mode of ['direct', 'wrapped']) {
    const state = join(out, target.id, mode); mkdirSync(state, { recursive: true });
    const transport = new StdioClientTransport({ command: process.execPath,
      args: mode === 'direct' ? [target.entry, ...target.args] : [join(root, 'dist/mcp-server.js'), 'wrap', '--id', `interop-${target.id}`,
        '--state-dir', state, '--results', 'block', '--', process.execPath, target.entry, ...target.args],
      cwd: state, stderr: 'pipe', env: { PATH: process.env.PATH ?? '', HOME: state, WARDEN_STATE_DIR: state,
        MEMORY_FILE_PATH: join(state, 'memory.jsonl'), DISABLE_THOUGHT_LOGGING: 'true' } });
    let stderr = ''; transport.stderr?.on('data', chunk => { stderr += chunk; });
    const client = new Client({ name: 'warden-interop-independent-sdk', version: '1' }, { capabilities: {} });
    const r = { mode, checks: [] }; const start = Date.now();
    try {
      await client.connect(transport, { timeout: 30000 });
      r.serverInfo = client.getServerVersion();
      const tools = []; let cursor;
      do { const p = await client.listTools(cursor ? { cursor } : {}, { timeout: 30000 }); tools.push(...p.tools); cursor = p.nextCursor; } while (cursor);
      r.toolCount = tools.length; r.digest = pinToolsHash(tools);
      writeFileSync(join(out, `${target.id}-${mode}-tools.json`), JSON.stringify(tools, null, 2));
      r.checks.push({ name: 'nonempty tools/list', pass: tools.length > 0 });
      const call = { ...target.call };
      if (target.id === 'sequential-thinking' && tools.some(t => t.name === 'sequential_thinking')) call.name = 'sequential_thinking';
      const response = await client.callTool(call, undefined, { timeout: 30000 });
      r.response = response;
      r.checks.push({ name: 'synthetic tool succeeds', pass: !response.isError && (target.id === 'warden'
        ? response.structuredContent?.canonical === target.expected : JSON.stringify(response).includes(target.expected)) });
      // An unknown tool must fail, and the session must remain usable afterwards.
      try {
        const missing = await client.callTool({ name: 'warden_fixture_unknown', arguments: {} }, undefined, { timeout: 30000 });
        r.checks.push({ name: 'unknown tool refused', pass: missing.isError === true });
      } catch (error) { r.checks.push({ name: 'unknown tool refused', pass: [-32601, -32602, -32000].includes(error.code) }); }
      await client.ping({ timeout: 30000 }); r.checks.push({ name: 'session survives refused call', pass: true });
    } catch (error) { r.error = String(error); r.checks.push({ name: 'MCP exchange', pass: false }); }
    finally { await client.close().catch(() => {}); r.elapsedMs = Date.now() - start; }
    writeFileSync(join(out, `${target.id}-${mode}-stderr.log`), stderr);
    r.pass = r.checks.every(c => c.pass); entry.modes.push(r);
    console.log(JSON.stringify({ id: target.id, mode, pass: r.pass, error: r.error, tools: r.toolCount }));
  }
  entry.toolListParity = Boolean(entry.modes[0].digest) && entry.modes[0].digest === entry.modes[1].digest;
  report.servers.push(entry);
  writeFileSync(join(out, 'results.json'), JSON.stringify(report, null, 2));
}
report.summary = { servers: report.servers.length, exchanges: report.servers.flatMap(s => s.modes).length,
  passed: report.servers.flatMap(s => s.modes).filter(m => m.pass).length, toolListParity: report.servers.filter(s => s.toolListParity).length };
writeFileSync(join(out, 'results.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.summary));
process.exitCode = report.summary.passed === report.summary.exchanges && report.summary.toolListParity === report.summary.servers ? 0 : 1;
