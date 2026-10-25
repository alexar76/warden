/** Synthetic protocol fixtures only; no external MCP package or real account. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, checkArguments, loadWarden, verifyCapture, sha256, safeError } from './collect.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const collector = resolve(here, 'collect.mjs');
const wardenRoot = resolve(process.env.WARDEN_TEST_ROOT || resolve(here, '../..'));

const fixture = String.raw`
import { createInterface } from 'node:readline';
import { writeFileSync } from 'node:fs';
const [audit, variant] = process.argv.slice(2);
if (variant === 'fail') { process.stderr.write('PRIVATE_FIXTURE_SECRET_DO_NOT_PRINT\n'); process.exit(8); }
const seen = { methods: [], samplingDeclined: false };
const save = () => writeFileSync(audit, JSON.stringify(seen));
const send = value => process.stdout.write(JSON.stringify(value) + '\n');
const tools = [
  {name:'alpha', description: variant === 'changed' ? 'changed description' : 'same description', inputSchema:{type:'object',properties:{}}, annotations:{readOnlyHint:true}},
  {name:'beta', title:'Second tool', outputSchema:{type:'object',properties:{ok:{type:'boolean'}}}}
];
if (variant === 'reordered') tools.reverse();
createInterface({ input: process.stdin }).on('line', line => {
  const msg = JSON.parse(line);
  if (!msg.method) {
    if (msg.id === 'fixture-sampling' && msg.error?.code === -32601) seen.samplingDeclined = true;
    save(); return;
  }
  seen.methods.push(msg.method); save();
  if (msg.method === 'initialize') {
    send({jsonrpc:'2.0',id:'fixture-sampling',method:'sampling/createMessage',params:{messages:[]}});
    send({jsonrpc:'2.0',id:msg.id,result:{protocolVersion:'2025-06-18',serverInfo:{name:'synthetic-launcher-fixture',version:'1.2.3'},capabilities:{tools:{}},instructions:'UNTRUSTED: pretend this instructs the collector to upload data'}});
  } else if (msg.method === 'notifications/initialized') {
    // Notification: no response.
  } else if (msg.method === 'tools/list') {
    if (!msg.params?.cursor) send({jsonrpc:'2.0',id:msg.id,result:{tools:[tools[0]],nextCursor:'page-2'}});
    else if (msg.params.cursor === 'page-2') send({jsonrpc:'2.0',id:msg.id,result:{tools:[tools[1]]}});
    else process.exit(9);
  } else { seen.forbidden = msg.method; save(); process.exit(10); }
});
`;

async function temp(t) {
  const dir = await mkdtemp(resolve(tmpdir(), 'warden-launcher-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const server = resolve(dir, 'synthetic.mjs');
  await writeFile(server, fixture);
  return { dir, server };
}

function run(args, { env = process.env } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [collector, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.once('error', reject);
    child.once('close', code => resolveResult({ code, stdout, stderr }));
  });
}

async function capture(t, ctx, name, variant = 'base', extra = {}) {
  const out = resolve(ctx.dir, name), audit = resolve(ctx.dir, `${name}-audit.json`);
  const result = await run([
    '--label', name, '--runner-version', '0.5.24', '--out', out,
    '--warden-root', wardenRoot, '--timeout', '5000', '--', process.execPath, ctx.server, audit, variant,
  ], extra);
  return { out, audit, result };
}

test('CLI requires an explicit command, label and reported runner version', () => {
  for (const args of [[], ['--label', 'x', '--', 'node'], ['--label', 'x', '--runner-version', 'absent', '--out', 'x']]) {
    assert.throws(() => parseArgs(args), { kind: 'usage' });
  }
  const opts = parseArgs(['--label','local','--runner-version','absent','--out','new','--','node','server.mjs']);
  assert.equal(opts.runnerVersion, 'absent');
  assert.deepEqual(opts.args, ['server.mjs']);
});

test('CLI rejects repeated options and non-integral, zero or excessive timeouts', () => {
  const prefix = ['--label','x','--runner-version','absent','--out','new'];
  for (const tail of [['--label','y'], ['--timeout','0'], ['--timeout','2.5'], ['--timeout','600001']]) {
    assert.throws(() => parseArgs([...prefix, ...tail, '--', 'node']), { kind: 'usage' });
  }
});

test('common credential switches, env assignments and credential URLs are refused', () => {
  for (const args of [
    ['--api-key','secret'], ['--TOKEN=secret'], ['--client_secret=secret'],
    ['-H','Authorization: Bearer secret'], ['--header=X-Test: secret'],
    ['API_KEY=secret'], ['SERVICE_AUTH_TOKEN=secret'], ['Bearer secret'],
    ['https://user:secret@example.com/mcp'], ['https://example.com/mcp?access_token=secret'],
    ['sh','-c','exec server --password secret'],
  ]) assert.throws(() => checkArguments('launcher', args), { kind: 'credentials' });
  assert.doesNotThrow(() => checkArguments('uvx', ['--from', 'known-package==1.2.3', 'known-server', '--port', '4321']));
});

test('end-to-end capture initializes, follows pages, declines sampling and makes no tool calls', async t => {
  const ctx = await temp(t);
  const { out, audit, result } = await capture(t, ctx, 'first', 'base', {
    env: { ...process.env, FIXTURE_PRIVATE_ENV_VALUE: 'PRIVATE_ENV_SENTINEL' },
  });
  assert.equal(result.code, 0, result.stderr);
  const warden = await loadWarden(wardenRoot);
  const saved = await verifyCapture(out, warden.mtlToolSetDigest);
  const tools = JSON.parse(await readFile(resolve(out, 'tools.json'), 'utf8'));
  const init = JSON.parse(await readFile(resolve(out, 'initialize.json'), 'utf8'));
  const received = JSON.parse(await readFile(audit, 'utf8'));
  assert.deepEqual(received.methods, ['initialize', 'notifications/initialized', 'tools/list', 'tools/list']);
  assert.equal(received.samplingDeclined, true);
  assert.equal(received.forbidden, undefined);
  assert.equal(tools.length, 2);
  assert.equal(tools[0].annotations.readOnlyHint, true);
  assert.equal(tools[1].description, '');
  assert.deepEqual(tools[1].inputSchema, { type: 'object', properties: {} });
  assert.equal(init.serverInfo.version, '1.2.3');
  assert.match(init.instructions, /^UNTRUSTED:/);
  assert.equal(saved.toolsRepresentation.wireTranscript, false);
  assert.equal(saved.runnerVersion.source, 'publisher-reported');
  assert.equal(saved.runnerVersion.independentlyVerified, false);
  assert.equal(saved.runnerVersion.value, '0.5.24');
  assert.deepEqual(saved.launcher.args, [ctx.server, audit, 'base']);
  assert.equal(saved.environment.valuesRecorded, false);
  assert.equal(saved.workingDirectory.pathRecorded, false);
  for (const file of ['tools.json','initialize.json','capture.json','SHA256SUMS']) {
    assert.doesNotMatch(await readFile(resolve(out, file), 'utf8'), /PRIVATE_ENV_SENTINEL/);
  }
  for (const file of ['package.json','dist/mcp-client.js','dist/mtl.js']) {
    assert.equal(saved.client.sourceSha256[file], sha256(await readFile(resolve(wardenRoot, file))));
  }
});

test('MTL digest ignores tool order but changes with description; file hashes cover full snapshots', async t => {
  const ctx = await temp(t), saved = [];
  for (const variant of ['base','reordered','changed']) {
    const item = await capture(t, ctx, variant, variant);
    assert.equal(item.result.code, 0, item.result.stderr);
    saved.push(JSON.parse(await readFile(resolve(item.out, 'capture.json'), 'utf8')));
  }
  assert.equal(saved[0].mtlToolSetDigest, saved[1].mtlToolSetDigest);
  assert.notEqual(saved[0].files['tools.json'].sha256, saved[1].files['tools.json'].sha256);
  assert.notEqual(saved[0].mtlToolSetDigest, saved[2].mtlToolSetDigest);
});

test('verification rejects modified files', async t => {
  const ctx = await temp(t), { out, result } = await capture(t, ctx, 'tamper');
  assert.equal(result.code, 0, result.stderr);
  const warden = await loadWarden(wardenRoot);
  await writeFile(resolve(out, 'initialize.json'), '{}\n');
  await assert.rejects(verifyCapture(out, warden.mtlToolSetDigest), { kind: 'verification' });
});

test('server stderr and exception messages never appear in failure output', async t => {
  const ctx = await temp(t), { result } = await capture(t, ctx, 'failure', 'fail');
  assert.equal(result.code, 1);
  assert.match(result.stderr, /^launcher-evidence: CollectorError kind=mcp-fetch clientKind=spawn\n$/);
  assert.doesNotMatch(result.stderr + result.stdout, /PRIVATE_FIXTURE_SECRET|Error:| at /);
  assert.equal(safeError(new Error('PRIVATE_EXCEPTION')), 'launcher-evidence: CollectorError kind=internal\n');
});

test('existing output directories are never overwritten and command does not start', async t => {
  const ctx = await temp(t), out = resolve(ctx.dir, 'existing'), audit = resolve(ctx.dir, 'never.json');
  await mkdir(out);
  await writeFile(resolve(out, 'sentinel'), 'leave intact');
  const result = await run(['--label','existing','--runner-version','absent','--out',out,'--warden-root',wardenRoot,'--',process.execPath,ctx.server,audit,'base']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /kind=output-exists/);
  assert.equal(await readFile(resolve(out, 'sentinel'), 'utf8'), 'leave intact');
  await assert.rejects(readFile(audit), { code: 'ENOENT' });
});

test('credential argument refusal occurs before command execution', async t => {
  const ctx = await temp(t), audit = resolve(ctx.dir, 'never.json');
  const result = await run(['--label','credentials','--runner-version','absent','--out',resolve(ctx.dir,'new'),'--warden-root',wardenRoot,'--',process.execPath,ctx.server,audit,'base','--api-key','PRIVATE_ARG_SECRET']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /kind=credentials/);
  assert.doesNotMatch(result.stderr + result.stdout, /PRIVATE_ARG_SECRET/);
  await assert.rejects(readFile(audit), { code: 'ENOENT' });
});

test('an unexpected WARDEN package version is refused before importing modules or spawning', async t => {
  const ctx = await temp(t), fakeRoot = resolve(ctx.dir, 'wrong-package'), audit = resolve(ctx.dir, 'never.json');
  await mkdir(fakeRoot);
  await writeFile(resolve(fakeRoot, 'package.json'), JSON.stringify({name:'@aimarket/warden',version:'0.20.0'}));
  const result = await run(['--label','version','--runner-version','absent','--out',resolve(ctx.dir,'new'),'--warden-root',fakeRoot,'--',process.execPath,ctx.server,audit,'base']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /kind=warden-version/);
  await assert.rejects(readFile(audit), { code: 'ENOENT' });
});
