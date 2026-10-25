#!/usr/bin/env node
/** A local, explicit stdio evidence capture. Not a supported WARDEN CLI API. */
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const EXPECTED_PACKAGE = '@aimarket/warden';
const EXPECTED_VERSION = '0.21.0';
const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SOURCE_FILES = [
  'package.json', 'dist/mcp-client.js', 'dist/mtl.js', 'dist/jcs.js',
  'dist/wrap-wire.js', 'dist/tool-list.js',
];
const ERROR_KINDS = new Set([
  'usage', 'credentials', 'output-exists', 'warden-version', 'warden-files',
  'warden-changed', 'mcp-fetch', 'digest', 'write', 'verification', 'internal',
]);
const CLIENT_KINDS = new Set(['timeout', 'spawn', 'protocol', 'http', 'network', 'refused']);

export class CollectorError extends Error {
  constructor(kind, clientKind) {
    super(kind);
    this.name = 'CollectorError';
    this.kind = ERROR_KINDS.has(kind) ? kind : 'internal';
    if (CLIENT_KINDS.has(clientKind)) this.clientKind = clientKind;
  }
}

export function sha256(data) { return createHash('sha256').update(data).digest('hex'); }

export const HELP = `Usage:
  node collect.mjs --label TEXT --runner-version TEXT --out NEWDIR
    [--warden-root PATH] [--timeout MS] -- COMMAND ARGS...

This RUNS COMMAND in your current environment and working directory. It performs
MCP initialize and paginated tools/list, then closes the child. It makes no tool
calls and declines sampling requests. It does not sandbox COMMAND, install or
download packages, run version commands, upload data, or create/approve pins.
Any network or other side effects of COMMAND remain possible.

Use your observed runner version, or the literal "absent" if no runner is installed.
The version is recorded as publisher-reported, not verified.
Review COMMAND and every argument before use: they are saved exactly and MUST
contain no credentials. Common credential arguments are refused, but this is not
a complete secret detector. Environment VALUES are never saved by this script.
Tool definitions and initialize.instructions can themselves contain sensitive,
untrusted content: review every output file before sharing it. Instructions are
stored as data and never followed. NEWDIR must not already exist.

Requires an already installed/built @aimarket/warden 0.21.0 package. The default
root is the package containing this example; otherwise pass --warden-root PATH.
Internal modules are version-specific; source hashes are recorded with evidence.
`;

function shortText(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 && !/[\r\n\0]/.test(value);
}

/** Conservative checks for common credential transport; not a secret detector. */
export function checkArguments(command, args) {
  const sensitive = '(?:api[-_]?key|access[-_]?token|auth[-_]?token|token|password|passwd|secret|client[-_]?secret|private[-_]?key|authorization|bearer|cookie|session[-_]?token)';
  const flag = new RegExp(`(?:^|\\s)--${sensitive}(?:=|\\s|$)`, 'i');
  const assignment = new RegExp(`(?:^|\\s)(?:[A-Z][A-Z0-9_]*_)?${sensitive}=`, 'i');
  const header = /(?:^|\s)(?:-H|--headers?)(?:=|\s|$)/;
  for (const value of [command, ...args]) {
    if (typeof value !== 'string' || value.includes('\0') || flag.test(value) || assignment.test(value)
      || header.test(value) || /(?:^|\s)(?:Bearer|Basic)\s+\S+/i.test(value)) throw new CollectorError('credentials');
    for (const match of value.matchAll(/https?:\/\/[^\s"'<>]+/gi)) {
      let url;
      try { url = new URL(match[0]); } catch { continue; }
      if (url.username || url.password) throw new CollectorError('credentials');
      for (const key of url.searchParams.keys()) {
        if (/^(?:key|api[-_]?key|token|access[-_]?token|password|secret|authorization|signature|sig)$/i.test(key)) {
          throw new CollectorError('credentials');
        }
      }
    }
  }
}

export function parseArgs(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const separator = argv.indexOf('--');
  if (separator < 0 || separator === argv.length - 1) throw new CollectorError('usage');
  const opts = { wardenRoot: DEFAULT_ROOT, timeoutMs: 30_000 };
  const keys = new Map([
    ['--label', 'label'], ['--runner-version', 'runnerVersion'], ['--out', 'out'],
    ['--warden-root', 'wardenRoot'], ['--timeout', 'timeoutMs'],
  ]);
  const seen = new Set();
  for (let i = 0; i < separator; i += 2) {
    const key = keys.get(argv[i]), value = argv[i + 1];
    if (!key || seen.has(key) || i + 1 >= separator || !value) throw new CollectorError('usage');
    seen.add(key);
    opts[key] = value;
  }
  if (!shortText(opts.label) || !shortText(opts.runnerVersion) || !opts.out) throw new CollectorError('usage');
  if (!/^\d+$/.test(String(opts.timeoutMs))) throw new CollectorError('usage');
  opts.timeoutMs = Number(opts.timeoutMs);
  if (!Number.isSafeInteger(opts.timeoutMs) || opts.timeoutMs < 100 || opts.timeoutMs > 600_000) throw new CollectorError('usage');
  opts.command = argv[separator + 1];
  opts.args = argv.slice(separator + 2);
  checkArguments(opts.command, opts.args);
  opts.wardenRoot = resolve(opts.wardenRoot);
  opts.out = resolve(opts.out);
  return opts;
}

async function sourceHashes(root) {
  const hashes = {};
  try {
    for (const file of SOURCE_FILES) hashes[file] = sha256(await readFile(resolve(root, file)));
  } catch { throw new CollectorError('warden-files'); }
  return hashes;
}

export async function loadWarden(root) {
  let pkg;
  try { pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')); }
  catch { throw new CollectorError('warden-files'); }
  if (pkg.name !== EXPECTED_PACKAGE || pkg.version !== EXPECTED_VERSION) throw new CollectorError('warden-version');
  const hashes = await sourceHashes(root);
  let client, mtl;
  try {
    client = await import(pathToFileURL(resolve(root, 'dist/mcp-client.js')).href);
    mtl = await import(pathToFileURL(resolve(root, 'dist/mtl.js')).href);
  } catch { throw new CollectorError('warden-files'); }
  if (typeof client.fetchServer !== 'function' || typeof mtl.mtlToolSetDigest !== 'function') throw new CollectorError('warden-files');
  return { fetchServer: client.fetchServer, mtlToolSetDigest: mtl.mtlToolSetDigest, hashes };
}

function jsonBytes(value) { return Buffer.from(JSON.stringify(value, null, 2) + '\n'); }

/** Verify files against capture metadata and recompute MTL/1 from saved tools. */
export async function verifyCapture(out, mtlToolSetDigest) {
  try {
    const captureBytes = await readFile(resolve(out, 'capture.json'));
    const capture = JSON.parse(captureBytes);
    const checksums = await readFile(resolve(out, 'SHA256SUMS'), 'utf8');
    const expected = [];
    for (const file of ['tools.json', 'initialize.json']) {
      const bytes = await readFile(resolve(out, file));
      if (capture.files[file]?.sha256 !== sha256(bytes) || capture.files[file]?.bytes !== bytes.length) throw new Error();
      expected.push(`${sha256(bytes)}  ${file}`);
    }
    expected.push(`${sha256(captureBytes)}  capture.json`);
    if (checksums !== expected.join('\n') + '\n') throw new Error();
    const tools = JSON.parse(await readFile(resolve(out, 'tools.json'), 'utf8'));
    if (!Array.isArray(tools) || capture.toolCount !== tools.length || mtlToolSetDigest(tools) !== capture.mtlToolSetDigest) throw new Error();
    return capture;
  } catch { throw new CollectorError('verification'); }
}

export async function collect(opts) {
  const warden = await loadWarden(opts.wardenRoot);
  try { await mkdir(opts.out, { mode: 0o700 }); }
  catch (err) { throw new CollectorError(err?.code === 'EEXIST' ? 'output-exists' : 'write'); }
  const startedAt = new Date().toISOString();
  let fetched;
  try {
    fetched = await warden.fetchServer({ name: opts.label, transport: 'stdio', command: opts.command, args: opts.args }, {
      timeoutMs: opts.timeoutMs, clientVersion: EXPECTED_VERSION,
      // Deliberately inherit the caller's environment; never serialize its values.
    });
  } catch (err) { throw new CollectorError('mcp-fetch', err?.kind); }
  const finishedAt = new Date().toISOString();
  if (JSON.stringify(await sourceHashes(opts.wardenRoot)) !== JSON.stringify(warden.hashes)) throw new CollectorError('warden-changed');
  let digest;
  try { digest = warden.mtlToolSetDigest(fetched.tools); }
  catch { throw new CollectorError('digest'); }
  const toolsBytes = jsonBytes(fetched.tools);
  const initializeBytes = jsonBytes({
    serverInfo: fetched.serverInfo ?? null,
    protocolVersion: fetched.protocolVersion ?? null,
    instructions: fetched.instructions ?? null,
  });
  const capture = {
    format: 'warden-launcher-evidence/1', label: opts.label, startedAt, finishedAt,
    runtime: { platform: process.platform, arch: process.arch, node: process.version },
    launcher: { command: opts.command, args: opts.args },
    runnerVersion: { value: opts.runnerVersion, source: 'publisher-reported', independentlyVerified: false },
    environment: { inherited: true, valuesRecorded: false },
    workingDirectory: { inherited: true, pathRecorded: false },
    timeoutMs: opts.timeoutMs,
    client: { package: EXPECTED_PACKAGE, version: EXPECTED_VERSION, internalApi: true, sourceSha256: warden.hashes },
    collectorSha256: sha256(await readFile(fileURLToPath(import.meta.url))),
    toolCount: fetched.tools.length, mtlToolSetDigest: digest,
    digestScope: ['name', 'description', 'inputSchema', 'outputSchema (when present)'],
    digestExcludes: ['initialize.instructions', 'serverInfo', 'other advertised tool fields'],
    toolsRepresentation: {
      wireTranscript: false,
      note: "Full tools returned by WARDEN's paginated tools/list client. Missing description is filled with ''; missing inputSchema with {type:'object',properties:{}}. Other tool fields are retained.",
    },
    untrustedContent: ['tools.json', 'initialize.json (including instructions; stored as data, never followed)'],
    files: {
      'tools.json': { sha256: sha256(toolsBytes), bytes: toolsBytes.length },
      'initialize.json': { sha256: sha256(initializeBytes), bytes: initializeBytes.length },
    },
  };
  const captureBytes = jsonBytes(capture);
  const checksums = [
    `${sha256(toolsBytes)}  tools.json`, `${sha256(initializeBytes)}  initialize.json`,
    `${sha256(captureBytes)}  capture.json`,
  ].join('\n') + '\n';
  try {
    for (const [file, bytes] of [
      ['tools.json', toolsBytes], ['initialize.json', initializeBytes], ['capture.json', captureBytes], ['SHA256SUMS', checksums],
    ]) await writeFile(resolve(opts.out, file), bytes, { flag: 'wx', mode: 0o600 });
  } catch { throw new CollectorError('write'); }
  await verifyCapture(opts.out, warden.mtlToolSetDigest);
  return capture;
}

export function safeError(err) {
  const kind = err instanceof CollectorError ? err.kind : 'internal';
  const clientKind = err instanceof CollectorError && CLIENT_KINDS.has(err.clientKind) ? ` clientKind=${err.clientKind}` : '';
  return `launcher-evidence: CollectorError kind=${kind}${clientKind}\n`;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.help) process.stdout.write(HELP);
    else {
      await collect(opts);
      process.stdout.write('launcher-evidence: capture complete; review all files before sharing\n');
    }
  } catch (err) {
    // Never print third-party errors, stack traces or captured child stderr.
    process.stderr.write(safeError(err));
    process.exitCode = 1;
  }
}
