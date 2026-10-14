/**
 * `warden-mcp declare` — for a server's publisher: the tool sets it lists under conditions HISTOR's
 * sandbox does not have (a launcher's runner installed, one runner per operating system, a real
 * key), written the way HISTOR reads them.
 *
 * A declaration goes in the server.json published to the official MCP registry
 * (`_meta` → `io.modelcontextprotocol.registry/publisher-provided` → `dev.modelmarket.histor/tool-sets`),
 * or in a file on the publisher's own domain that the entry points at with `url`. The file changes
 * with every runner release without a new registry entry; HISTOR reads it every hour.
 *
 *   warden-mcp declare --when "runner 1.4, macOS" --out mcp-tool-sets.json -- npx -y @acme/launcher
 *   warden-mcp declare --server-json --link https://acme.dev/.well-known/mcp-tool-sets.json
 *   warden-mcp declare --check https://acme.dev/.well-known/mcp-tool-sets.json --name dev.acme/launcher
 *
 * The rules here are HISTOR's (histor/histor/declared.py), so what this command accepts HISTOR takes.
 */
import { readFile, writeFile, rename } from 'node:fs/promises';
import { fetchServer, McpClientError, type FetchedServer } from './mcp-client.js';
import { mtlToolSetDigest, MtlError } from './mtl.js';
import { packageVersion } from './mcp-rpc.js';
import { displaySafe } from './sanitize.js';
import type { McpServerRef } from './types.js';

export const PUBLISHER_PROVIDED = 'io.modelcontextprotocol.registry/publisher-provided';
export const DECLARATION_FIELD = 'dev.modelmarket.histor/tool-sets';
/** In the registry entry: the registry keeps ~4 KB of publisher-provided metadata. */
export const MAX_ENTRY_SETS = 8;
/** In a file on the publisher's domain: runner versions × operating systems. */
export const MAX_FILE_SETS = 64;
export const MAX_WHEN = 200;
export const MAX_FILE_BYTES = 64 * 1024;
const MAX_TOOLS = 5000;
const SRI = /^sha256-[A-Za-z0-9+/]{43}=$/;
const GITHUB_USER = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;

export interface DeclaredSet { digest: string; count?: number; when?: string }
export interface DeclarationFile { mtl: '1'; sets: DeclaredSet[] }

export class DeclareError extends Error {
  constructor(message: string) { super(message); this.name = 'DeclareError'; }
}

/** The condition as one line of visible text: control and format characters (zero-width, bidi overrides) dropped. */
export function cleanWhen(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const text = value.replace(/[\t\r\n]/g, ' ').replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}]/gu, '').split(/\s+/).filter(Boolean).join(' ');
  return text ? [...text].slice(0, MAX_WHEN).join('') : undefined;
}

/**
 * Why HISTOR will not read a declaration file at `url` for `serverName`, or undefined. The file must
 * be on the domain the registry verified for the server's namespace or a subdomain (`ai.acme/x` →
 * acme.ai); for `io.github.<user>/x`, on `<user>.github.io` or under `/<user>/` on raw or gist files.
 */
export function urlRefusal(url: unknown, serverName: string): string | undefined {
  if (typeof url !== 'string' || !url || url.length > 2000) return '"url" must be an https URL';
  // Scheme first, as HISTOR's urlsplit does: "not a url" is an answer about https, not about parsing.
  if (!/^https:/i.test(url)) return '"url" must be https';
  let parts: URL;
  try { parts = new URL(url); } catch { return '"url" does not parse'; }
  if (parts.username || parts.password) return '"url" must not carry credentials';
  if (parts.port && parts.port !== '443') return '"url" must use the default https port';
  const host = parts.hostname.toLowerCase().replace(/\.$/, '');
  const namespace = serverName.split('/', 1)[0]!.trim().toLowerCase();
  if (namespace.startsWith('io.github.')) {
    const user = namespace.slice('io.github.'.length);
    if (!GITHUB_USER.test(user)) return 'the server name has no GitHub user HISTOR can bind the file to';
    const path = parts.pathname.toLowerCase();
    if (host === `${user}.github.io` || (['raw.githubusercontent.com', 'gist.githubusercontent.com'].includes(host) && path.startsWith(`/${user}/`))) return undefined;
    return `"url" must be on ${user}.github.io or under /${user}/ on raw.githubusercontent.com, the account the registry verified`;
  }
  const labels = namespace.split('.').filter(Boolean);
  if (labels.length < 2) return 'the server name has no domain HISTOR can bind the file to';
  const domain = [...labels].reverse().join('.');
  if (host === domain || host.endsWith(`.${domain}`)) return undefined;
  return `"url" must be on ${domain} or a subdomain, the domain the registry verified for ${namespace}`;
}

/** Validated sets from a `sets` list, and why any entry was skipped — HISTOR's rules. */
export function parseSets(entries: unknown, limit: number): { sets: DeclaredSet[]; ignored: string[] } {
  if (!Array.isArray(entries) || !entries.length) return { sets: [], ignored: ['"sets" must be a non-empty list'] };
  const sets: DeclaredSet[] = [], ignored: string[] = [], seen = new Set<string>();
  for (let i = 0; i < entries.length; i++) {
    if (sets.length === limit) { ignored.push(`sets[${i}:]: more than ${limit} sets`); break; }
    const e = entries[i] as Record<string, unknown> | null;
    if (!e || typeof e !== 'object' || Array.isArray(e)) { ignored.push(`sets[${i}]: not an object`); continue; }
    if (typeof e.digest !== 'string' || !SRI.test(e.digest)) { ignored.push(`sets[${i}]: digest is not an MTL/1 tool-set digest (sha256-<base64>)`); continue; }
    if (seen.has(e.digest)) { ignored.push(`sets[${i}]: the same digest twice`); continue; }
    if (e.count !== undefined && e.count !== null && (typeof e.count !== 'number' || !Number.isInteger(e.count) || e.count < 0 || e.count > MAX_TOOLS)) {
      ignored.push(`sets[${i}]: count must be an integer from 0 to ${MAX_TOOLS}`); continue;
    }
    seen.add(e.digest);
    const out: DeclaredSet = { digest: e.digest };
    if (typeof e.count === 'number') out.count = e.count;
    const when = cleanWhen(e.when);
    if (when) out.when = when;
    sets.push(out);
  }
  return { sets, ignored };
}

/** A declaration file, read the way HISTOR reads it. Throws when HISTOR would take nothing from it. */
export function parseDeclarationFile(text: string): { sets: DeclaredSet[]; ignored: string[] } {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { throw new DeclareError('the file is not JSON'); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new DeclareError('the file is not a JSON object');
  const d = doc as Record<string, unknown>;
  if (d.mtl !== '1') throw new DeclareError('"mtl" must be "1"');
  if (Array.isArray(d.sets) && d.sets.length === 0) return { sets: [], ignored: [] };
  const parsed = parseSets(d.sets, MAX_FILE_SETS);
  if (!parsed.sets.length) throw new DeclareError(parsed.ignored.slice(0, 3).join('; ') || 'no valid sets');
  return parsed;
}

/** `file` with `set` in it: a set with the same digest is replaced, the others are kept in order. */
export function withSet(file: DeclarationFile | undefined, set: DeclaredSet, limit = MAX_FILE_SETS): DeclarationFile {
  const sets = (file?.sets ?? []).filter(s => s.digest !== set.digest);
  const at = (file?.sets ?? []).findIndex(s => s.digest === set.digest);
  if (at >= 0) sets.splice(at, 0, set); else sets.push(set);
  if (sets.length > limit) throw new DeclareError(`the file would hold ${sets.length} sets; HISTOR reads at most ${limit}. Remove sets for runners nobody uses any more.`);
  return { mtl: '1', sets };
}

/** The server.json `_meta` block for the registry entry. */
export function serverJsonBlock(sets: DeclaredSet[], url?: string): Record<string, unknown> {
  if (sets.length > MAX_ENTRY_SETS) throw new DeclareError(`a registry entry holds at most ${MAX_ENTRY_SETS} sets; put them in a file and link it with --link`);
  const block: Record<string, unknown> = { mtl: '1' };
  if (sets.length) block.sets = sets;
  if (url) block.url = url;
  return { _meta: { [PUBLISHER_PROVIDED]: { [DECLARATION_FIELD]: block } } };
}

/** The set this machine gets from a server, ready to declare. */
export function setFrom(fetched: FetchedServer, when?: string): DeclaredSet {
  let digest: string;
  try { digest = mtlToolSetDigest(fetched.tools); }
  catch (err) { throw new DeclareError(`the tool set has no MTL/1 digest (${err instanceof MtlError ? err.code : String(err)}), so it cannot be declared or compared`); }
  const set: DeclaredSet = { digest, count: fetched.tools.length };
  const w = cleanWhen(when);
  if (w) set.when = w;
  return set;
}

export interface DeclareOptions {
  mode: 'set' | 'check';
  when?: string;
  out?: string;
  serverJson?: boolean;
  link?: string;
  /** The server to read: a stdio command or an http(s) URL. */
  ref?: McpServerRef;
  timeoutMs: number;
  /** --check: a file URL (with `name`) or a local path. */
  check?: string;
  name?: string;
}

export const DECLARE_USAGE = `Usage:
  warden-mcp declare [--when TEXT] [--out FILE] -- COMMAND [ARGS...]
  warden-mcp declare [--when TEXT] [--out FILE] --url URL
  warden-mcp declare --server-json [--link URL] [--when TEXT] [-- COMMAND ... | --url URL]
  warden-mcp declare --check URL --name SERVER_NAME
  warden-mcp declare --check FILE

Starts the server the way a client would, digests its tools/list (MTL/1) and prints the set to
declare, so HISTOR and WARDEN can tell it apart from a set nobody has seen.

  --when TEXT        the condition this set needs, in your words (at most ${MAX_WHEN} characters),
                     e.g. "runner 1.4, macOS"
  --out FILE         add the set to this declaration file (created if missing; other sets kept,
                     the same digest replaced). Publish it on your own domain and link it from
                     server.json with "url" (--server-json --link prints that block)
  --server-json      print the server.json _meta block instead (sets inline, at most ${MAX_ENTRY_SETS})
  --link URL         with --server-json: point the entry at your declaration file
  --check URL --name SERVER_NAME
                     read a published declaration file the way HISTOR will: the domain must be the
                     one the registry verified for SERVER_NAME, https, no redirects, at most 64 KiB
  --check FILE       check a local declaration file's format
  --timeout MS       how long to wait for the server (default 60000)

Details: https://github.com/alexar76/histor/blob/main/docs/api.md#declaring-tool-sets-publishers`;

export class DeclareUsage extends Error {}

export function parseDeclareArgs(argv: string[]): DeclareOptions {
  const opts: DeclareOptions = { mode: 'set', timeoutMs: 60_000 };
  const dash = argv.indexOf('--');
  const own = dash >= 0 ? argv.slice(0, dash) : argv;
  const command = dash >= 0 ? argv.slice(dash + 1) : [];
  let url: string | undefined;
  for (let i = 0; i < own.length; i++) {
    const a = own[i]!;
    const value = () => { const v = own[++i]; if (v === undefined || v.startsWith('--')) throw new DeclareError(`${a} needs a value`); return v; };
    switch (a) {
      case '-h': case '--help': throw new DeclareUsage();
      case '--when': opts.when = value(); break;
      case '--out': opts.out = value(); break;
      case '--server-json': opts.serverJson = true; break;
      case '--link': opts.link = value(); break;
      case '--url': url = value(); break;
      case '--check': opts.mode = 'check'; opts.check = value(); break;
      case '--name': opts.name = value(); break;
      case '--timeout': {
        const n = Number(value());
        if (!Number.isInteger(n) || n < 1000 || n > 600_000) throw new DeclareError('--timeout must be 1000..600000 ms');
        opts.timeoutMs = n; break;
      }
      default: throw new DeclareError(`unknown option ${a}`);
    }
  }
  if (opts.mode === 'check') {
    if (command.length || url || opts.out || opts.serverJson) throw new DeclareError('--check reads a declaration file; it does not start a server');
    if (/^https?:\/\//i.test(opts.check!) && !opts.name) throw new DeclareError('--check URL needs --name, the server name in the registry (e.g. ai.acme/launcher)');
    return opts;
  }
  if (opts.out && opts.serverJson) throw new DeclareError('--out writes a declaration file, --server-json prints the registry block: pick one');
  if (opts.link && !opts.serverJson) throw new DeclareError('--link goes with --server-json');
  if (command.length && url) throw new DeclareError('give a command after -- or --url, not both');
  if (command.length) opts.ref = { id: 'declare', name: command.join(' '), transport: 'stdio', command: command[0]!, args: command.slice(1) };
  else if (url) {
    if (!/^https?:\/\//i.test(url)) throw new DeclareError('--url must be an http(s) URL');
    opts.ref = { id: 'declare', name: url, transport: 'http', url };
  } else if (!(opts.serverJson && opts.link)) throw new DeclareError('give the server: a command after --, or --url');
  return opts;
}

export interface DeclareDeps {
  fetch?: (ref: McpServerRef, timeoutMs: number) => Promise<FetchedServer>;
  /** --check URL: GET without redirects; returns status and at most MAX_FILE_BYTES + 1 bytes of body. */
  get?: (url: string, timeoutMs: number) => Promise<{ status: number; body: string }>;
  readFile?: (path: string) => Promise<string>;
  writeFile?: (path: string, text: string) => Promise<void>;
  out?: (text: string) => void;
  err?: (text: string) => void;
}

async function httpGet(url: string, timeoutMs: number): Promise<{ status: number; body: string }> {
  const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json', 'user-agent': `warden-mcp/${packageVersion()}` } });
  if (!res.body) return { status: res.status, body: '' };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value); size += value.length;
    if (size > MAX_FILE_BYTES) { await reader.cancel(); break; }
  }
  return { status: res.status, body: Buffer.concat(chunks).toString('utf8') };
}

async function atomicWrite(path: string, text: string): Promise<void> {
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, text);
  await rename(tmp, path);
}

/** Runs one `declare`; returns the exit code (0 ok, 1 refused or failed). */
export async function runDeclare(opts: DeclareOptions, deps: DeclareDeps = {}): Promise<number> {
  const out = deps.out ?? (t => process.stdout.write(t + '\n'));
  const err = deps.err ?? (t => process.stderr.write(t + '\n'));
  const read = deps.readFile ?? (p => readFile(p, 'utf8'));
  const write = deps.writeFile ?? atomicWrite;

  if (opts.mode === 'check') {
    const target = opts.check!;
    let text: string;
    if (/^https?:\/\//i.test(target)) {
      const refusal = urlRefusal(target, opts.name!);
      if (refusal) { err(`HISTOR will not read this file: ${refusal}.`); return 1; }
      let got: { status: number; body: string };
      try { got = await (deps.get ?? httpGet)(target, opts.timeoutMs); }
      catch (e) { err(`HISTOR could not read this file: the request failed (${displaySafe(e instanceof Error ? e.message : String(e), 200)}).`); return 1; }
      if (got.status >= 300 && got.status < 400) { err(`HISTOR will not read this file: http-${got.status}, and redirects are not followed. Serve it at this address.`); return 1; }
      if (got.status !== 200) { err(`HISTOR could not read this file: http-${got.status}.`); return 1; }
      if (Buffer.byteLength(got.body) > MAX_FILE_BYTES) { err(`HISTOR will not read this file: it is larger than ${MAX_FILE_BYTES / 1024} KiB.`); return 1; }
      text = got.body;
    } else {
      try { text = await read(target); } catch (e) { err(`cannot read ${displaySafe(target, 300)}: ${displaySafe(e instanceof Error ? e.message : String(e), 200)}`); return 1; }
    }
    let parsed: { sets: DeclaredSet[]; ignored: string[] };
    try { parsed = parseDeclarationFile(text); }
    catch (e) { err(`HISTOR will not take this file: ${e instanceof Error ? e.message : String(e)}.`); return 1; }
    for (const why of parsed.ignored) err(`skipped: ${why}`);
    out(parsed.sets.length
      ? `OK: HISTOR will take ${parsed.sets.length} set${parsed.sets.length === 1 ? '' : 's'} from this file${parsed.ignored.length ? ` (${parsed.ignored.length} skipped, above)` : ''}.`
      : 'OK: an empty "sets" list. HISTOR will withdraw every set this file declared before.');
    for (const s of parsed.sets) out(`  ${s.digest}${s.count !== undefined ? ` · ${s.count} tools` : ''}${s.when ? ` · "${s.when}"` : ''}`);
    return 0;
  }

  let set: DeclaredSet | undefined;
  if (opts.ref) {
    let fetched: FetchedServer;
    try {
      fetched = deps.fetch ? await deps.fetch(opts.ref, opts.timeoutMs)
        : await fetchServer(opts.ref, { timeoutMs: opts.timeoutMs, clientVersion: packageVersion(), cwd: process.cwd() });
    } catch (e) {
      const msg = e instanceof McpClientError ? e.message : e instanceof Error ? e.message : String(e);
      err(`the server did not answer tools/list: ${displaySafe(msg, 400)}`);
      return 1;
    }
    try { set = setFrom(fetched, opts.when); }
    catch (e) { err(e instanceof Error ? e.message : String(e)); return 1; }
    err(`${set.count} tool${set.count === 1 ? '' : 's'} · ${set.digest}${set.when ? ` · "${set.when}"` : ''}`);
  }

  if (opts.serverJson) {
    if (opts.link) {
      // The domain can only be checked against the server's registry name; say what the rule is.
      err(`"url" must be on the domain the registry verified for your server's namespace (ai.acme/x → acme.ai) or a subdomain; check it with --check ${opts.link} --name <server name>.`);
    }
    try { out(JSON.stringify(serverJsonBlock(set ? [set] : [], opts.link), null, 2)); }
    catch (e) { err(e instanceof Error ? e.message : String(e)); return 1; }
    return 0;
  }

  if (opts.out) {
    let existing: DeclarationFile | undefined;
    let text: string | undefined;
    try { text = await read(opts.out); } catch { text = undefined; }
    if (text !== undefined) {
      try { existing = { mtl: '1', sets: parseDeclarationFile(text).sets }; }
      catch (e) { err(`${displaySafe(opts.out, 300)} is not a declaration file HISTOR would read (${e instanceof Error ? e.message : String(e)}); not overwriting it.`); return 1; }
    }
    let next: DeclarationFile;
    try { next = withSet(existing, set!); }
    catch (e) { err(e instanceof Error ? e.message : String(e)); return 1; }
    await write(opts.out, JSON.stringify(next, null, 2) + '\n');
    const replaced = existing?.sets.some(s => s.digest === set!.digest);
    out(`${replaced ? 'Updated' : 'Added'} the set in ${opts.out} (${next.sets.length} set${next.sets.length === 1 ? '' : 's'}). Publish it on your domain; HISTOR reads it every hour.`);
    return 0;
  }

  out(JSON.stringify(set, null, 2));
  return 0;
}

/** `warden-mcp declare …` — returns the process exit code. */
export async function runDeclareCli(argv: string[]): Promise<number> {
  let opts: DeclareOptions;
  try { opts = parseDeclareArgs(argv); }
  catch (e) {
    if (e instanceof DeclareUsage) { process.stdout.write(DECLARE_USAGE + '\n'); return 0; }
    process.stderr.write(`warden-mcp declare: ${displaySafe(e instanceof Error ? e.message : String(e), 1000)}\nRun warden-mcp declare --help for options.\n`);
    return 2;
  }
  return runDeclare(opts);
}
