import { spawn } from 'node:child_process';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import { isIP } from 'node:net';
import type { McpServerRef, ToolDef } from './types.js';
import { WrapFrames, readFrames } from './wrap-wire.js';
import { listAllTools, SCAN_LIST_LIMITS, type ToolPage } from './tool-list.js';

/**
 * A one-shot MCP client for `scan`: initialize, list every tool, close.
 *
 * It never calls a tool, reads a resource or answers a sampling request. Over
 * stdio it starts the server the way the client config says to — which runs
 * that program, exactly as the MCP client would — so `scan --no-launch` exists
 * for places (CI on a pull request) where running it is not acceptable.
 */
export const PROTOCOL_VERSION = '2025-06-18';
export const RESPONSE_BYTES = SCAN_LIST_LIMITS.maxBytes;

export interface FetchedServer {
  tools: ToolDef[];
  serverInfo?: { name?: string; version?: string };
  protocolVersion?: string;
  instructions?: string;
}

export interface ClientOptions {
  timeoutMs: number;
  clientVersion: string;
  /** Remote servers only: refuse loopback, private, link-local and metadata addresses. */
  publicOnly?: boolean;
  headers?: Record<string, string>;
  /** stdio: base environment for the child (defaults to process.env). */
  baseEnv?: NodeJS.ProcessEnv;
  cwd?: string;
}

export class McpClientError extends Error {
  constructor(readonly kind: 'timeout' | 'spawn' | 'protocol' | 'http' | 'network' | 'refused', message: string) { super(message); this.name = 'McpClientError'; }
}

type Rpc = { jsonrpc?: string; id?: unknown; method?: string; params?: unknown; result?: unknown; error?: { code?: number; message?: string } };

function initParams(version: string) {
  return { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'warden-scan', version } };
}

function readInit(result: unknown): Omit<FetchedServer, 'tools'> {
  if (!result || typeof result !== 'object') throw new McpClientError('protocol', 'initialize returned no result');
  const r = result as Record<string, unknown>;
  const info = r.serverInfo && typeof r.serverInfo === 'object' ? r.serverInfo as Record<string, unknown> : {};
  return {
    protocolVersion: typeof r.protocolVersion === 'string' ? r.protocolVersion : undefined,
    serverInfo: { name: typeof info.name === 'string' ? info.name : undefined, version: typeof info.version === 'string' ? info.version : undefined },
    instructions: typeof r.instructions === 'string' ? r.instructions : undefined,
  };
}

/** Answer what a well-behaved client must answer; refuse everything else. */
function answerServerRequest(msg: Rpc): Rpc {
  if (msg.method === 'ping') return { jsonrpc: '2.0', id: msg.id, result: {} };
  if (msg.method === 'roots/list') return { jsonrpc: '2.0', id: msg.id, result: { roots: [] } };
  return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'warden scan does not serve this request' } };
}

// ── stdio ────────────────────────────────────────────────────────────────────

export async function fetchStdio(ref: McpServerRef, opts: ClientOptions): Promise<FetchedServer> {
  if (!ref.command) throw new McpClientError('spawn', 'no command');
  const child = spawn(ref.command, ref.args ?? [], {
    stdio: ['pipe', 'pipe', 'pipe'], cwd: opts.cwd,
    env: { ...(opts.baseEnv ?? process.env), ...(ref.env ?? {}) },
  });
  let stderrTail = '';
  child.stderr.on('data', chunk => { stderrTail = (stderrTail + String(chunk)).slice(-2000); });
  const pending = new Map<string, { resolve: (m: { msg: Rpc; bytes: number }) => void; reject: (e: Error) => void }>();
  let failure: Error | undefined;
  const fail = (err: Error) => {
    if (failure) return;
    failure = err;
    for (const p of pending.values()) p.reject(err);
    pending.clear();
  };
  child.on('error', e => fail(new McpClientError('spawn', `could not start: ${e.message}`)));
  child.on('close', code => fail(new McpClientError('spawn', `exited (code ${code ?? 'signal'}) before answering${stderrTail ? `: ${lastLine(stderrTail)}` : ''}`)));
  child.stdin.on('error', () => {});
  const send = (msg: object) => { if (!child.stdin.destroyed) child.stdin.write(JSON.stringify(msg) + '\n'); };
  readFrames(child.stdout, new WrapFrames('ndjson'), body => {
    let msg: Rpc;
    try { msg = JSON.parse(body); } catch { return; } // a stray log line on stdout is not our concern
    if (!msg || typeof msg !== 'object') return;
    if (msg.method !== undefined) { if (msg.id !== undefined && msg.id !== null) send(answerServerRequest(msg)); return; }
    if (typeof msg.id !== 'string') return;
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    p.resolve({ msg, bytes: Buffer.byteLength(body) });
  }, e => fail(new McpClientError('protocol', e instanceof Error ? e.message : String(e))), () => {});

  let seq = 0;
  const call = (method: string, params: object) => new Promise<{ msg: Rpc; bytes: number }>((resolve, reject) => {
    if (failure) { reject(failure); return; }
    const id = `warden-scan:${seq++}`;
    pending.set(id, { resolve, reject });
    send({ jsonrpc: '2.0', id, method, params });
  });
  const result = async (method: string, params: object) => {
    const { msg, bytes } = await call(method, params);
    if (msg.error) throw new McpClientError('protocol', `${method} failed: ${msg.error.message ?? JSON.stringify(msg.error)}`);
    return { result: msg.result, bytes };
  };

  const work = (async () => {
    const init = readInit((await result('initialize', initParams(opts.clientVersion))).result);
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const tools = await listAllTools(cursor => result('tools/list', cursor === undefined ? {} : { cursor }) as Promise<ToolPage>, SCAN_LIST_LIMITS);
    return { ...init, tools };
  })();
  try { return await withTimeout(work, opts.timeoutMs, () => new McpClientError('timeout', `no answer within ${opts.timeoutMs} ms${stderrTail ? `: ${lastLine(stderrTail)}` : ''}`)); }
  finally { stopChild(child); }
}

function stopChild(child: ReturnType<typeof spawn>): void {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.stdin?.end(); } catch { /* already closed */ }
  const term = setTimeout(() => { try { child.kill('SIGTERM'); } catch { /* gone */ } }, 1500);
  const kill = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, 4000);
  term.unref(); kill.unref();
  child.once('close', () => { clearTimeout(term); clearTimeout(kill); });
  child.stdout?.destroy(); child.stderr?.destroy();
  child.unref();
}

/** The most telling stderr line: the last one that is not a stack frame or Node's version footer. */
function lastLine(text: string): string {
  const lines = text.trim().split('\n').map(l => l.trimEnd()).filter(l => l && !/^\s+at\s/.test(l) && !/^Node\.js v\d/.test(l) && !/^\s*\^+\s*$/.test(l));
  const errorLine = [...lines].reverse().find(l => /error|cannot|not found|missing|denied|refused/i.test(l));
  return (errorLine ?? lines[lines.length - 1] ?? '').slice(0, 300);
}

function withTimeout<T>(work: Promise<T>, ms: number, error: () => Error): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(error()), ms); });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

// ── address policy for remote servers ────────────────────────────────────────

/** True for addresses a CI scan must not be steered into: loopback, private, link-local, metadata, CGNAT, ULA. */
export function isNonPublicAddress(address: string): boolean {
  const v = isIP(address);
  if (v === 4) {
    const [a, b] = address.split('.').map(Number) as [number, number];
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (v === 6) {
    const x = address.toLowerCase();
    if (x === '::' || x === '::1') return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(x);
    if (mapped) return isNonPublicAddress(mapped[1]!);
    return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(x) || x.startsWith('fd00:ec2:');
  }
  return true;
}

function guardedLookup(publicOnly: boolean) {
  return (hostname: string, options: object, callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void) => {
    dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) { callback(err, ''); return; }
      const list = addresses as LookupAddress[];
      if (publicOnly) {
        const bad = list.find(a => isNonPublicAddress(a.address));
        if (bad) { callback(Object.assign(new Error(`${hostname} resolves to a non-public address (${bad.address}); refused by --public-only`), { code: 'EWARDENREFUSED' }), ''); return; }
      }
      if ((options as { all?: boolean }).all) callback(null, list);
      else callback(null, list[0]!.address, list[0]!.family);
    });
  };
}

// ── HTTP transports ──────────────────────────────────────────────────────────

interface HttpReply { status: number; headers: IncomingMessage['headers']; res: IncomingMessage }

function open(url: URL, method: 'GET' | 'POST', headers: Record<string, string>, body: string | undefined, opts: ClientOptions, signal: AbortSignal): Promise<HttpReply> {
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return Promise.reject(new McpClientError('refused', `unsupported URL scheme ${url.protocol}`));
  if (opts.publicOnly && isIP(url.hostname.replace(/^\[|\]$/g, '')) && isNonPublicAddress(url.hostname.replace(/^\[|\]$/g, ''))) {
    return Promise.reject(new McpClientError('refused', `${url.hostname} is a non-public address; refused by --public-only`));
  }
  const fn = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = fn(url, { method, headers: { 'user-agent': `warden-scan/${opts.clientVersion}`, ...headers, ...(body ? { 'content-length': String(Buffer.byteLength(body)) } : {}) }, lookup: guardedLookup(!!opts.publicOnly) as never, signal },
      res => resolve({ status: res.statusCode ?? 0, headers: res.headers, res }));
    req.on('error', e => reject((e as NodeJS.ErrnoException).code === 'EWARDENREFUSED' ? new McpClientError('refused', e.message)
      : signal.aborted ? new McpClientError('timeout', 'timed out') : new McpClientError('network', e.message)));
    if (body) req.write(body);
    req.end();
  });
}

async function readAll(res: IncomingMessage, limit = RESPONSE_BYTES): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of res) {
    total += (chunk as Buffer).length;
    if (total > limit) { res.destroy(); throw new McpClientError('protocol', `response exceeds ${limit} bytes`); }
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Incremental SSE parser: yields `{event, data}` per dispatched event. */
export class SseParser {
  private buf = '';
  private event = '';
  private data: string[] = [];
  push(text: string): Array<{ event: string; data: string }> {
    this.buf += text;
    const out: Array<{ event: string; data: string }> = [];
    let nl: number;
    while ((nl = this.buf.search(/\r\n|\r|\n/)) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + (this.buf.startsWith('\r\n', nl) ? 2 : 1));
      if (line === '') {
        if (this.data.length) out.push({ event: this.event || 'message', data: this.data.join('\n') });
        this.event = ''; this.data = [];
        continue;
      }
      if (line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '');
      if (field === 'event') this.event = value;
      else if (field === 'data') this.data.push(value);
    }
    if (this.buf.length > RESPONSE_BYTES) throw new McpClientError('protocol', 'SSE line exceeds the response limit');
    return out;
  }
  end(): Array<{ event: string; data: string }> { return this.push('\n\n'); }
}

function parseRpc(text: string): Rpc[] {
  let v: unknown;
  try { v = JSON.parse(text); } catch { return []; }
  return (Array.isArray(v) ? v : [v]).filter((m): m is Rpc => !!m && typeof m === 'object');
}

/** Streamable HTTP (2025-03-26 and later): every request is a POST; the reply is JSON or an SSE stream. */
export async function fetchStreamableHttp(ref: McpServerRef, opts: ClientOptions): Promise<FetchedServer> {
  const url = new URL(ref.url!);
  const controller = new AbortController();
  let session: string | undefined, negotiated: string | undefined, seq = 0;
  const post = async (msg: Rpc & { method: string }, expectReply: boolean): Promise<{ msg?: Rpc; bytes: number }> => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}), 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
    if (session) headers['mcp-session-id'] = session;
    if (negotiated) headers['mcp-protocol-version'] = negotiated;
    const body = JSON.stringify(msg);
    const reply = await open(url, 'POST', headers, body, opts, controller.signal);
    const sid = reply.headers['mcp-session-id'];
    if (typeof sid === 'string' && sid) session = sid;
    if (reply.status >= 300 && reply.status < 400) { reply.res.resume(); throw new McpClientError('http', `HTTP ${reply.status} redirect (not followed)`); }
    if (reply.status === 401 || reply.status === 403) { reply.res.resume(); throw new McpClientError('http', `HTTP ${reply.status}: the server needs credentials this config does not carry`); }
    if (reply.status >= 400) { reply.res.resume(); throw new McpClientError('http', `HTTP ${reply.status}`); }
    if (!expectReply) { reply.res.resume(); return { bytes: 0 }; }
    const type = String(reply.headers['content-type'] ?? '');
    if (type.includes('text/event-stream')) {
      const parser = new SseParser();
      let bytes = 0;
      for await (const chunk of reply.res) {
        bytes += (chunk as Buffer).length;
        if (bytes > RESPONSE_BYTES) { reply.res.destroy(); throw new McpClientError('protocol', 'SSE response exceeds the limit'); }
        for (const ev of parser.push(String(chunk))) {
          for (const m of parseRpc(ev.data)) {
            if (m.id === msg.id && m.method === undefined) { reply.res.destroy(); return { msg: m, bytes }; }
          }
        }
      }
      for (const ev of parser.end()) for (const m of parseRpc(ev.data)) if (m.id === msg.id && m.method === undefined) return { msg: m, bytes };
      throw new McpClientError('protocol', `${msg.method}: the event stream ended without a reply`);
    }
    const text = await readAll(reply.res);
    const m = parseRpc(text).find(r => r.id === msg.id);
    if (!m) throw new McpClientError('protocol', `${msg.method}: no JSON-RPC reply in the response`);
    return { msg: m, bytes: Buffer.byteLength(text) };
  };
  const call = async (method: string, params: object) => {
    const { msg, bytes } = await post({ jsonrpc: '2.0', id: `warden-scan:${seq++}`, method, params }, true);
    if (msg!.error) throw new McpClientError('protocol', `${method} failed: ${msg!.error.message ?? JSON.stringify(msg!.error)}`);
    return { result: msg!.result, bytes };
  };
  const work = (async () => {
    const init = readInit((await call('initialize', initParams(opts.clientVersion))).result);
    negotiated = init.protocolVersion;
    await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, false).catch(() => {});
    const tools = await listAllTools(cursor => call('tools/list', cursor === undefined ? {} : { cursor }), SCAN_LIST_LIMITS);
    return { ...init, tools };
  })();
  try { return await withTimeout(work, opts.timeoutMs, () => new McpClientError('timeout', `no answer within ${opts.timeoutMs} ms`)); }
  finally {
    controller.abort();
    if (session) {
      // Courtesy: end the session. Never awaited past a short bound, never fatal.
      const end = new AbortController();
      const t = setTimeout(() => end.abort(), 2000); t.unref();
      open(url, 'GET', {}, undefined, opts, end.signal).then(r => r.res.resume(), () => {}).finally(() => clearTimeout(t));
    }
  }
}

/** Legacy HTTP+SSE (2024-11-05): GET opens the stream, its `endpoint` event names where to POST. */
export async function fetchLegacySse(ref: McpServerRef, opts: ClientOptions): Promise<FetchedServer> {
  const url = new URL(ref.url!);
  const controller = new AbortController();
  const work = (async () => {
    const reply = await open(url, 'GET', { ...(opts.headers ?? {}), accept: 'text/event-stream' }, undefined, opts, controller.signal);
    if (reply.status >= 400) { reply.res.resume(); throw new McpClientError('http', `HTTP ${reply.status}`); }
    if (reply.status >= 300) { reply.res.resume(); throw new McpClientError('http', `HTTP ${reply.status} redirect (not followed)`); }
    const parser = new SseParser();
    const pending = new Map<string, (m: { msg: Rpc; bytes: number }) => void>();
    let endpoint: URL | undefined, endpointReady: (u: URL) => void = () => {}, streamError: (e: Error) => void = () => {};
    const ready = new Promise<URL>((resolve, reject) => { endpointReady = resolve; streamError = reject; });
    let bytes = 0;
    reply.res.on('data', chunk => {
      bytes += (chunk as Buffer).length;
      if (bytes > RESPONSE_BYTES * 4) { reply.res.destroy(); streamError(new McpClientError('protocol', 'SSE stream exceeds the limit')); return; }
      for (const ev of parser.push(String(chunk))) {
        if (ev.event === 'endpoint' && !endpoint) {
          const target = new URL(ev.data.trim(), url);
          if (target.origin !== url.origin) { streamError(new McpClientError('refused', `endpoint event points at another origin (${target.origin})`)); return; }
          endpoint = target; endpointReady(target); continue;
        }
        for (const m of parseRpc(ev.data)) {
          if (m.method !== undefined) {
            if (m.id !== undefined && m.id !== null && endpoint) void open(endpoint, 'POST', { ...(opts.headers ?? {}), 'content-type': 'application/json' }, JSON.stringify(answerServerRequest(m)), opts, controller.signal).then(r => r.res.resume(), () => {});
            continue;
          }
          const resolve = typeof m.id === 'string' ? pending.get(m.id) : undefined;
          if (resolve) { pending.delete(m.id as string); resolve({ msg: m, bytes: Buffer.byteLength(ev.data) }); }
        }
      }
    });
    reply.res.on('error', e => streamError(new McpClientError('network', e.message)));
    reply.res.on('end', () => streamError(new McpClientError('protocol', 'the event stream closed')));
    const postUrl = await ready;
    let seq = 0;
    const call = async (method: string, params: object) => {
      const id = `warden-scan:${seq++}`;
      const answered = new Promise<{ msg: Rpc; bytes: number }>((resolve, reject) => { pending.set(id, resolve); ready.catch(reject); reply.res.once('end', () => reject(new McpClientError('protocol', 'the event stream closed'))); });
      const r = await open(postUrl, 'POST', { ...(opts.headers ?? {}), 'content-type': 'application/json' }, JSON.stringify({ jsonrpc: '2.0', id, method, params }), opts, controller.signal);
      r.res.resume();
      if (r.status >= 400) throw new McpClientError('http', `${method}: HTTP ${r.status}`);
      const { msg, bytes: n } = await answered;
      if (msg.error) throw new McpClientError('protocol', `${method} failed: ${msg.error.message ?? JSON.stringify(msg.error)}`);
      return { result: msg.result, bytes: n };
    };
    const init = readInit((await call('initialize', initParams(opts.clientVersion))).result);
    await open(postUrl, 'POST', { ...(opts.headers ?? {}), 'content-type': 'application/json' }, JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }), opts, controller.signal).then(r => r.res.resume(), () => {});
    const tools = await listAllTools(cursor => call('tools/list', cursor === undefined ? {} : { cursor }), SCAN_LIST_LIMITS);
    return { ...init, tools };
  })();
  try { return await withTimeout(work, opts.timeoutMs, () => new McpClientError('timeout', `no answer within ${opts.timeoutMs} ms`)); }
  finally { controller.abort(); }
}

/** Dispatch on the server's transport. */
export function fetchServer(ref: McpServerRef, opts: ClientOptions): Promise<FetchedServer> {
  if (ref.transport === 'stdio') return fetchStdio(ref, opts);
  if (ref.transport === 'sse') return fetchLegacySse(ref, opts);
  return fetchStreamableHttp(ref, opts);
}
