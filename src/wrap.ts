import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { constants } from 'node:os';
import { Warden, FilePinStore, pinToolsHash, displaySafe, StaticScanGate } from './index.js';
import type { ToolDef, WardenVerdict } from './types.js';
import { WrapFrames, readFrames } from './wrap-wire.js';
import { loadWrapFeed, wrapLogger, wrapServer, type WrapOptions } from './wrap-cli.js';
import { observe, vetAndPin, observationPath, WardenBlock, type Observation } from './wrap-state.js';
import { readState } from './state.js';

type Message = { jsonrpc: '2.0'; id?: string | number | null; method?: string; params?: Record<string, unknown>; result?: any; error?: unknown };
function parse(body: string): Message {
  const msg = JSON.parse(body);
  if (!msg || Array.isArray(msg) || msg.jsonrpc !== '2.0' ||
      (msg.id !== undefined && msg.id !== null && typeof msg.id !== 'string' && typeof msg.id !== 'number')) throw new Error('Invalid JSON-RPC message');
  return msg;
}
const LIST_BYTES = 1_048_576;

export async function runWrap(opts: WrapOptions): Promise<number> {
  const server = wrapServer(opts), log = wrapLogger(opts.auditOnly);
  const feed = await loadWrapFeed(opts), store = new FilePinStore(join(opts.stateDir, 'pins'));
  const warden = Warden.create({ policy: opts.policy, threatFeed: feed, store });
  if (opts.verdictLog) mkdirSync(dirname(opts.verdictLog), { recursive: true, mode: 0o700 });
  const record = (verdict: WardenVerdict) => {
    process.stderr.write(`warden: ${opts.auditOnly ? 'AUDIT-ONLY ' : ''}${verdict.allow ? 'ALLOW' : 'BLOCK'} ${displaySafe(server.id)} decidedBy=${displaySafe(verdict.decidedBy ?? '-')} score=${verdict.score.toFixed(2)} ${verdict.findings.map(f => `${displaySafe(f.code)}${f.tool ? `(${displaySafe(f.tool)})` : ''}`).join(' ')}\n`);
    if (opts.verdictLog) appendFileSync(opts.verdictLog, JSON.stringify({ timestamp: new Date().toISOString(), serverId: server.id,
      mode: opts.auditOnly ? 'AUDIT-ONLY' : 'ENFORCE', ...verdict }) + '\n', { mode: 0o600 });
  };
  const launch = await warden.vetLaunch(server); record(launch);
  const prior = await readState<Observation>(observationPath(opts.stateDir, server.id));
  const blockedLaunch = !opts.auditOnly && (!launch.allow || prior?.revoked);
  if (blockedLaunch) await observe(opts.stateDir, { server, policy: opts.policy });
  const reason = (v: WardenVerdict) => `blocked by WARDEN: ${v.findings.filter(f => !f.advisory).map(f => f.code).join(', ')}; warden-mcp pins status --id ${server.id}`;
  const frames = new WrapFrames();
  let child: ChildProcessWithoutNullStreams | undefined;
  let finished = false, closing = false, generation = 0, quarantined = true;
  // Why tools are withheld: a WARDEN decision or a change waits for the client to list again;
  // a check that merely failed to run (timeout, lock, child error) is retried by the next call.
  let quarantineKind: 'start' | 'changed' | 'blocked' | 'error' = 'start';
  let blockReason = blockedLaunch ? (prior?.revoked ? 'Approval revoked; run warden-mcp pins status --id ' + server.id : reason(launch)) : '';
  let visible: ToolDef[] = [];
  let refresh: Promise<ToolDef[]> | undefined;
  const prefix = `warden:${randomUUID()}:`;
  let seq = 0;
  const pending = new Map<string, { resolve: (value: { result: any; bytes: number }) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  // Every client request forwarded to the child, by id. A child response is delivered only
  // against one of these, once: a response to an id the client never sent to the child (its
  // tools/list, which this proxy answers) or already received is a forgery, not a reply.
  const tracked = new Map<string | number | null, { kind: 'initialize' | 'call' | 'other'; generation: number }>();
  let activeChecks = 0;
  let stopTimer: NodeJS.Timeout | undefined, killTimer: NodeJS.Timeout | undefined;

  return new Promise<number>(resolve => {
    const finish = (code: number) => {
      if (finished) return;
      finished = true;
      clearTimeout(stopTimer); clearTimeout(killTimer);
      for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new Error('MCP child exited')); }
      pending.clear();
      process.stdin.pause();
      process.removeListener('SIGTERM', signalStop); process.removeListener('SIGINT', signalStop);
      resolve(code);
    };
    const stop = () => {
      if (closing) return;
      closing = true; quarantined = true; generation++;
      if (!child) { finish(blockedLaunch ? 3 : 0); return; }
      child.stdin.end();
      stopTimer = setTimeout(() => child?.kill('SIGTERM'), 5000);
      killTimer = setTimeout(() => child?.kill('SIGKILL'), 9900);
    };
    const signalStop = () => stop();
    const fatal = (error: unknown) => { log.error(error instanceof Error ? error.message : String(error)); stop(); };
    const clientWrite = (body: string) => {
      if (finished) return;
      const data = frames.mode === 'lsp' ? `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}` : body + '\n';
      if (!process.stdout.write(data)) {
        child?.stdout.pause();
        process.stdout.once('drain', () => child?.stdout.resume());
      }
    };
    const send = (msg: object) => clientWrite(JSON.stringify(msg));
    const fail = (msg: Message, message: string, code = -32602) => {
      if (msg.id !== undefined) send({ jsonrpc: '2.0', id: msg.id, error: { code, message: displaySafe(message, 8192) } });
    };
    const childWrite = (body: string) => {
      if (!child || closing || finished || child.stdin.destroyed) throw new Error('MCP child unavailable');
      if (!child.stdin.write(body + '\n')) {
        process.stdin.pause();
        child.stdin.once('drain', () => { if (!closing) process.stdin.resume(); });
      }
    };
    const requestPage = (cursor?: string): Promise<{ result: any; bytes: number }> => new Promise((resolvePage, reject) => {
      const id = prefix + seq++;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('MCP tools/list timed out')); }, 10_000);
      pending.set(id, { resolve: resolvePage, reject, timer });
      try { childWrite(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params: cursor === undefined ? {} : { cursor } })); }
      catch (e) { clearTimeout(timer); pending.delete(id); reject(e); }
    });
    const listAll = async (): Promise<ToolDef[]> => {
      const tools: ToolDef[] = [], names = new Set<string>(), cursors = new Set<string>();
      let cursor: string | undefined, bytes = 0;
      for (let page = 0; page < 32; page++) {
        const response = await requestPage(cursor), listed = response.result;
        bytes += response.bytes;
        if (bytes > LIST_BYTES) throw new Error('MCP tools/list exceeds 1 MiB');
        if (!listed || !Array.isArray(listed.tools)) throw new Error('Invalid MCP tools/list');
        if (tools.length + listed.tools.length > 256) throw new Error('MCP tools/list exceeds 256 tools');
        for (const t of listed.tools) {
          if (!t || typeof t !== 'object' || Array.isArray(t) || typeof t.name !== 'string' || !t.name || names.has(t.name) ||
              (t.description !== undefined && typeof t.description !== 'string') || (t.title !== undefined && typeof t.title !== 'string')) throw new Error('Invalid or duplicate MCP tool definition');
          for (const key of ['inputSchema', 'outputSchema', 'annotations']) {
            if (t[key] !== undefined && (!t[key] || typeof t[key] !== 'object' || Array.isArray(t[key]))) throw new Error(`Invalid MCP ${key}`);
          }
          names.add(t.name);
          tools.push({ ...t, description: t.description ?? '', inputSchema: t.inputSchema ?? { type: 'object', properties: {} } });
        }
        if (listed.nextCursor === undefined) return tools;
        cursor = listed.nextCursor;
        if (typeof cursor !== 'string' || !cursor || cursors.has(cursor)) throw new Error('Invalid or repeated MCP next-page token');
        cursors.add(cursor);
      }
      throw new Error('MCP tools/list exceeds 32 pages');
    };
    const check = (): Promise<ToolDef[]> => {
      if (refresh) return refresh;
      const epoch = generation;
      const work = (async () => {
        const tools = await listAll();
        const verdict = await vetAndPin(opts.stateDir, server, tools, opts.policy, store, warden, feed, opts.auditOnly, () => epoch === generation && !closing, record);
        if (!opts.auditOnly && epoch !== generation) throw new WardenBlock('tools changed, blocked by WARDEN during verification');
        if (!opts.auditOnly && !verdict.allow) throw new WardenBlock(reason(verdict));
        if (closing) throw new Error('MCP connection closing');
        blockReason = ''; quarantined = false;
        return opts.auditOnly ? tools : tools.filter(t => verdict.allowedTools.includes(t.name));
      })();
      refresh = work;
      void work.then(() => { if (refresh === work) refresh = undefined; }, e => {
        if (refresh === work) refresh = undefined;
        quarantined = true; quarantineKind = e instanceof WardenBlock ? 'blocked' : 'error';
        blockReason = e instanceof Error ? e.message : String(e); log.warn(blockReason);
      });
      return work;
    };
    // Batches (allowed by protocol 2025-03-26, removed in 2025-06-18) are refused per request,
    // as an array of errors, rather than ending the session: each element would need its own
    // tools/list and tools/call checks, and splitting them would change the reply shape.
    const refuseBatch = (body: string): boolean => {
      let raw: unknown;
      try { raw = JSON.parse(body); } catch { return false; }
      if (!Array.isArray(raw)) return false;
      if (raw.length === 0) { send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request: empty batch' } }); return true; }
      const replies = raw.filter((m): m is Message => !!m && typeof m === 'object' && !Array.isArray(m) && m.method !== undefined && m.id !== undefined)
        .map(m => ({ jsonrpc: '2.0', id: typeof m.id === 'string' || typeof m.id === 'number' ? m.id : null,
          error: { code: -32600, message: 'warden wrap does not accept JSON-RPC batches; send each request on its own' } }));
      if (replies.length) send(replies);
      return true;
    };
    const fromClient = async (body: string) => {
      if (refuseBatch(body)) return;
      const msg = parse(body);
      if (typeof msg.id === 'string' && msg.id.startsWith(prefix)) { fail(msg, 'Reserved proxy request ID'); return; }
      if (blockedLaunch) {
        fail(msg, blockReason, -32000);
        if (msg.method === 'initialize') finish(3);
        return;
      }
      if (closing) return;
      if (msg.method === 'tools/list' || msg.method === 'tools/call') {
        if (msg.id === undefined) return; // These are requests, never notifications.
        if (activeChecks >= 256) { fail(msg, 'Too many pending MCP requests'); return; }
        activeChecks++;
        try {
          if (msg.method === 'tools/list') {
            const tools = await check();
            if (!opts.auditOnly && quarantined) throw new Error(blockReason || 'tools changed, blocked by WARDEN');
            visible = tools;
            send({ jsonrpc: '2.0', id: msg.id, result: { tools } });
          } else {
            const name = msg.params?.name;
            const seen = visible.find(t => t.name === name);
            // A failed check is retried here; a refusal or a change waits for the client to re-list.
            if (!opts.auditOnly && ((quarantined && quarantineKind !== 'error') || !seen)) throw new Error(blockReason || 'tool blocked by WARDEN');
            const epoch = generation;
            const current = await check();
            const def = current.find(t => t.name === name);
            if (!opts.auditOnly && (quarantined || epoch !== generation || !def || !seen || pinToolsHash([def]) !== pinToolsHash([seen]))) throw new Error('tool blocked by WARDEN: definition changed since exposure');
            if (tracked.size >= 256 || tracked.has(msg.id)) throw new Error('Too many or duplicate pending MCP requests');
            tracked.set(msg.id, { kind: 'call', generation });
            childWrite(body);
          }
        } catch (e) { fail(msg, e instanceof Error ? e.message : String(e)); }
        finally { activeChecks--; }
        return;
      }
      if (msg.method !== undefined && msg.id !== undefined) {
        if (tracked.size >= 256 || tracked.has(msg.id)) { fail(msg, 'Too many or duplicate pending MCP requests'); return; }
        tracked.set(msg.id, { kind: msg.method === 'initialize' ? 'initialize' : 'other', generation });
      }
      childWrite(body);
    };
    const fromChild = async (body: string) => {
      const msg = parse(body);
      if (msg.method === undefined && typeof msg.id === 'string' && msg.id.startsWith(prefix)) {
        const p = pending.get(msg.id);
        if (!p) return; // Timed-out internal response must never leak to the client.
        clearTimeout(p.timer); pending.delete(msg.id);
        if (msg.error) p.reject(new Error('MCP tools/list failed: ' + JSON.stringify(msg.error)));
        else p.resolve({ result: msg.result, bytes: Buffer.byteLength(body) });
        return;
      }
      if (msg.method === 'notifications/tools/list_changed') {
        generation++; quarantined = true; quarantineKind = 'changed'; blockReason = 'tools changed, blocked by WARDEN';
        const epoch = generation;
        // Do not reuse a check that started before the notification.
        void (async () => {
          await refresh?.catch(() => {});
          if (epoch !== generation || closing) return;
          await check();
          if (epoch === generation && !closing && (!quarantined || opts.auditOnly)) clientWrite(body);
        })().catch(e => log.warn(e instanceof Error ? e.message : String(e)));
        return;
      }
      if (msg.method === undefined && msg.id !== undefined) {
        const request = tracked.get(msg.id);
        if (!request) { log.warn(`dropped a child response to request ${displaySafe(JSON.stringify(msg.id), 80)}, which the client did not send to it or already received`); return; }
        {
          tracked.delete(msg.id);
          if (request.kind === 'call' && !opts.auditOnly && (quarantined || request.generation !== generation)) {
            fail(msg, 'tools changed, blocked by WARDEN; result withheld, execution may already have occurred'); return;
          }
          if (request.kind === 'initialize' && msg.result && typeof msg.result === 'object') {
            msg.result.capabilities = { ...msg.result.capabilities, tools: { ...msg.result.capabilities?.tools, listChanged: true } };
            if (typeof msg.result.instructions === 'string') {
              const scan = new Warden({ policy: opts.policy, gates: [new StaticScanGate()] });
              const verdict = await scan.vet(server, [{ name: 'initialize.instructions', description: msg.result.instructions, inputSchema: { type: 'object' } }]);
              record(verdict);
              if (!verdict.allow && !opts.auditOnly) delete msg.result.instructions;
            } else if (msg.result.instructions !== undefined && !opts.auditOnly) delete msg.result.instructions;
            send(msg); return;
          }
        }
      }
      clientWrite(body);
    };
    process.stdout.on('error', fatal);
    process.once('SIGTERM', signalStop); process.once('SIGINT', signalStop);
    if (!blockedLaunch) {
      child = spawn(server.command!, server.args!, { stdio: ['pipe', 'pipe', 'pipe'], env: process.env });
      child.on('error', e => { log.error(e.message); finish(1); });
      child.on('close', (code, signal) => finish(code ?? (signal ? 128 + (constants.signals[signal] ?? 0) : 1)));
      child.stdin.on('error', fatal);
      // Bound and sanitize each chunk; a child cannot accumulate an unterminated stderr line.
      child.stderr.on('data', chunk => {
        for (const line of String(chunk).split('\n').filter(Boolean)) process.stderr.write(`warden: ${opts.auditOnly ? 'AUDIT-ONLY ' : ''}[child ${displaySafe(server.id)}] ${displaySafe(line, 8192)}\n`);
      });
      readFrames(child.stdout, new WrapFrames('ndjson'), body => { void fromChild(body).catch(fatal); }, fatal, () => {});
    }
    readFrames(process.stdin, frames, body => { void fromClient(body).catch(fatal); }, fatal, stop);
  });
}
