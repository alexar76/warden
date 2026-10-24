import { TaskAdapter, TASK_TOOLS } from './task-adapter.js';
import { parseJsonStrict } from './jcs.js';
import { readFrames, WrapFrames } from './wrap-wire.js';
import { randomUUID } from 'node:crypto';

/** Trusted MCP adapter, not a proxy to a server claiming to be read-only. */
export async function runTaskCli(args: string[]): Promise<number> {
  if (args.length) { process.stderr.write('warden-mcp task: no arguments; configure the pinned taskAdapter in the user flow policy\n'); return 2; }
  const adapter = new TaskAdapter();
  const frames = new WrapFrames();
  const active = new Map<string | number, AbortController>();
  const jobs = new Set<Promise<void>>();
  const questions = new Map<string, (answer: boolean) => void>();
  const prefix = `warden-task:${randomUUID()}:`;
  let sequence = 0, canAsk = false, closing = false;
  let outputBlocked = false;
  const send = (msg: object) => {
    if (closing) return;
    const body = JSON.stringify(msg);
    if (!process.stdout.write(frames.mode === 'lsp' ? `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}` : body + '\n') && !outputBlocked) {
      outputBlocked = true; process.stdin.pause();
      process.stdout.once('drain', () => { outputBlocked = false; if (!closing) process.stdin.resume(); });
    }
  };
  const error = (id: unknown, code: number, message: string) => send({ jsonrpc: '2.0', id, error: { code, message } });
  const approve = (message: string, signal?: AbortSignal): Promise<boolean> => {
    if (!canAsk || signal?.aborted) return Promise.resolve(false);
    return new Promise(resolve => {
      const id = prefix + sequence++;
      const finish = (answer: boolean) => { if (!questions.delete(id)) return; clearTimeout(timer); signal?.removeEventListener('abort', abort); resolve(answer); };
      const withdraw = (reason: string) => send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason } });
      const abort = () => { finish(false); withdraw('The task run was cancelled'); };
      const timer = setTimeout(() => { finish(false); withdraw('No approval within five minutes'); }, 300_000);
      questions.set(id, finish); signal?.addEventListener('abort', abort, { once: true });
      send({ jsonrpc: '2.0', id, method: 'elicitation/create', params: { message,
        requestedSchema: { type: 'object', required: ['run'], properties: { run: { type: 'boolean', title: 'Run the complete plan once', default: false } } } } });
    });
  };
  let initialized = false;
  return new Promise<number>(resolve => {
    const finish = (code: number) => {
      if (closing) return; closing = true;
      for (const a of active.values()) a.abort();
      void Promise.allSettled([...jobs]).then(() => { process.stdout.removeListener('error', outputError); resolve(code); });
    };
    const outputError = () => finish(1);
    process.stdout.once('error', outputError);
    const dispatch = async (body: string) => {
      if (closing) return;
      let raw: unknown;
      try { if (Buffer.byteLength(body) > 65_536) throw new Error(); raw = parseJsonStrict(body); }
      catch { error(null, -32700, 'Invalid or oversized task JSON'); return; }
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) { error(null, -32600, 'Invalid task request'); return; }
      const m = raw as Record<string, unknown>;
      if (typeof m.id === 'string' && m.id.startsWith(prefix)) {
        if (m.jsonrpc === '2.0' && m.method === undefined) {
          const r = m.result as { action?: unknown; content?: { run?: unknown } } | undefined;
          questions.get(m.id)?.(m.error === undefined && r?.action === 'accept' && r.content?.run === true);
        } else error(m.id, -32600, 'Reserved task request ID');
        return;
      }
      const params = m.params as Record<string, unknown> | undefined;
      if (m.jsonrpc !== '2.0' || typeof m.method !== 'string' || Object.keys(m).some(k => !['jsonrpc', 'id', 'method', 'params'].includes(k)) ||
        m.id !== undefined && !(typeof m.id === 'string' || typeof m.id === 'number') || params !== undefined && (!params || typeof params !== 'object' || Array.isArray(params))) {
        error(null, -32600, 'Invalid task request'); return;
      }
      if (m.method === 'notifications/cancelled' && m.id === undefined) {
        const id = params?.requestId;
        if (typeof id === 'string' || typeof id === 'number') active.get(id)?.abort();
        return;
      }
      if (m.id === undefined) return;
      const id = m.id as string | number;
      if (active.has(id)) { error(id, -32600, 'Duplicate active task request ID'); return; }
      if (m.method === 'initialize') {
        if (initialized) { error(id, -32600, 'Task already initialized'); return; }
        initialized = true;
        const capability = (params?.capabilities as Record<string, unknown> | undefined)?.elicitation;
        canAsk = !!capability && typeof capability === 'object' && !Array.isArray(capability) && (Object.keys(capability).length === 0 || 'form' in capability);
        const version = ['2025-03-26', '2025-06-18', '2025-11-25'].includes(String(params?.protocolVersion)) ? params!.protocolVersion : '2025-06-18';
        send({ jsonrpc: '2.0', id, result: { protocolVersion: version, capabilities: { tools: {} }, serverInfo: { name: 'warden-task', version: '1.0.0' } } }); return;
      }
      if (!initialized) { error(id, -32000, 'Initialize task server first'); return; }
      if (m.method === 'ping') { send({ jsonrpc: '2.0', id, result: {} }); return; }
      if (m.method === 'tools/list') { send({ jsonrpc: '2.0', id, result: { tools: TASK_TOOLS } }); return; }
      if (m.method !== 'tools/call') { error(id, -32601, 'Task method not supported'); return; }
      if (!params || Object.keys(params).some(k => !['name', 'arguments'].includes(k)) || typeof params.name !== 'string' || !TASK_TOOLS.some(t => t.name === params.name)) {
        error(id, -32602, 'Invalid task call'); return;
      }
      if (active.size >= 16) { error(id, -32000, 'Too many active task calls'); return; }
      const abort = new AbortController(); active.set(id, abort);
      try {
        const result = await adapter.call(params.name, params.arguments === undefined ? {} : params.arguments, abort.signal, approve);
        if (!abort.signal.aborted) send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(result) }] } });
      } catch {
        if (!abort.signal.aborted) send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: 'WARDEN task refused or failed. Check the local policy, manifest pins, expiry and operation budget. A started request may have taken effect; do not retry automatically.' }] } });
      } finally { active.delete(id); }
    };
    readFrames(process.stdin, frames, body => { const work = dispatch(body); jobs.add(work); void work.catch(() => finish(1)).finally(() => jobs.delete(work)); }, () => {
      process.stdin.pause(); finish(1);
    }, () => finish(0));
  });
}
