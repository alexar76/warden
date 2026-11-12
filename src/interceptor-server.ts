import { createInterface } from 'node:readline';
import { stdin, stdout, stderr } from 'node:process';
import {
  INTERCEPTORS_EXTENSION, InterceptorError, interceptorDescriptors, invokeInterceptor, SUPPORTED_EVENTS,
  type InterceptorDeps,
} from './interceptor.js';
import { MAX_FRAME_BYTES, packageVersion } from './mcp-rpc.js';
import { readLock } from './scan-lock.js';
import { displaySafe } from './sanitize.js';

/**
 * `warden-mcp interceptor`: WARDEN as an MCP Interceptor Server over stdio.
 *
 * It answers `initialize`, `ping`, `interceptors/list` and `interceptor/invoke`, and nothing
 * else: an Interceptor Server "SHOULD NOT also expose tools, prompts, or resources" (SEP-2624).
 * stdout is the wire (newline-delimited JSON); anything for a person goes to stderr.
 */

const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_TIMEOUT_MS = 60_000;

export const INTERCEPTOR_USAGE = `Usage: warden-mcp interceptor [--lock PATH]

Runs WARDEN as an MCP Interceptor Server over stdio (SEP-2624, experimental). A client, a server
or a gateway that speaks the interceptor extension calls it on the response to tools/list.

  warden.tool-definition-integrity   is this the tool set that was approved?
  warden.tool-definition-scan        does a definition carry text aimed at the model?

  --lock PATH   a warden.lock.json (written by: warden-mcp scan --update-lock). With it, an
                invocation names the server in config.server and is compared with that entry.

Docs: docs/interceptor.md
`;

type Id = string | number | null;
interface Reply { jsonrpc: '2.0'; id: Id; result?: unknown; error?: { code: number; message: string; data?: unknown } }

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** One JSON-RPC message in, one reply out (none for a notification). */
export async function handleInterceptorRpc(raw: unknown, deps: InterceptorDeps = {}): Promise<Reply | null> {
  const invalid: Reply = { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } };
  if (!isObject(raw) || raw.jsonrpc !== '2.0' || typeof raw.method !== 'string') return invalid;
  const id = raw.id as Id | undefined;
  if (id !== undefined && id !== null && typeof id !== 'string' && !(typeof id === 'number' && Number.isFinite(id))) return invalid;
  if (id === undefined) return null;                       // a notification: nothing to answer
  const ok = (result: unknown): Reply => ({ jsonrpc: '2.0', id, result });
  const fail = (code: number, message: string, data?: unknown): Reply => ({ jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } });
  if (raw.params !== undefined && !isObject(raw.params)) return fail(-32602, 'params must be an object');
  const params = (raw.params ?? {}) as Record<string, unknown>;
  const version = packageVersion();

  switch (raw.method) {
    case 'initialize': {
      const asked = params.protocolVersion;
      return ok({
        protocolVersion: typeof asked === 'string' && PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
        capabilities: { extensions: { [INTERCEPTORS_EXTENSION]: { supportedEvents: [...SUPPORTED_EVENTS] } } },
        serverInfo: { name: 'warden-interceptor', title: 'WARDEN tool-definition interceptors', version },
        instructions: 'An MCP Interceptor Server. Call interceptors/list, then interceptor/invoke on the response to tools/list.',
      });
    }
    case 'ping':
      return ok({});
    case 'interceptors/list': {
      const event = params.event;
      if (event !== undefined && typeof event !== 'string') return fail(-32602, 'params.event must be a string');
      const hooked = event === undefined || event === '*' || (SUPPORTED_EVENTS as readonly string[]).includes(event);
      return ok({ interceptors: hooked ? interceptorDescriptors(version) : [] });
    }
    case 'interceptor/invoke': {
      const timeoutMs = params.timeoutMs;
      if (timeoutMs !== undefined && !(typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs > 0)) {
        return fail(-32602, 'params.timeoutMs must be a positive number');
      }
      let timer: NodeJS.Timeout | undefined;
      try {
        const run = invokeInterceptor(params, deps);
        if (timeoutMs === undefined) return ok(await run);
        const limit = Math.min(timeoutMs as number, MAX_TIMEOUT_MS);
        const timeout = new Promise<'timeout'>(resolve => { timer = setTimeout(() => resolve('timeout'), limit); });
        const outcome = await Promise.race([run, timeout]);
        if (outcome === 'timeout') {
          run.catch(() => {});                              // its late answer, or error, is dropped
          return fail(-32000, 'Interceptor execution timeout', {
            interceptor: typeof params.name === 'string' ? displaySafe(params.name, 140) : null, timeoutMs: limit, phase: params.phase ?? null,
          });
        }
        return ok(outcome);
      } catch (err) {
        if (err instanceof InterceptorError) return fail(err.code, err.message, err.data);
        stderr.write(`warden-mcp interceptor: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
        return fail(-32603, 'Interceptor execution failed', { interceptor: typeof params.name === 'string' ? displaySafe(params.name, 140) : null, reason: 'internal error' });
      } finally {
        if (timer) clearTimeout(timer);
      }
    }
    default:
      return fail(-32601, 'method not found');
  }
}

/** Parse `interceptor` arguments. Throws with a message for a person. */
export function parseInterceptorArgs(argv: string[]): { lock?: string; help: boolean } {
  const out: { lock?: string; help: boolean } = { help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--lock') {
      const value = argv[++i];
      if (!value) throw new Error('--lock needs a path');
      out.lock = value;
    } else if (arg.startsWith('--lock=')) out.lock = arg.slice('--lock='.length);
    else throw new Error(`unknown argument ${displaySafe(arg, 80)} (see: warden-mcp interceptor --help)`);
  }
  return out;
}

/** Run the Interceptor Server on stdin/stdout until stdin closes. Returns the exit code. */
export async function runInterceptorCli(argv: string[]): Promise<number> {
  let options;
  try { options = parseInterceptorArgs(argv); }
  catch (err) { stderr.write(`warden-mcp interceptor: ${err instanceof Error ? err.message : String(err)}\n`); return 2; }
  if (options.help) { stdout.write(INTERCEPTOR_USAGE); return 0; }
  const deps: InterceptorDeps = {};
  if (options.lock) {
    try {
      deps.lock = await readLock(options.lock);
      // A lock named and absent is a mistake to hear about now, not a silent "first sight" later.
      if (!deps.lock) throw new Error(`${options.lock}: no such lock file`);
    } catch (err) {
      stderr.write(`warden-mcp interceptor: ${displaySafe(err instanceof Error ? err.message : String(err), 400)}\n`);
      return 2;
    }
  }
  const write = (message: Reply): void => { stdout.write(JSON.stringify(message) + '\n'); };
  const lines = createInterface({ input: stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    const body = line.trim();
    if (!body) continue;
    if (Buffer.byteLength(body, 'utf8') > MAX_FRAME_BYTES) {
      write({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'message too large' } });
      continue;
    }
    let parsed: unknown;
    try { parsed = JSON.parse(body); }
    catch { write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); continue; }
    const reply = await handleInterceptorRpc(parsed, deps);
    if (reply) write(reply);
  }
  return 0;
}
