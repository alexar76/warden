/**
 * WARDEN flow guard for OpenCode (https://opencode.ai): the checks of the Claude Code plugin, through OpenCode's
 * plugin hooks, for agents that often run with no person at the keyboard (Multica, CI, cron).
 *
 * - `tool.execute.before` maps the call to the Claude Code tool vocabulary the guard classifies (bash → Bash,
 *   read → Read, `<server>_<tool>` → mcp__<server>__<tool>, …) and runs `flowPre`. A refused call throws: OpenCode
 *   does not run the tool and the model reads the reason.
 * - `tool.execute.after` runs `flowPost`, which records outside text, private data and credentials the result
 *   brought in. Its warning to the model is appended to the result.
 * - `chat.message` runs `flowPrompt`: destinations the user's own message names.
 * - `shell.env` blanks secrets a shell command does not need (`stripEnv`), so an injected `env` or `printenv`
 *   cannot read the model provider's key or a hub key that only the OpenCode process itself uses.
 * - A subagent (`task`) runs in a child session. The guard keeps ONE state per session tree, keyed by the root:
 *   a fresh child would otherwise start untainted, and an injected parent could hand it the read-and-send. Parents
 *   come from `session.created`/`session.updated` events, else from the SDK client. A child's prompt is written by
 *   the parent model, so it is not recorded as the user's words.
 * - If recording a result fails, every later call of that session tree is refused: an unrecorded result may be the
 *   outside text or credential the next decision depends on.
 *
 * Where the Claude Code hook would ask a person, nobody may be there. `block` decides:
 * - `data` (default): refuse what involves data — a known secret, a credential boundary, private text or personal
 *   data in the arguments, a short credential fragment, an incomplete payload check, a change to the guard's own
 *   settings — and every decision whose payload is sensitive, whatever the first reason. Calls that only act after
 *   outside text (opaque shell code, an unnamed destination, a destructive command, a GUI action) run and are
 *   logged: an unattended agent's work is reading outside text and then reporting, and a network allowlist or a
 *   sandbox has to bound where it can act.
 * - `all`: refuse everything the Claude Code hook would ask about. Safe and noisy; most agents stop on their first
 *   shell command after reading a web page.
 *
 * Node built-ins and flow-guard parts only, so the compiled files can be copied next to an OpenCode config.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { flowPaths, sessionKey, stateDir } from './flow-guard-paths.js';
import { flowPost } from './flow-guard-post.js';
import { flowPrompt } from './flow-guard-answer.js';
import { flowPre } from './flow-guard-pre.js';
import { log } from './flow-guard-state.js';
import type { FlowPreDetail } from './flow-guard-pre.js';
import { blockMode, patchFiles, refuses, type UnattendedBlockMode } from './flow-guard-unattended.js';

export { patchFiles, refuses } from './flow-guard-unattended.js';

export type OpenCodeBlockMode = UnattendedBlockMode;

export interface OpenCodeGuardOptions {
  /** Which decisions refuse the call: see the module comment. Env `WARDEN_OPENCODE_BLOCK`. */
  block?: OpenCodeBlockMode;
  /** MCP server names as configured in OpenCode; tools are named `<server>_<tool>`. Read from the config hook too. */
  mcpServers?: string[];
  /** Environment variables blanked for shell commands. Env `WARDEN_OPENCODE_STRIP_ENV` (comma-separated). */
  stripEnv?: string[];
  env?: NodeJS.ProcessEnv;
}

/** Tools that only change OpenCode's own session state. */
const IGNORED = new Set(['todowrite', 'todoread', 'question', 'skill', 'invalid']);

export interface GuardCall { name: string; input: Record<string, unknown> }

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

/** One OpenCode call as the guard's vocabulary: zero, one or (for a multi-file patch) several calls. */
export function guardCalls(tool: string, rawArgs: unknown, mcpServers: readonly string[]): GuardCall[] {
  const a = obj(rawArgs);
  const t = tool.toLowerCase();
  if (IGNORED.has(t)) return [];
  const file = str(a.filePath) ?? str(a.file_path) ?? str(a.path);
  switch (t) {
    case 'bash': return [{ name: 'Bash', input: { command: str(a.command) ?? '',
      ...(str(a.workdir) ? { workdir: a.workdir } : {}) } }];
    case 'read': return [{ name: 'Read', input: file ? { file_path: file } : {} }];
    case 'write': return [{ name: 'Write', input: { file_path: file ?? '', content: a.content } }];
    case 'edit': return [{ name: 'Edit', input: { file_path: file ?? '', old_string: a.oldString, new_string: a.newString } }];
    case 'multiedit': return [{ name: 'MultiEdit', input: { file_path: file ?? '',
      edits: Array.isArray(a.edits) ? a.edits.map(e => ({ old_string: obj(e).oldString, new_string: obj(e).newString })) : [] } }];
    case 'patch': case 'apply_patch': {
      const text = str(a.patchText) ?? str(a.patch) ?? str(a.input) ?? '';
      const files = patchFiles(text);
      // An unparsable patch is still a write of its whole text somewhere.
      return (files.length ? files : ['']).map(f => ({ name: 'Write', input: { file_path: f, content: text } }));
    }
    case 'webfetch': return [{ name: 'WebFetch', input: { url: str(a.url) ?? '' } }];
    case 'websearch': case 'codesearch': return [{ name: 'WebSearch', input: { query: str(a.query) ?? '' } }];
    case 'grep': return [{ name: 'Grep', input: { pattern: a.pattern, ...(str(a.path) ? { path: a.path } : {}) } }];
    case 'glob': return [{ name: 'Glob', input: { pattern: a.pattern, ...(str(a.path) ? { path: a.path } : {}) } }];
    case 'list': case 'ls': return [{ name: 'LS', input: str(a.path) ? { path: a.path } : {} }];
  }
  // MCP tools are `<server>_<tool>`; the longest configured server name wins (names may contain `_`).
  const server = [...mcpServers].sort((x, y) => y.length - x.length).find(s => tool.startsWith(`${s}_`) && tool.length > s.length + 1);
  if (server) return [{ name: `mcp__${server}__${tool.slice(server.length + 1)}`, input: a }];
  // Anything else (a subagent `task`, another plugin's tool) is treated like an unlabelled MCP tool: its result is
  // outside text, and it sends when its name or arguments say so.
  return [{ name: `mcp__opencode__${tool}`, input: a }];
}

function list(v: string | undefined): string[] {
  return (v ?? '').split(',').map(s => s.trim()).filter(Boolean);
}

function textOf(parts: unknown): string {
  return (Array.isArray(parts) ? parts : []).map(p => obj(p)).filter(p => p.type === 'text' && typeof p.text === 'string' && !p.synthetic)
    .map(p => p.text as string).join('\n');
}

/** The adapter's resolution of a decision, next to the guard's own log line for the same call. */
function note(env: NodeJS.ProcessEnv, sessionId: string, entry: Record<string, unknown>): void {
  log(flowPaths(stateDir(env), sessionId), { event: 'opencode', ...entry });
}

type Hooks = Record<string, (input: any, output: any) => Promise<void>>;

interface SessionClient { session?: { get?: (req: { path: { id: string } }) => Promise<unknown> } }

const MAX_DEPTH = 16;

/** The plugin function OpenCode calls with its context. Export exactly this from a file in OpenCode's plugin folder. */
export function createWardenPlugin(options: OpenCodeGuardOptions = {}) {
  return async (ctx: { directory?: string; worktree?: string; client?: SessionClient } = {}): Promise<Hooks> => {
    const env = options.env ?? process.env;
    const blockEnv = blockMode(env.WARDEN_OPENCODE_BLOCK);
    const block: OpenCodeBlockMode = options.block ?? blockEnv ?? 'data';
    const servers = new Set(options.mcpServers ?? []);
    const strip = [...new Set([...(options.stripEnv ?? []), ...list(env.WARDEN_OPENCODE_STRIP_ENV)])];
    // The host session directory is the trusted project boundary. A Bash workdir resolves execution paths
    // without redefining that boundary.
    const cwd = ctx.directory ?? ctx.worktree ?? process.cwd();
    const parentOf = new Map<string, string>();
    const looked = new Set<string>();
    const broken = new Set<string>();
    const brokenPath = (sessionId?: string) => join(stateDir(env), 'opencode', 'broken', sessionId ? sessionKey(sessionId) : '_unknown');
    const markBroken = (sessionId?: string) => {
      broken.add(sessionId ?? '_unknown');
      mkdirSync(join(stateDir(env), 'opencode', 'broken'), { recursive: true, mode: 0o700 });
      writeFileSync(brokenPath(sessionId), new Date().toISOString() + '\n', { mode: 0o600 });
    };
    const learn = (info: unknown) => {
      const i = obj(info), id = str(i.id), parent = str(i.parentID);
      if (!id || (i.parentID !== undefined && (!parent || parent === id))) {
        throw new Error('WARDEN flow guard could not verify session ancestry. Refused.');
      }
      looked.add(id);
      if (parent) parentOf.set(id, parent);
    };
    const parentFromClient = async (id: string) => {
      if (looked.has(id)) return;
      try {
        if (!ctx.client?.session?.get) throw new Error('session client unavailable');
        const res = obj(await ctx.client?.session?.get?.({ path: { id } }));
        const info = obj(res.data ?? res);
        if (info.id !== id) throw new Error('session lookup did not return the requested session');
        learn(info);
      } catch {
        // Only a successful lookup or a host session event confirms ancestry. A failed lookup must be
        // retried, never cached as proof that a child is a clean root session.
        throw new Error('WARDEN flow guard could not verify session ancestry. Refused; retry after the session lookup recovers.');
      }
    };
    const rootOf = async (id: string): Promise<string> => {
      let cur = id;
      const seen = new Set<string>();
      for (let i = 0; i < MAX_DEPTH; i++) {
        if (seen.has(cur)) throw new Error('WARDEN flow guard found cyclic session ancestry. Refused.');
        seen.add(cur);
        await parentFromClient(cur);
        const parent = parentOf.get(cur);
        if (!parent) return cur;
        cur = parent;
      }
      throw new Error('WARDEN flow guard could not verify session ancestry within its depth limit. Refused.');
    };
    return {
      event: async (input: { event?: unknown }) => {
        const e = obj(input?.event);
        if (e.type === 'session.created' || e.type === 'session.updated') learn(obj(e.properties).info);
      },
      config: async (config: unknown) => {
        for (const name of Object.keys(obj(obj(config).mcp))) servers.add(name);
      },
      'chat.message': async (input: { sessionID?: string }, output: { parts?: unknown }) => {
        const prompt = textOf(output?.parts), sessionId = str(input?.sessionID);
        if (!sessionId || !prompt) return;
        // A subagent's prompt comes from the parent model, which may carry outside text: not the user's words.
        if (await rootOf(sessionId) !== sessionId) return;
        flowPrompt({ session_id: sessionId, prompt, cwd }, env);
      },
      'tool.execute.before': async (input: { tool?: string; sessionID?: string }, output: { args?: unknown }) => {
        const tool = str(input?.tool), session = str(input?.sessionID);
        if (!tool || !session) return;
        const sessionId = await rootOf(session);
        if (broken.has(sessionId) || broken.has('_unknown') || existsSync(brokenPath(sessionId)) || existsSync(brokenPath())) {
          throw new Error('WARDEN flow guard could not record an earlier result of this session, so it cannot judge this call. Refused; start a new session.');
        }
        for (const call of guardCalls(tool, output?.args, [...servers])) {
          const detail: FlowPreDetail = {};
          // A guard failure must not let the call through: flowPre's own corrupt-state errors refuse here.
          let decision;
          try { decision = flowPre({ session_id: sessionId, tool_name: call.name, tool_input: call.input, cwd }, env, 'hook', detail); }
          catch (err) { throw new Error(`WARDEN flow guard could not safely check this call (${err instanceof Error ? err.message : String(err)}). Repair the guard state before retrying.`); }
          if (!decision) continue;
          const refused = refuses(decision, detail, block);
          note(env, sessionId, { tool: call.name, decision: decision.permissionDecision, reason: detail.reason, sensitive: !!detail.sensitive,
            resolution: refused ? 'refused' : 'allowed_unattended', block });
          if (refused) throw new Error(`${decision.permissionDecisionReason}\nRefused by the WARDEN flow guard (OpenCode, block=${block}). Do not retry this call in another form; report what was refused.`);
        }
      },
      'tool.execute.after': async (input: { tool?: string; sessionID?: string; args?: unknown }, output: { output?: unknown }) => {
        const tool = str(input?.tool), session = str(input?.sessionID);
        let sessionId: string | undefined;
        try {
          if (!tool || !session) throw new Error('result has no session or tool name');
          sessionId = await rootOf(session);
          if (!output) throw new Error('result output is unavailable');
          const response = typeof output.output === 'string' ? output.output : JSON.stringify(output.output ?? '');
          if (typeof response !== 'string') throw new Error('result cannot be serialized');
          for (const call of guardCalls(tool, input.args, [...servers])) {
            const post = flowPost({ session_id: sessionId, tool_name: call.name, tool_input: call.input, tool_response: response, cwd }, env);
            const warning = post?.additionalContext || post?.systemMessage;
            if (warning && typeof output.output === 'string') output.output = `${output.output}\n\n[WARDEN] ${warning}`;
          }
        } catch (err) {
          // This hook runs after execution. If ancestry is unknown, the lost result could belong to any
          // root; fence this installation. Otherwise the durable fence stays scoped to the verified root.
          markBroken(sessionId);
          note(env, sessionId ?? session ?? 'unknown', { tool, resolution: 'record_failed', error: err instanceof Error ? err.name : 'error' });
        }
      },
      'shell.env': async (_input: unknown, output: { env?: Record<string, string> }) => {
        if (!output?.env || !strip.length) return;
        for (const name of strip) output.env[name] = '';
      },
    };
  };
}
