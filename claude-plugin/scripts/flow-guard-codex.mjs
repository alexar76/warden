// GENERATED from src/flow-guard-codex.ts by scripts/sync-flow-guard.mjs. Do not edit; run npm run build.
/**
 * WARDEN flow guard for OpenAI Codex (CLI, desktop app, `codex exec`, a Multica runtime): the checks of the Claude
 * Code plugin, through Codex's command hooks (`hooks.json`, `[hooks]` in `config.toml` or `requirements.toml`).
 *
 * Codex hooks speak nearly the Claude Code hook protocol: the same events, `tool_name`/`tool_input`/`tool_response`,
 * `hookSpecificOutput.permissionDecision`. Three differences decide this adapter:
 *
 * - **No `ask`.** Codex does not support `permissionDecision: "ask"` in PreToolUse: the hook run counts as failed and
 *   THE TOOL CALL CONTINUES. Passing the Claude Code decision through would let every questioned call run. Every
 *   `ask` therefore becomes `deny` or a logged pass, by `block` (see flow-guard-unattended.ts); this adapter never
 *   prints `ask`.
 * - **A failed hook does not stop the call.** An exception in a hook, or output Codex cannot parse, lets the tool
 *   run. Every path of PreToolUse that is not a clean "no decision" prints a deny, and a PostToolUse that could not
 *   record its result marks the session, so every later call of that session is denied.
 * - **Tool names.** Shell and unified exec arrive as `Bash` with `tool_input.command`; edits as `apply_patch` with the
 *   patch in `tool_input.command`; MCP tools as `mcp__<server>__<tool>`; other local tools by their own name.
 *   Subagent hooks carry the parent's `session_id`, so a session tree shares one guard state without extra work.
 *
 * Codex's own session ids are namespaced (`codex:<id>`) so they never share state with a Claude Code session.
 * Hosted tools (Codex's own web search) run no local hook: what they bring in is not recorded. Turn web search off
 * for a guarded agent (`web_search = "disabled"`) or accept that gap.
 *
 * Node built-ins and flow-guard parts only: `codex-plugin/scripts` holds copies that run without the package.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { flowPaths, stateDir } from './flow-guard-paths.mjs';
import { flowPost } from './flow-guard-post.mjs';
import { flowPrompt, flowStop } from './flow-guard-answer.mjs';
import { flowPre } from './flow-guard-pre.mjs';
import { log } from './flow-guard-state.mjs';
import { blockMode, patchFiles, refuses } from './flow-guard-unattended.mjs';
/** Local tools that only change Codex's own session state: no data in, no data out. */
const IGNORED = new Set(['update_plan', 'request_user_input']);
const SHELLS = /^(?:\/(?:usr\/)?bin\/)?(?:ba|z|da|k)?sh$/;
// A PostToolUse input carries the whole tool result (a large file read); too small a cap would skip fingerprinting it.
const STDIN_BYTES = 16 * 1_048_576;
function obj(v) {
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}
function str(v) {
    return typeof v === 'string' ? v : undefined;
}
/** The shell text of a Codex command: a string, or an argv where `bash -lc "<script>"` means its script. */
export function commandText(value) {
    if (typeof value === 'string')
        return value;
    if (!Array.isArray(value) || !value.every(v => typeof v === 'string'))
        return value === undefined ? '' : JSON.stringify(value);
    const argv = value;
    const flag = argv.findIndex((a, i) => i > 0 && /^-[a-z]*c[a-z]*$/.test(a));
    if (argv.length >= 3 && SHELLS.test(argv[0]) && flag > 0 && flag === argv.length - 2)
        return argv[argv.length - 1];
    // Quote each word, so a word with a space stays one word for the guard's shell parser.
    return argv.map(a => /^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`).join(' ');
}
/** One Codex tool call in the guard's (Claude Code) vocabulary: zero, one or, for a multi-file patch, several calls. */
export function codexGuardCalls(toolName, rawInput) {
    const a = obj(rawInput);
    if (IGNORED.has(toolName))
        return [];
    if (toolName.startsWith('mcp__'))
        return [{ name: toolName, input: a }];
    switch (toolName) {
        case 'Bash':
        case 'shell':
        case 'exec_command':
        case 'local_shell':
        case 'unified_exec':
            return [{ name: 'Bash', input: { command: commandText(a.command ?? a.cmd) } }];
        case 'Edit':
            return [{ name: 'Edit', input: { file_path: str(a.file_path) ?? str(a.path) ?? '', old_string: a.old_string, new_string: a.new_string } }];
        case 'Write':
            return [{ name: 'Write', input: { file_path: str(a.file_path) ?? str(a.path) ?? '', content: a.content } }];
        case 'apply_patch': {
            const text = str(a.command) ?? str(a.patch) ?? str(a.input) ?? (typeof rawInput === 'string' ? rawInput : '');
            const files = patchFiles(text);
            // An unparsable patch is still a write of its whole text somewhere.
            return (files.length ? files : ['']).map(f => ({ name: 'Write', input: { file_path: f, content: text } }));
        }
        case 'view_image': {
            const path = str(a.path) ?? str(a.file_path);
            return [{ name: 'Read', input: path ? { file_path: path } : {} }];
        }
        case 'write_stdin':
            // Input to a running command: its text is what that command receives.
            return [{ name: 'Bash', input: { command: str(a.chars) ?? str(a.input) ?? '' } }];
    }
    // Anything else (spawn_agent, a plugin's tool) is an unlabelled tool: its result is outside text, and it sends
    // when its name or arguments say so.
    return [{ name: `mcp__codex__${toolName.replace(/[^A-Za-z0-9_-]/g, '_')}`, input: a }];
}
/** The guard's session id for a Codex session: namespaced, so it never shares state with a Claude Code session. */
export function codexSession(input) {
    const id = str(input.session_id);
    return id ? `codex:${id}` : '';
}
function brokenPath(env, sessionId) {
    return join(stateDir(env), 'codex', 'broken', sessionId ? createHash('sha256').update(sessionId).digest('hex') : '_unknown');
}
function deny(reason) {
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}
function settings(options) {
    const env = options.env ?? process.env;
    return { env, block: options.block ?? blockMode(env.WARDEN_CODEX_BLOCK) ?? 'data' };
}
function hookInput(input, call, sessionId) {
    return { session_id: sessionId, tool_name: call.name, tool_input: call.input, cwd: str(input.cwd) || process.cwd(),
        ...(input.tool_response !== undefined ? { tool_response: input.tool_response } : {}) };
}
/** PreToolUse: a deny, or undefined to let the call run. Never `ask` (Codex runs the call on `ask`). */
export function codexPre(input, options = {}) {
    const { env, block } = settings(options);
    const sessionId = codexSession(input);
    const tool = str(input.tool_name) ?? '';
    if (!sessionId || !tool)
        return deny('WARDEN flow guard got a Codex hook input without a session or tool name. Refused.');
    if (existsSync(brokenPath(env, sessionId)) || existsSync(brokenPath(env))) {
        return deny('WARDEN flow guard could not record an earlier result of this session, so it cannot judge this call. Refused; start a new session.');
    }
    for (const call of codexGuardCalls(tool, input.tool_input)) {
        const detail = {};
        const decision = flowPre(hookInput(input, call, sessionId), env, 'hook', detail);
        if (!decision)
            continue;
        const refused = refuses(decision, detail, block);
        log(flowPaths(stateDir(env), sessionId), { event: 'codex', tool: call.name, decision: decision.permissionDecision,
            reason: detail.reason, sensitive: !!detail.sensitive, resolution: refused ? 'refused' : 'allowed_unattended', block });
        if (refused) {
            return deny(`${decision.permissionDecisionReason}\nRefused by the WARDEN flow guard (Codex, block=${block}). Do not retry this call in another form; report what was refused.`);
        }
    }
    return undefined;
}
/** PostToolUse: records what the result brought in. A failure marks the session so that later calls are denied. */
export function codexPost(input, options = {}) {
    const { env } = settings(options);
    const sessionId = codexSession(input);
    const tool = str(input.tool_name) ?? '';
    if (!sessionId || !tool) {
        markBroken(env, sessionId || undefined);
        return undefined;
    }
    const warnings = [];
    for (const call of codexGuardCalls(tool, input.tool_input)) {
        let post;
        try {
            post = flowPost(hookInput(input, call, sessionId), env);
        }
        catch (err) {
            markBroken(env, sessionId);
            log(flowPaths(stateDir(env), sessionId), { event: 'codex', tool: call.name, resolution: 'record_failed', error: err instanceof Error ? err.name : 'error' });
            continue;
        }
        const warning = post?.additionalContext || post?.systemMessage;
        if (warning && !warnings.includes(warning))
            warnings.push(warning);
    }
    return warnings.length ? { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: `[WARDEN] ${warnings.join('\n')}` } } : undefined;
}
function markBroken(env, sessionId) {
    const path = brokenPath(env, sessionId);
    mkdirSync(join(stateDir(env), 'codex', 'broken'), { recursive: true, mode: 0o700 });
    writeFileSync(path, new Date().toISOString() + '\n', { mode: 0o600 });
}
/** UserPromptSubmit: the destinations the user's own message names. */
export function codexPrompt(input, options = {}) {
    const { env } = settings(options);
    const sessionId = codexSession(input);
    if (sessionId)
        flowPrompt({ ...input, session_id: sessionId }, env);
    return undefined;
}
/** Stop: the guard's note on the answer. `decision: block` makes Codex continue once with the reason as the prompt. */
export function codexStop(input, options = {}) {
    const { env } = settings(options);
    const sessionId = codexSession(input);
    return sessionId ? flowStop({ ...input, session_id: sessionId }, env) : undefined;
}
const EVENTS = ['pre-tool-use', 'post-tool-use', 'user-prompt-submit', 'stop'];
/** One hook run: the stdout line, or undefined. Throws only on bad input; the caller turns that into a deny. */
export function runCodexHook(event, stdin, options = {}) {
    if (Buffer.byteLength(stdin) > STDIN_BYTES)
        throw new Error('hook input too large');
    const parsed = JSON.parse(stdin || '{}');
    const input = obj(parsed);
    if (input !== parsed)
        throw new Error('hook input is not an object');
    const out = event === 'pre-tool-use' ? codexPre(input, options) : event === 'post-tool-use' ? codexPost(input, options)
        : event === 'user-prompt-submit' ? codexPrompt(input, options) : codexStop(input, options);
    return out ? JSON.stringify(out) : undefined;
}
/** `codex-hook.mjs <event>` reads the Codex hook JSON on stdin. Fails closed for PreToolUse. */
export function codexHookMain(argv = process.argv.slice(2), options = {}) {
    const event = argv[0];
    if (!EVENTS.includes(event)) {
        process.stderr.write(`Usage: codex-hook.mjs ${EVENTS.join('|')}  (Codex command hook; reads the hook JSON on stdin)\n`);
        // Codex reads a deny from stdout; a misconfigured PreToolUse hook must not let calls through.
        process.stdout.write(JSON.stringify(deny('WARDEN Codex hook is misconfigured (unknown event). Refused.')) + '\n');
        return 0;
    }
    let stdin = '';
    try {
        stdin = readFileSync(0, 'utf8');
        const out = runCodexHook(event, stdin, options);
        if (out)
            process.stdout.write(out + '\n');
    }
    catch (err) {
        process.stderr.write(`warden codex hook ${event}: ${err instanceof Error ? err.message : String(err)}\n`);
        if (event === 'pre-tool-use')
            process.stdout.write(JSON.stringify(deny('WARDEN flow guard could not safely check this call. Repair the guard state before retrying.')) + '\n');
        if (event === 'post-tool-use') {
            let sessionId;
            try {
                sessionId = codexSession(obj(JSON.parse(stdin || '{}'))) || undefined;
            }
            catch { /* no trustworthy session id */ }
            // An unreadable result without a session id fences this installation until repaired.
            markBroken(options.env ?? process.env, sessionId);
        }
    }
    return 0;
}
