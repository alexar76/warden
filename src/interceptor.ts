import { CanonicalizationError } from './jcs.js';
import { pinToolsHash } from './pinning.js';
import { readLock, type LockFile } from './scan-lock.js';
import { displaySafe } from './sanitize.js';
import { StaticScanGate, staticScanRulesetRef } from './static-scan.js';
import {
  contractDigest, definitionText, digestBytes, extrasDigest, perToolContract, sameDigest,
  TOOL_SET_DIGEST_SPEC, ToolSetDigestError,
} from './tool-set-digest.js';
import type { Severity, ToolDef, WardenPolicy } from './types.js';

/**
 * WARDEN as an MCP Interceptor Server.
 *
 * Interceptors are the extension the MCP Interceptors Working Group is specifying (SEP-2624,
 * modelcontextprotocol/experimental-ext-interceptors): a client, a server or a gateway calls
 * `interceptors/list` and `interceptor/invoke` on a server like this one at fixed points of a
 * request, and acts on the answer. A validator inspects and returns a decision; it never changes
 * the payload.
 *
 * This server has two validators, both on the response to `tools/list`: the moment a tool set
 * reaches a client and before a model reads it.
 *
 * - {@link INTEGRITY}: is this the tool set that was approved? It computes the contract and
 *   extras digests of `mcp-tool-set-digest/1` and compares them with the expected ones, which
 *   the invoker passes in `config` or which come from a `warden.lock.json` the server was
 *   started with.
 * - {@link SCAN}: does a definition carry instructions for the model? WARDEN's static scan.
 *
 * The server keeps no state: what a call is compared with arrives with the call, as the proposal
 * asks ("configuration is passed on each invocation so that Interceptor Servers can remain
 * stateless"), or is read from a lock file that only `scan --update-lock` writes.
 *
 * Written against the proposal as of experimental-ext-interceptors 07c89a24 (2026-10-28). The
 * extension is experimental and its wire format may change.
 */

export const INTERCEPTORS_EXTENSION = 'io.modelcontextprotocol/interceptors';
export const INTEGRITY = 'warden.tool-definition-integrity';
export const SCAN = 'warden.tool-definition-scan';
export const SUPPORTED_EVENTS = ['tools/list'] as const;
const MAX_MESSAGES = 50;
const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

type Phase = 'request' | 'response';
type Level = 'info' | 'warn' | 'error';

export interface ValidationMessage { path?: string; message: string; severity: Level }

/** `ValidationResult` of the proposal (section "Validator"). */
export interface ValidationResult {
  interceptor: string;
  type: 'validation';
  phase: Phase;
  durationMs?: number;
  info?: Record<string, unknown>;
  valid: boolean;
  severity?: Level;
  messages?: ValidationMessage[];
}

/** A request this server refuses, as a JSON-RPC error: `code`, `message` and `data`. */
export class InterceptorError extends Error {
  constructor(readonly code: number, message: string, readonly data: Record<string, unknown>) {
    super(message);
    this.name = 'InterceptorError';
  }
}

export interface InterceptorDeps {
  /** A `warden.lock.json`, when the server was started with `--lock`. */
  lock?: LockFile;
  now?: () => number;
}

const HOOKS = [{ events: [...SUPPORTED_EVENTS], phase: 'response' as const }];

/** The descriptors `interceptors/list` returns. */
export function interceptorDescriptors(version: string): Array<Record<string, unknown>> {
  return [
    {
      name: INTEGRITY,
      version,
      description: 'Checks that the tool set a server lists is the one that was approved: computes the ' +
        `contract and extras digests of ${TOOL_SET_DIGEST_SPEC} and compares them with the expected ones ` +
        '(passed in config, or from a warden.lock.json). Names the tools that were added, removed or changed.',
      type: 'validation',
      hooks: HOOKS,
      mode: 'active',
      failOpen: false,
      compat: { minProtocol: '2024-11-05' },
      configSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          expected: {
            type: 'object',
            additionalProperties: false,
            description: 'What was approved. Digests as sha256-<base64> or sha256:<hex>.',
            properties: {
              contract: { type: 'string', description: `The contract digest (${TOOL_SET_DIGEST_SPEC}).` },
              extras: { type: ['string', 'null'], description: 'The extras digest (annotations, title, _meta, …); null when the approved set had no extras.' },
              tools: { type: 'array', description: 'The approved tool definitions; with them the answer names each changed tool.' },
              toolsHashV2: { type: 'string', description: 'A whole-definition WARDEN v2 pin (toolsHash from a pin with toolsHashVersion: 2). Supply it by itself.' },
            },
          },
          server: { type: 'string', description: 'The id of this server in the lock file the Interceptor Server was started with.' },
          firstSight: { type: 'string', enum: ['allow', 'warn', 'block'], description: 'When nothing is expected. Default: warn.' },
          extras: { type: 'string', enum: ['error', 'warn'], description: 'When only members outside the contract changed. Default: error.' },
          requireFullCoverage: { type: 'boolean', description: 'Require a complete baseline and tool list for checking an existing approval. Default: false.' },
        },
      },
    },
    {
      name: SCAN,
      version,
      description: 'Reads every tool definition a server lists for text aimed at the model: instructions, ' +
        'requests for secrets, exfiltration, hidden characters. WARDEN static scan, ruleset ' +
        `${staticScanRulesetRef().version}.`,
      type: 'validation',
      hooks: HOOKS,
      mode: 'active',
      failOpen: false,
      compat: { minProtocol: '2024-11-05' },
      configSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          blockAt: { type: 'string', enum: SEVERITY_ORDER, description: 'Findings at or above this severity make the answer invalid. Default: high.' },
        },
      },
    },
  ];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** The `tools` array of a `tools/list` response payload: the result, the JSON-RPC response, or the array. */
export function toolsOf(payload: unknown): unknown[] | undefined {
  if (Array.isArray(payload)) return payload;
  if (!isObject(payload)) return undefined;
  if (Array.isArray(payload.tools)) return payload.tools;
  if (isObject(payload.result) && Array.isArray(payload.result.tools)) return payload.result.tools;
  return undefined;
}

function digestOrCode(compute: () => string): { digest?: string; code?: string; detail?: string } {
  try { return { digest: compute() }; }
  catch (err) {
    if (!(err instanceof ToolSetDigestError)) throw err;
    return { code: err.code, detail: err.message };
  }
}

/** What was approved. `extras` is null when the approved set had none, undefined when nothing is known about them. */
interface Expected { contract?: string; extras?: string | null; tools?: ToolDef[]; toolsHashV2?: string; from: 'config' | 'lock' }

/** The extras digest of approved definitions: a digest, null for "no extras", undefined when it cannot be computed. */
function extrasOf(tools: readonly unknown[]): string | null | undefined {
  try { return extrasDigest(tools) ?? null; }
  catch (err) {
    if (!(err instanceof ToolSetDigestError)) throw err;
    return undefined;
  }
}

function expectedFrom(config: Record<string, unknown>, lock: LockFile | undefined, fail: (reason: string) => never): Expected | undefined {
  const given = config.expected;
  if (given !== undefined) {
    if (!isObject(given)) fail('config.expected must be an object');
    for (const key of Object.keys(given)) if (!['contract', 'extras', 'tools', 'toolsHashV2'].includes(key)) fail(`config.expected.${displaySafe(key, 60)} is not a setting of this interceptor`);
    if (given.toolsHashV2 !== undefined) {
      if (typeof given.toolsHashV2 !== 'string' || !/^(?:rfc8785:)?[a-f0-9]{64}$/.test(given.toolsHashV2)) fail('config.expected.toolsHashV2 is not a WARDEN v2 pin hash');
      if (Object.keys(given).length !== 1) fail('config.expected.toolsHashV2 must be supplied by itself');
      return { from: 'config', toolsHashV2: given.toolsHashV2 };
    }
    if (given.contract !== undefined && !digestBytes(given.contract)) fail('config.expected.contract is not sha256-<base64> or sha256:<hex>');
    if (given.extras !== undefined && given.extras !== null && !digestBytes(given.extras)) fail('config.expected.extras is not sha256-<base64>, sha256:<hex> or null');
    if (given.tools !== undefined && !Array.isArray(given.tools)) fail('config.expected.tools must be an array');
    const tools = given.tools as ToolDef[] | undefined;
    const out: Expected = { from: 'config', tools };
    // The approved definitions say more than a digest of them: when both are given they must agree.
    if (tools) {
      const fromTools = digestOrCode(() => contractDigest(tools));
      if (!fromTools.digest) fail(`config.expected.tools has no contract digest (${fromTools.code})`);
      if (given.contract !== undefined && !sameDigest(given.contract, fromTools.digest)) fail('config.expected.contract is not the digest of config.expected.tools');
      out.contract = fromTools.digest;
      out.extras = extrasOf(tools);
      if (given.extras !== undefined && !(given.extras === null ? out.extras === null : sameDigest(given.extras, out.extras))) {
        fail('config.expected.extras is not the digest of config.expected.tools');
      }
    } else {
      out.contract = given.contract as string | undefined;
      out.extras = given.extras as string | null | undefined;
    }
    if (!out.contract && out.extras === undefined) fail('config.expected names nothing to compare with');
    return out;
  }
  if (config.server === undefined) return undefined;
  if (typeof config.server !== 'string' || !config.server) fail('config.server must be a non-empty string');
  if (!lock) fail('config.server needs a lock file: start the Interceptor Server with --lock PATH');
  const entry = lock.servers[config.server];
  if (!entry) return undefined;
  const tools = entry.tools as ToolDef[] | undefined;
  if (config.requireFullCoverage === true && entry.toolsHashVersion === 2) {
    // Only use the retained definitions for the diff if they describe the approved pin.
    const matches = tools && !coverageProblem(tools) && pinHashOrCode(tools).digest === entry.toolsHash;
    return { from: 'lock', tools: matches ? tools : undefined, toolsHashV2: entry.toolsHash };
  }
  return {
    from: 'lock',
    tools,
    contract: entry.mtlDigest ?? (tools ? digestOrCode(() => contractDigest(tools)).digest : undefined),
    extras: tools ? extrasOf(tools) : undefined,
  };
}

/** Split digests bind extras to a name. Each name must identify exactly one declaration. */
function coverageProblem(tools: readonly unknown[]): string | undefined {
  const names = new Set<string>();
  for (const t of tools) {
    if (!isObject(t) || typeof t.name !== 'string' || !t.name || !isObject(t.inputSchema) ||
        (Object.hasOwn(t, 'description') && typeof t.description !== 'string') ||
        (Object.hasOwn(t, 'outputSchema') && !isObject(t.outputSchema))) {
      return 'the list contains an invalid tool declaration';
    }
    if (names.has(t.name)) return 'the list contains duplicate tool names';
    names.add(t.name);
  }
  return undefined;
}

function pinHashOrCode(tools: ToolDef[]): { digest?: string; code?: string } {
  try { return { digest: pinToolsHash(tools) }; }
  catch (err) {
    if (!(err instanceof CanonicalizationError)) throw err;
    return { code: err.code };
  }
}

/**
 * Which tools differ, and whether in what a model reads (contract) or only outside it (extras).
 * Tools are matched by name; tools that share a name are compared as a group. A definition that
 * cannot be written (a number with no double in an extra) counts as different from any other.
 */
function changes(before: readonly unknown[], after: readonly unknown[]): { added: string[]; removed: string[]; contract: string[]; extras: string[] } {
  const group = (tools: readonly unknown[]): Map<string, { contract: string; whole: string }> => {
    const contracts = new Map<string, string[]>(), wholes = new Map<string, string[]>();
    for (const { name, contract } of perToolContract(tools)) contracts.set(name, [...(contracts.get(name) ?? []), contract]);
    tools.forEach((tool, i) => {
      const name = (tool as { name: string }).name;
      const written = definitionText(tool);
      wholes.set(name, [...(wholes.get(name) ?? []), written.text ?? `!${written.code}#${i}`]);
    });
    return new Map([...contracts].map(([name, list]) => [name, { contract: list.sort().join('\n'), whole: (wholes.get(name) ?? []).sort().join('\n') }]));
  };
  const old = group(before), now = group(after);
  const out = { added: [] as string[], removed: [] as string[], contract: [] as string[], extras: [] as string[] };
  for (const name of [...new Set([...old.keys(), ...now.keys()])].sort()) {
    const a = old.get(name), b = now.get(name);
    if (!a) out.added.push(name);
    else if (!b) out.removed.push(name);
    else if (a.contract !== b.contract) out.contract.push(name);
    else if (a.whole !== b.whole) out.extras.push(name);
  }
  return out;
}

function integrity(payload: unknown, config: Record<string, unknown>, deps: InterceptorDeps, fail: (reason: string) => never): Omit<ValidationResult, 'interceptor' | 'type' | 'phase'> {
  for (const key of Object.keys(config)) {
    if (!['expected', 'server', 'firstSight', 'extras', 'requireFullCoverage'].includes(key)) fail(`config.${displaySafe(key, 60)} is not a setting of this interceptor`);
  }
  const firstSight = config.firstSight ?? 'warn', extras = config.extras ?? 'error';
  if (!['allow', 'warn', 'block'].includes(firstSight as string)) fail('config.firstSight must be allow, warn or block');
  if (!['error', 'warn'].includes(extras as string)) fail('config.extras must be error or warn');
  if (config.requireFullCoverage !== undefined && typeof config.requireFullCoverage !== 'boolean') fail('config.requireFullCoverage must be a boolean');
  const expected = expectedFrom(config, deps.lock, fail);
  const full = config.requireFullCoverage === true || expected?.toolsHashV2 !== undefined;
  if (full && extras === 'warn') fail('full coverage cannot be combined with config.extras: warn');
  if (full && config.expected !== undefined && config.server !== undefined) fail('full coverage requires one baseline source: config.expected or config.server');

  const tools = toolsOf(payload);
  if (!tools) {
    return { valid: false, severity: 'error', messages: [{ message: 'the payload holds no tools array: nothing was checked', severity: 'error' }] };
  }
  const refuse = (message: string, info?: Record<string, unknown>): Omit<ValidationResult, 'interceptor' | 'type' | 'phase'> => ({
    valid: false, severity: 'error', ...(info ? { info } : {}), messages: [{ message, severity: 'error' }],
  });
  let approvedHash: string | undefined;
  if (full) {
    if (isObject(payload)) {
      const result = isObject(payload.result) ? payload.result : undefined;
      if (Object.hasOwn(payload, 'nextCursor') || (result && Object.hasOwn(result, 'nextCursor'))) {
        return refuse('full coverage requires the entire tool list; the payload contains a pagination cursor');
      }
      if (result && Object.hasOwn(payload, 'tools')) {
        return refuse('full coverage requires one unambiguous tools array');
      }
    }
    const problem = coverageProblem(tools);
    if (problem) return refuse(`full coverage cannot be verified: ${problem}`);
    if (!expected || (expected.from === 'lock' && !expected.toolsHashV2) ||
        (!expected.toolsHashV2 && !expected.tools && (!expected.contract || expected.extras === undefined))) {
      return refuse('full coverage requires an approved WARDEN v2 pin, complete definitions, or both contract and extras baselines');
    }
    approvedHash = expected.toolsHashV2;
    if (!approvedHash && expected.tools) {
      const baselineProblem = coverageProblem(expected.tools);
      if (baselineProblem) return refuse(`full coverage cannot be verified for the approved definitions: ${baselineProblem}`);
      approvedHash = pinHashOrCode(expected.tools).digest;
      if (!approvedHash) return refuse('the approved definitions have no whole-definition digest');
    }
  }
  const contract = digestOrCode(() => contractDigest(tools));
  // The extras digest: a digest, null when no tool has extras, or the code of why it cannot be computed.
  let extrasNow: string | null | undefined, extrasCode: string | undefined;
  try { extrasNow = extrasDigest(tools) ?? null; }
  catch (err) { if (!(err instanceof ToolSetDigestError)) throw err; extrasCode = err.code; }
  const info: Record<string, unknown> = {
    specification: TOOL_SET_DIGEST_SPEC,
    tools: tools.length,
    contract: contract.digest ?? { error: contract.code },
    extras: extrasCode ? { error: extrasCode } : extrasNow,
  };
  if (!contract.digest) {
    // No digest means no comparison. Passing the list on would be a guess.
    return { valid: false, severity: 'error', info, messages: [{ message: `this tool set has no digest (${displaySafe(contract.detail ?? '', 300)})`, severity: 'error' }] };
  }
  if (!expected) {
    const what = typeof config.server === 'string'
      ? `the lock file has no entry for server ${displaySafe(JSON.stringify(config.server), 140)}`
      : 'nothing is expected of this tool set yet';
    const message = `${what}: there is nothing to compare it with. Its digests are in info.`;
    if (firstSight === 'block') return { valid: false, severity: 'error', info, messages: [{ message, severity: 'error' }] };
    const level: Level = firstSight === 'allow' ? 'info' : 'warn';
    return { valid: true, severity: level, info, messages: [{ message, severity: level }] };
  }
  info.expected = { from: expected.from, contract: expected.contract, ...(expected.extras === undefined ? {} : { extras: expected.extras }) };
  const messages: ValidationMessage[] = [];
  const index = new Map<string, number>();
  tools.forEach((tool, i) => { if (isObject(tool) && typeof tool.name === 'string' && !index.has(tool.name)) index.set(tool.name, i); });
  const at = (name: string): string | undefined => index.has(name) ? `tools[${index.get(name)}]` : undefined;
  const named = (name: string): string => displaySafe(JSON.stringify(name), 140);

  // Per-tool names need both lists to have contract entries; a lock entry written by hand may not.
  let diff: ReturnType<typeof changes> | undefined;
  if (expected.tools) {
    try { diff = changes(expected.tools, tools); }
    catch (err) { if (!(err instanceof ToolSetDigestError)) throw err; }
  }
  if (diff) info.changed = diff;

  if (approvedHash) {
    const actual = pinHashOrCode(tools as ToolDef[]);
    info.toolsHashV2 = actual.digest ?? { error: actual.code };
    info.expected = { from: expected.from, toolsHashV2: approvedHash };
    if (!actual.digest) return refuse(`this tool set has no whole-definition digest (${actual.code})`, info);
    if (actual.digest !== approvedHash) return refuse('the whole-definition digest changed since approval', info);
    return { valid: true, severity: 'info', info, messages: [{ message: 'the whole-definition digest matches the approved baseline', severity: 'info' }] };
  }

  const contractSame = expected.contract ? sameDigest(expected.contract, contract.digest) : undefined;
  // Extras: equal digests, or both without extras. With the approved definitions at hand, the
  // definitions themselves decide, which also covers a set whose extras digest cannot be computed.
  let extrasSame: boolean | undefined;
  if (diff) extrasSame = diff.extras.length === 0;
  else if (expected.extras !== undefined) extrasSame = extrasCode === undefined && (expected.extras === null ? extrasNow === null : sameDigest(expected.extras, extrasNow));

  if (contractSame === false) {
    messages.push({ message: `the contract digest is ${contract.digest}, expected ${expected.contract}: what a model reads or a call accepts has changed`, severity: 'error' });
    for (const name of diff?.added ?? []) messages.push({ path: at(name), message: `tool ${named(name)} was added`, severity: 'error' });
    for (const name of diff?.removed ?? []) messages.push({ message: `tool ${named(name)} was removed`, severity: 'error' });
    for (const name of diff?.contract ?? []) messages.push({ path: at(name), message: `tool ${named(name)}: its name, description or schema changed`, severity: 'error' });
    for (const name of diff?.extras ?? []) messages.push({ path: at(name), message: `tool ${named(name)}: a member outside the contract changed (annotations, title, _meta, …)`, severity: 'warn' });
    return { valid: false, severity: 'error', info, messages: messages.slice(0, MAX_MESSAGES) };
  }
  if (extrasSame === false) {
    const level: Level = extras === 'warn' ? 'warn' : 'error';
    const now = extrasCode ? `cannot be computed (${extrasCode})` : extrasNow === null ? 'is absent (no tool has extras)' : `is ${extrasNow}`;
    const was = expected.extras === undefined ? '' : expected.extras === null ? ', expected none' : `, expected ${expected.extras}`;
    const context = contractSame === true ? 'the contract digest is unchanged; ' : '';
    messages.push({ message: `${context}the extras digest ${now}${was}: a member outside the contract changed`, severity: level });
    for (const name of diff?.extras ?? []) messages.push({ path: at(name), message: `tool ${named(name)}: a member outside the contract changed (annotations, title, _meta, …)`, severity: level });
    return { valid: level !== 'error', severity: level, info, messages: messages.slice(0, MAX_MESSAGES) };
  }
  const compared = [contractSame === true ? 'contract' : undefined, extrasSame === true ? 'extras' : undefined].filter(Boolean).join(' and ');
  const note = extrasSame === undefined ? ' Members outside the contract were not compared: no extras digest is expected.' : '';
  return { valid: true, severity: 'info', info, messages: [{ message: `unchanged: the ${compared} digest${compared.includes(' and ') ? 's are' : ' is'} as expected.${note}`, severity: 'info' }] };
}

const SCAN_POLICY: Omit<WardenPolicy, 'blockAtSeverity'> = { sensitiveToolPatterns: [], allowUnknownServers: true, pinToolDefs: false };

async function scan(payload: unknown, config: Record<string, unknown>, fail: (reason: string) => never): Promise<Omit<ValidationResult, 'interceptor' | 'type' | 'phase'>> {
  for (const key of Object.keys(config)) if (key !== 'blockAt') fail(`config.${displaySafe(key, 60)} is not a setting of this interceptor`);
  const blockAt = (config.blockAt ?? 'high') as Severity;
  if (!SEVERITY_ORDER.includes(blockAt)) fail(`config.blockAt must be one of ${SEVERITY_ORDER.join(', ')}`);
  const listed = toolsOf(payload);
  if (!listed) {
    return { valid: false, severity: 'error', messages: [{ message: 'the payload holds no tools array: nothing was scanned', severity: 'error' }] };
  }
  const index = new Map<string, number>();
  const tools: ToolDef[] = [];
  const unreadable: ValidationMessage[] = [];
  listed.forEach((tool, i) => {
    if (!isObject(tool) || typeof tool.name !== 'string' || !tool.name) {
      unreadable.push({ path: `tools[${i}]`, message: 'not a tool definition (no name): it was not scanned', severity: 'error' });
      return;
    }
    if (!index.has(tool.name)) index.set(tool.name, i);
    tools.push({
      ...tool,
      name: tool.name,
      description: typeof tool.description === 'string' ? tool.description : '',
      inputSchema: isObject(tool.inputSchema) ? tool.inputSchema : {},
    } as ToolDef);
  });
  const ruleset = staticScanRulesetRef();
  const policy: WardenPolicy = { ...SCAN_POLICY, blockAtSeverity: blockAt };
  const { findings } = await new StaticScanGate().evaluate({ server: { id: 'interceptor', name: 'interceptor', transport: 'stdio' }, tools, prior: [], policy });
  const blocks = (severity: Severity): boolean => SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(blockAt);
  const messages: ValidationMessage[] = [...unreadable];
  let blocking = unreadable.length;
  for (const finding of findings) {
    const stops = !finding.advisory && blocks(finding.severity);
    if (stops) blocking++;
    messages.push({
      path: finding.tool !== undefined && index.has(finding.tool) ? `tools[${index.get(finding.tool)}]` : undefined,
      message: `${finding.code} (${finding.severity}${finding.advisory ? ', advisory' : ''}): ${finding.message}`,
      severity: stops ? 'error' : finding.advisory || SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf('medium') ? 'info' : 'warn',
    });
  }
  // Blocking findings first, so a truncated list keeps the ones that decided.
  messages.sort((a, b) => Number(b.severity === 'error') - Number(a.severity === 'error'));
  const info = { ruleset, blockAt, tools: tools.length, findings: findings.length, blocking };
  if (blocking) return { valid: false, severity: 'error', info, messages: messages.slice(0, MAX_MESSAGES) };
  const level: Level = messages.some(m => m.severity === 'warn') ? 'warn' : 'info';
  return { valid: true, severity: level, info, messages: messages.length ? messages.slice(0, MAX_MESSAGES) : [{ message: `no finding in ${tools.length} tool definition${tools.length === 1 ? '' : 's'}`, severity: 'info' }] };
}

/** `interceptor/invoke`: run one validator over one payload. Throws {@link InterceptorError}. */
export async function invokeInterceptor(params: unknown, deps: InterceptorDeps = {}): Promise<ValidationResult> {
  const now = deps.now ?? Date.now;
  const started = now();
  if (!isObject(params)) throw new InterceptorError(-32602, 'interceptor/invoke needs params', { reason: 'params must be an object' });
  const { name, event, phase, payload } = params;
  if (name !== INTEGRITY && name !== SCAN) {
    throw new InterceptorError(-32602, 'Unknown interceptor', { interceptor: typeof name === 'string' ? displaySafe(name, 140) : null, reason: 'no interceptor with that name' });
  }
  const fail = (reason: string): never => { throw new InterceptorError(-32603, 'Interceptor execution failed', { interceptor: name, reason }); };
  if (!(SUPPORTED_EVENTS as readonly unknown[]).includes(event) || phase !== 'response') {
    throw new InterceptorError(-32602, 'Interceptor does not hook this event', {
      interceptor: name, reason: `${name} runs on the response to tools/list, not on ${displaySafe(String(event), 60)} (${displaySafe(String(phase), 20)})`,
    });
  }
  if (params.config !== undefined && !isObject(params.config)) fail('config must be an object');
  const config = (params.config ?? {}) as Record<string, unknown>;
  const outcome = name === INTEGRITY ? integrity(payload, config, deps, fail) : await scan(payload, config, fail);
  return { interceptor: name, type: 'validation', phase: 'response', durationMs: Math.max(0, now() - started), ...outcome };
}

export { readLock };
