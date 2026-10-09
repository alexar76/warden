import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { Warden, StaticScanGate, ThreatFeed, staticScanRulesetRef, displaySafe, FilePinStore } from './index.js';
import { asPolicy } from './mcp-tools.js';
import { defaultStateDir } from './state.js';
import { packageVersion } from './mcp-rpc.js';
import { discoverServers, CLIENT_KINDS, type ClientKind, type ConfiguredServer, type DiscoveryEnv, type SourceResult } from './scan-config.js';
import { fetchServer, McpClientError, type FetchedServer } from './mcp-client.js';
import { mtlToolSetDigest, MtlError } from './mtl.js';
import { historCheck, DEFAULT_HISTOR_URL, type HistorCheck } from './histor.js';
import { classifyTools, ClassifierError, type ClassifierOptions } from './classifier.js';
import { LockStore, readLock, writeLock, lockEntryFor, diffTools, LOCK_VERSION, type LockEntry, type LockFile, type ToolChange } from './scan-lock.js';
import type { PinStore, Severity, ToolDef, WardenFinding, WardenPolicy, WardenVerdict, RulesetRef } from './types.js';

export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export interface ScanOptions {
  configs: string[];
  project: boolean;
  clients?: ClientKind[];
  cwd: string;
  launch: boolean;
  publicOnly: boolean;
  timeoutMs: number;
  concurrency: number;
  policy: WardenPolicy;
  lock?: string;
  updateLock: boolean;
  stateDir: string;
  feed?: string;
  feedKey?: string;
  histor: boolean;
  historUrl: string;
  /** Opt-in meaning-based check; absent unless both --classifier-url and --classifier-model are given. */
  classifier?: ClassifierOptions & { blocks: boolean };
  format: 'table' | 'json';
  sarif?: string;
  markdown?: string;
  jsonFile?: string;
  failOnError: boolean;
  color: boolean;
}

export type ServerStatus = 'scanned' | 'launch-only' | 'blocked-at-launch' | 'error' | 'skipped';

export interface HistorSummary {
  match?: string;
  note?: string;
  page?: string;
  unchangedSince?: string;
  changes?: number;
  error?: string;
  notSent?: string;
}

export interface ScanServerResult {
  id: string;
  key: string;
  client: ClientKind;
  source: string;
  scope: 'user' | 'project';
  transport: 'stdio' | 'sse' | 'http';
  wrapped: boolean;
  /** Display form of the launch: secrets in args and URLs are redacted. */
  launch: string;
  status: ServerStatus;
  allow: boolean | null;
  score?: number;
  decidedBy?: string;
  findings: WardenFinding[];
  allowedTools: string[];
  blockedTools: string[];
  toolCount?: number;
  serverInfo?: { name?: string; version?: string };
  error?: string;
  skipped?: string;
  mtlDigest?: string;
  mtlError?: string;
  histor?: HistorSummary;
  classifier?: { model: string; flagged: number; error?: string };
  lock?: { state: 'match' | 'drift' | 'missing' | 'updated' | 'unchanged' | 'refused'; changes?: ToolChange[] };
  /** The fetched definitions; kept for the Markdown diff and --update-lock, not printed in JSON. */
  tools?: ToolDef[];
}

export interface ScanReport {
  tool: 'warden-scan';
  version: string;
  scannedAt: string;
  ruleset: RulesetRef;
  policy: WardenPolicy;
  launch: boolean;
  sources: Array<{ path: string; client: ClientKind; scope: 'user' | 'project'; servers: number; error?: string }>;
  servers: ScanServerResult[];
  lock?: { path: string; stale: string[]; written: boolean };
  summary: { servers: number; scanned: number; allowed: number; blocked: number; errors: number; skipped: number; launchOnly: number };
}

// ── argument parsing ─────────────────────────────────────────────────────────

export const SCAN_USAGE = `Usage: warden-mcp scan [CONFIG...] [options]

Reads MCP client configs, connects to every server they start, and vets the
tool definitions before a model sees them. Exit 0 = nothing blocked,
1 = a server was blocked (or, with --fail-on-error, could not be checked),
2 = usage or config error.

Where to look (default: every known client file that exists)
  CONFIG...              client config files (.mcp.json, claude_desktop_config.json, mcp.json …)
  --project              only project files in --cwd (.mcp.json, .cursor/mcp.json, .vscode/mcp.json)
  --client NAME          only this client: ${CLIENT_KINDS.join(', ')} (repeatable)
  --cwd DIR              project directory (default: current directory)

How to connect
  --no-launch            do not start stdio servers; vet their launch line only
  --public-only          refuse remote servers that resolve to private/loopback/link-local addresses
  --timeout MS           per server (default 30000)
  --concurrency N        servers checked at once (default 4)

Verdicts
  --fail-on SEVERITY     block at this severity: info|low|medium|high|critical (default high)
  --policy FILE          strict JSON policy, as for wrap
  --lock FILE            compare with reviewed definitions; a server missing from the lock is blocked
  --update-lock          write what the servers advertise now into --lock (refuses blocked servers)
  --state-dir DIR        where wrap keeps pins (read only here)
  --feed URL --feed-key HEX   signed threat feed, as for wrap
  --histor               ask the HISTOR log whether remote servers serve you what they serve everyone
                         (sends the endpoint without query or credentials, and a digest; never tool text)
  --histor-url URL       default ${DEFAULT_HISTOR_URL}
  --classifier-url URL --classifier-model NAME
                         also ask a model you choose (OpenAI-compatible: Ollama, vLLM, a hosted API)
                         whether each tool's text directs the model. Sends tool definitions to that URL.
                         Key, if any, from WARDEN_CLASSIFIER_API_KEY. Advisory unless --classifier-blocks.
  --classifier-blocks    let the classifier's high/medium verdicts block like a rule

Output
  --json                 JSON report on stdout instead of a table
  --sarif FILE           also write SARIF 2.1.0 (GitHub code scanning)
  --markdown FILE        also write a Markdown report (e.g. $GITHUB_STEP_SUMMARY)
  --json-file FILE       also write the JSON report to FILE
  --fail-on-error        a server that could not be checked fails the run too
  --no-color`;

export async function parseScanArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<ScanOptions> {
  const opts: ScanOptions = {
    configs: [], project: false, cwd: process.cwd(), launch: true, publicOnly: false, timeoutMs: 30_000, concurrency: 4,
    policy: asPolicy(undefined), updateLock: false, stateDir: defaultStateDir(), histor: false, historUrl: DEFAULT_HISTOR_URL,
    format: 'table', failOnError: false, color: !!process.stdout.isTTY && !env.NO_COLOR,
  };
  let failOn: Severity | undefined, policyFile: string | undefined;
  let classifierUrl: string | undefined, classifierModel: string | undefined, classifierBlocks = false;
  const clients: ClientKind[] = [];
  const value = (flag: string) => {
    const v = argv.shift();
    if (v === undefined || (v.startsWith('--') && v.length > 2)) throw new Error(`Missing value for ${flag}`);
    return v;
  };
  while (argv.length) {
    const arg = argv.shift()!;
    if (!arg.startsWith('--')) { opts.configs.push(arg); continue; }
    switch (arg) {
      case '--project': opts.project = true; break;
      case '--client': {
        const c = value(arg) as ClientKind;
        if (!CLIENT_KINDS.includes(c)) throw new Error(`--client must be one of ${CLIENT_KINDS.join(', ')}`);
        clients.push(c); break;
      }
      case '--cwd': opts.cwd = resolve(value(arg)); break;
      case '--no-launch': opts.launch = false; break;
      case '--public-only': opts.publicOnly = true; break;
      case '--timeout': {
        const n = Number(value(arg));
        if (!Number.isInteger(n) || n < 100 || n > 600_000) throw new Error('--timeout must be 100–600000 ms');
        opts.timeoutMs = n; break;
      }
      case '--concurrency': {
        const n = Number(value(arg));
        if (!Number.isInteger(n) || n < 1 || n > 32) throw new Error('--concurrency must be 1–32');
        opts.concurrency = n; break;
      }
      case '--fail-on': {
        const s = value(arg) as Severity;
        if (!SEVERITIES.includes(s)) throw new Error(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
        failOn = s; break;
      }
      case '--policy': policyFile = value(arg); break;
      case '--lock': opts.lock = resolve(value(arg)); break;
      case '--update-lock': opts.updateLock = true; break;
      case '--state-dir': opts.stateDir = value(arg); break;
      case '--feed': opts.feed = value(arg); break;
      case '--feed-key': opts.feedKey = value(arg); break;
      case '--histor': opts.histor = true; break;
      case '--histor-url': opts.historUrl = value(arg); opts.histor = true; break;
      case '--classifier-url': classifierUrl = value(arg); break;
      case '--classifier-model': classifierModel = value(arg); break;
      case '--classifier-blocks': classifierBlocks = true; break;
      case '--json': opts.format = 'json'; break;
      case '--sarif': opts.sarif = resolve(value(arg)); break;
      case '--markdown': opts.markdown = resolve(value(arg)); break;
      case '--json-file': opts.jsonFile = resolve(value(arg)); break;
      case '--fail-on-error': opts.failOnError = true; break;
      case '--no-color': opts.color = false; break;
      case '--help': case '-h': throw new UsageRequested();
      default: throw new Error(`Unknown option ${arg}`);
    }
  }
  if (clients.length) opts.clients = clients;
  if (opts.updateLock && !opts.lock) throw new Error('--update-lock needs --lock FILE');
  if (opts.updateLock && !opts.launch) throw new Error('--update-lock needs the tool definitions, so it cannot be combined with --no-launch');
  if (opts.project && opts.configs.length) throw new Error('--project and explicit CONFIG files are alternatives');
  if (policyFile) {
    // Same strict reading as `wrap --policy`: a typo must stop the run, not silently relax it.
    const raw = JSON.parse(await readFile(policyFile, 'utf8'));
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('policy must be an object');
    for (const key of Object.keys(raw)) if (!['blockAtSeverity', 'pinToolDefs', 'allowUnknownServers', 'sensitiveToolPatterns'].includes(key)) throw new Error(`Unknown policy field ${key}`);
    opts.policy = asPolicy(raw);
  }
  if (failOn) opts.policy = { ...opts.policy, blockAtSeverity: failOn };
  if (!!classifierUrl !== !!classifierModel) throw new Error('--classifier-url and --classifier-model go together');
  if (classifierBlocks && !classifierUrl) throw new Error('--classifier-blocks needs --classifier-url and --classifier-model');
  if (classifierUrl && classifierModel) {
    const cu = new URL(classifierUrl);
    if (cu.protocol !== 'https:' && cu.protocol !== 'http:') throw new Error('--classifier-url must be http(s)');
    if (cu.username || cu.password) throw new Error('--classifier-url must not carry credentials; use WARDEN_CLASSIFIER_API_KEY');
    opts.classifier = { url: classifierUrl, model: classifierModel, apiKey: env.WARDEN_CLASSIFIER_API_KEY || undefined, blocks: classifierBlocks };
  }
  const u = new URL(opts.historUrl);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('--histor-url must be http(s)');
  return opts;
}

export class UsageRequested extends Error { constructor() { super(SCAN_USAGE); } }

// ── display helpers ──────────────────────────────────────────────────────────

const SECRET_FLAG = /(key|token|secret|password|passwd|pwd|auth|bearer|credential)/i;
const SECRET_SHAPE = /^(?:sk-|sk_|ghp_|gho_|ghs_|github_pat_|xox[abpr]-|aimk_|AKIA|eyJ)[A-Za-z0-9._-]{8,}|^[A-Za-z0-9+/_-]{32,}={0,2}$/;

/** A path segment or argument that looks like it carries a credential. */
export function looksSecret(text: string): boolean {
  if (SECRET_SHAPE.test(text)) return true;
  return text.length >= 24 && /[A-Za-z]/.test(text) && /\d/.test(text) && /^[A-Za-z0-9_-]+$/.test(text);
}

/** The launch line with credentials replaced, for terminals, reports and SARIF. */
export function redactLaunch(server: ConfiguredServer): string {
  const ref = server.ref;
  if (ref.url) return redactUrl(ref.url);
  const out: string[] = [];
  const args = ref.args ?? [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const eq = a.indexOf('=');
    if (a.startsWith('--') && eq > 0 && SECRET_FLAG.test(a.slice(0, eq))) { out.push(a.slice(0, eq + 1) + '***'); continue; }
    if (i > 0 && args[i - 1]!.startsWith('-') && SECRET_FLAG.test(args[i - 1]!)) { out.push('***'); continue; }
    out.push(looksSecret(a) ? '***' : a);
  }
  return [ref.command ?? '', ...out].join(' ').trim();
}

export function redactUrl(raw: string): string {
  try {
    const u = new URL(raw);
    u.username = ''; u.password = '';
    const q = [...u.searchParams.keys()];
    u.search = '';
    for (const k of q) u.searchParams.set(k, '***');
    u.pathname = u.pathname.split('/').map(seg => looksSecret(decodeURIComponent(seg)) ? '***' : seg).join('/');
    return u.toString();
  } catch { return '(unparseable URL)'; }
}

/** The endpoint HISTOR may be asked about, or why it is not sent. */
export function historEndpoint(raw: string): { endpoint?: string; reason?: string } {
  let u: URL;
  try { u = new URL(raw); } catch { return { reason: 'unparseable URL' }; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { reason: 'not an http(s) endpoint' };
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || /\.(local|internal|lan|home|corp|intranet|test|example|invalid)$/.test(host) || !host.includes('.')) {
    return { reason: 'private host name' };
  }
  if (/^[\d.]+$/.test(host) || host.includes(':')) {
    // An address literal: only a public one names something HISTOR could have crawled.
    const v4 = host.split('.').map(Number);
    if (host.includes(':') || v4[0] === 10 || v4[0] === 127 || (v4[0] === 192 && v4[1] === 168) || (v4[0] === 172 && v4[1]! >= 16 && v4[1]! <= 31) || (v4[0] === 169 && v4[1] === 254)) return { reason: 'private address' };
  }
  if (u.pathname.split('/').some(seg => seg && looksSecret(decodeURIComponent(seg)))) return { reason: 'the path looks like it carries a credential' };
  return { endpoint: `${u.protocol}//${u.host}${u.pathname}` };
}

// ── the scan ─────────────────────────────────────────────────────────────────

async function pool<T, R>(items: T[], n: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i]!); }
  }));
  return out;
}

const READ_ONLY = (store: PinStore): PinStore => ({ getPin: id => store.getPin(id), putPin: async () => {} });
const NO_PINS: PinStore = { getPin: async () => undefined, putPin: async () => {} };

function blocking(f: WardenFinding, policy: WardenPolicy): boolean {
  return !f.advisory && SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(policy.blockAtSeverity);
}

export interface ScanDeps {
  fetch?: (server: ConfiguredServer, opts: ScanOptions) => Promise<FetchedServer>;
  historFetch?: typeof fetch;
  now?: () => Date;
  discovery?: Partial<DiscoveryEnv>;
}

export async function runScan(opts: ScanOptions, deps: ScanDeps = {}): Promise<ScanReport> {
  const version = packageVersion();
  const d: DiscoveryEnv = { home: homedir(), cwd: opts.cwd, platform: process.platform, env: process.env, ...deps.discovery };
  let results: SourceResult[];
  if (opts.project) {
    const files = ['.mcp.json', join('.cursor', 'mcp.json'), join('.vscode', 'mcp.json')].map(f => join(opts.cwd, f));
    const { existsSync } = await import('node:fs');
    results = await discoverServers(files.filter(f => existsSync(f)), d);
    // An explicit file list makes guessClient decide; mark scope honestly.
    for (const r of results) { r.source.scope = 'project'; for (const s of r.servers) s.scope = 'project'; }
    if (!results.length) results = [];
  } else {
    results = await discoverServers(opts.configs.length ? opts.configs : undefined, d, opts.clients);
  }

  const feed = new ThreatFeed({ feedPublicKey: opts.feedKey, stateDir: opts.stateDir });
  await feed.load(opts.feed);
  const lockFile: LockFile | undefined = opts.lock ? await readLock(opts.lock) : undefined;
  const lockStore = opts.lock ? new LockStore(lockFile?.servers ?? {}) : undefined;
  const wrapPins = READ_ONLY(new FilePinStore(join(opts.stateDir, 'pins')));
  const now = (deps.now ?? (() => new Date()))().toISOString();

  const all: ConfiguredServer[] = results.flatMap(r => r.servers);
  // The same server listed by two clients is checked once per entry: they are separate launches.
  const servers = await pool(all, opts.concurrency, async (server): Promise<ScanServerResult> => {
    const base: ScanServerResult = {
      id: server.id, key: server.key, client: server.client, source: server.source, scope: server.scope,
      transport: server.ref.transport, wrapped: server.wrapped, launch: redactLaunch(server),
      status: 'skipped', allow: null, findings: [], allowedTools: [], blockedTools: [],
    };
    if (server.skipped) return { ...base, skipped: server.skipped };
    const store = lockStore ?? (server.wrapped ? wrapPins : NO_PINS);
    const warden = Warden.create({ policy: opts.policy, threatFeed: feed, store });
    const launchVerdict = await warden.vetLaunch(server.ref);
    const lockEntry = lockStore ? lockStore.entries.get(server.id) : undefined;
    const lockMissing: WardenFinding | undefined = lockStore && !lockEntry ? {
      gate: 'lock', severity: 'high', code: 'LOCK_MISSING',
      message: `Server "${displaySafe(server.id)}" is not in the lock file, so its tool definitions were never reviewed. Run scan --lock … --update-lock and commit the lock.`,
    } : undefined;
    if (!launchVerdict.allow) {
      return { ...base, status: 'blocked-at-launch', allow: false, score: launchVerdict.score, decidedBy: launchVerdict.decidedBy,
        findings: [...launchVerdict.findings, ...(lockMissing ? [lockMissing] : [])], lock: lockStore ? { state: lockEntry ? 'drift' : 'missing' } : undefined };
    }
    if (server.ref.transport === 'stdio' && !opts.launch) {
      const findings = [...launchVerdict.findings, ...(lockMissing ? [lockMissing] : [])];
      return { ...base, status: 'launch-only', allow: !lockMissing, score: launchVerdict.score, findings,
        ...(lockMissing ? { decidedBy: 'lock' } : {}), lock: lockStore ? { state: lockEntry ? 'match' : 'missing' } : undefined };
    }

    let fetched: FetchedServer;
    try {
      fetched = deps.fetch ? await deps.fetch(server, opts)
        : await fetchServer(server.ref, { timeoutMs: opts.timeoutMs, clientVersion: version, publicOnly: opts.publicOnly, headers: server.headers, cwd: opts.cwd });
    } catch (err) {
      const msg = err instanceof McpClientError ? err.message : err instanceof Error ? err.message : String(err);
      return { ...base, status: 'error', error: displaySafe(msg, 400), findings: lockMissing ? [lockMissing] : [], allow: lockMissing ? false : null, ...(lockMissing ? { decidedBy: 'lock' } : {}) };
    }

    const verdict: WardenVerdict = await warden.vet(server.ref, fetched.tools);
    const findings = [...verdict.findings];
    let allow = verdict.allow, decidedBy = verdict.decidedBy, score = verdict.score;
    if (fetched.instructions) {
      // The same check wrap applies before passing initialize.instructions to the client.
      const scan = await new Warden({ policy: opts.policy, gates: [new StaticScanGate()] })
        .vet(server.ref, [{ name: 'initialize.instructions', description: fetched.instructions, inputSchema: { type: 'object' } }]);
      for (const f of scan.findings) findings.push({ ...f, tool: 'initialize.instructions' });
      if (!scan.allow) { if (allow) decidedBy = 'static-scan'; allow = false; }
      score *= scan.score;
    }
    if (lockMissing) { findings.push(lockMissing); if (allow) decidedBy = 'lock'; allow = false; }

    let mtlDigest: string | undefined, mtlError: string | undefined;
    try { mtlDigest = mtlToolSetDigest(fetched.tools); }
    catch (err) { mtlError = err instanceof MtlError ? err.code : String(err); }

    let histor: HistorSummary | undefined;
    if (opts.histor && server.ref.url) {
      const target = historEndpoint(server.ref.url);
      if (!target.endpoint) histor = { notSent: target.reason };
      else {
        try {
          const answer: HistorCheck = await historCheck(opts.historUrl, { endpoint: target.endpoint, ...(mtlDigest ? { toolSetDigest: mtlDigest } : {}) },
            { fetchImpl: deps.historFetch, userAgent: `warden-scan/${version}` });
          histor = { match: String(answer.match), note: typeof answer.note === 'string' ? displaySafe(answer.note, 400) : undefined,
            page: answer.target?.page, unchangedSince: answer.observed?.unchangedSince, changes: answer.observed?.changes };
          if (answer.match === 'different') findings.push({ gate: 'histor', severity: 'medium', code: 'HISTOR_UNSEEN_TOOLSET', advisory: true,
            message: `HISTOR has never observed the tool set this server served you (${mtlDigest}). Either it changed after the last crawl, or it serves you something it does not serve the public crawler.` });
          if (answer.match === 'previously-observed') findings.push({ gate: 'histor', severity: 'low', code: 'HISTOR_OLDER_TOOLSET', advisory: true,
            message: 'HISTOR observed this tool set earlier, but the server now serves the public a different one.' });
          // The log's own classifier verdict on the set you were served, when it holds one: advisory, never a block.
          const cls = answer.classifier as { status?: unknown; model?: unknown; findings?: unknown } | undefined;
          if (answer.match === 'same' && cls && cls.status === 'classified' && Array.isArray(cls.findings)) {
            for (const f of cls.findings.slice(0, 50) as Array<Record<string, unknown>>) {
              const cats = Array.isArray(f.categories) ? f.categories.filter((c): c is string => typeof c === 'string').slice(0, 4) : [];
              if (!cats.length || typeof f.tool !== 'string') continue;
              findings.push({ gate: 'histor', severity: 'medium', code: 'HISTOR_CLASSIFIER', advisory: true, tool: f.tool,
                message: `HISTOR's classifier (${displaySafe(String(cls.model ?? 'model'), 60)}) reads this tool as ${cats.map(c => displaySafe(c, 30)).join(', ')}: ${displaySafe(String(f.reason ?? ''), 300)}` });
            }
          }
        } catch (err) { histor = { error: displaySafe(err instanceof Error ? err.message : String(err), 200) }; }
      }
    }

    let classifier: ScanServerResult['classifier'];
    if (opts.classifier && fetched.tools.length) {
      try {
        const verdicts = await classifyTools(fetched.tools, opts.classifier);
        classifier = { model: opts.classifier.model, flagged: verdicts.length };
        for (const v of verdicts) {
          const f: WardenFinding = { gate: 'classifier', code: 'TOOL_DEF_CLASSIFIER', severity: v.severity, tool: v.tool,
            message: `Model ${displaySafe(opts.classifier.model, 60)} reads this tool as ${v.categories.join(', ')}: ${displaySafe(v.reason, 300)} — at "${displaySafe(v.quote, 200)}"` };
          if (!opts.classifier.blocks) f.advisory = true;
          findings.push(f);
          if (opts.classifier.blocks && blocking(f, opts.policy)) {
            if (allow) decidedBy = 'classifier';
            allow = false;
          }
        }
      } catch (err) {
        classifier = { model: opts.classifier.model, flagged: 0, error: displaySafe(err instanceof ClassifierError ? err.message : String(err), 200) };
      }
    }

    let lock: ScanServerResult['lock'];
    if (lockStore) {
      const changes = diffTools(lockEntry?.tools, fetched.tools);
      const drift = findings.some(f => f.code === 'TOOL_DEF_DRIFT' || f.code === 'SERVER_IDENTITY_DRIFT' || f.code === 'PIN_FORMAT_UPGRADE_REQUIRED' || (f.code === 'TOOL_DEF_UNCANONICAL' && !!lockEntry));
      lock = { state: !lockEntry ? 'missing' : drift ? 'drift' : 'match', ...(changes.length && lockEntry ? { changes } : !lockEntry ? { changes } : {}) };
    }

    return { ...base, status: 'scanned', allow, decidedBy: allow ? undefined : decidedBy, score, findings,
      allowedTools: verdict.allowedTools, blockedTools: verdict.blockedTools, toolCount: fetched.tools.length,
      serverInfo: fetched.serverInfo, mtlDigest, mtlError, histor, classifier, lock, tools: fetched.tools,
      ...(classifier && opts.classifier?.blocks ? { blockedTools: [...new Set([...verdict.blockedTools, ...findings.filter(f => f.gate === 'classifier' && !f.advisory && blocking(f, opts.policy)).map(f => f.tool!)])] } : {}) };
  });

  let lockSummary: ScanReport['lock'];
  if (opts.lock && lockStore) {
    const ids = new Set(servers.filter(s => s.status !== 'skipped').map(s => s.id));
    const stale = [...lockStore.entries.keys()].filter(id => !ids.has(id)).sort();
    let written = false;
    if (opts.updateLock) {
      const next: Record<string, LockEntry> = {};
      for (const s of servers) {
        if (s.status === 'skipped') continue;
        const previous = lockStore.entries.get(s.id);
        if (s.status !== 'scanned' || !s.tools) { if (previous) next[s.id] = previous; if (s.lock) s.lock.state = 'refused'; continue; }
        // Approve only what the non-pinning gates accept, as `pins approve` does.
        const fresh = await Warden.create({ policy: opts.policy, threatFeed: feed, store: NO_PINS }).vet(serverRef(s, all), s.tools);
        const instructionsBlocked = s.findings.some(f => f.tool === 'initialize.instructions' && blocking(f, opts.policy));
        if (!fresh.allow || instructionsBlocked) { if (previous) next[s.id] = previous; s.lock = { ...(s.lock ?? { state: 'refused' }), state: 'refused' }; continue; }
        const entry = lockEntryFor(serverRef(s, all), s.tools, s.mtlDigest, previous, now);
        next[s.id] = entry;
        const changed = !previous || previous.toolsHash !== entry.toolsHash || previous.identityHash !== entry.identityHash;
        s.lock = { ...(s.lock ?? { state: 'updated' }), state: changed ? 'updated' : 'unchanged' };
        // Once written, the server is reviewed: drop the findings that only said "not reviewed / drifted".
        s.findings = s.findings.filter(f => !['LOCK_MISSING', 'TOOL_DEF_DRIFT', 'SERVER_IDENTITY_DRIFT', 'PIN_FORMAT_UPGRADE_REQUIRED', 'TOOL_DEF_UNPINNED'].includes(f.code));
        s.allow = !s.findings.some(f => blocking(f, opts.policy));
        if (s.allow) { s.decidedBy = undefined; s.blockedTools = fresh.blockedTools; s.allowedTools = fresh.allowedTools; }
      }
      await writeLock(opts.lock, { lockfileVersion: LOCK_VERSION, generatedBy: `@aimarket/warden ${version}`, ruleset: staticScanRulesetRef(), servers: next });
      written = true;
    }
    lockSummary = { path: opts.lock, stale: opts.updateLock ? [] : stale, written };
  }

  const summary = {
    servers: servers.length,
    scanned: servers.filter(s => s.status === 'scanned').length,
    allowed: servers.filter(s => s.allow === true && s.status === 'scanned').length,
    blocked: servers.filter(s => s.allow === false).length,
    errors: servers.filter(s => s.status === 'error').length,
    skipped: servers.filter(s => s.status === 'skipped').length,
    launchOnly: servers.filter(s => s.status === 'launch-only').length,
  };
  return {
    tool: 'warden-scan', version, scannedAt: now, ruleset: staticScanRulesetRef(), policy: opts.policy, launch: opts.launch,
    sources: results.map(r => ({ path: r.source.path, client: r.source.client, scope: r.source.scope, servers: r.servers.length, ...(r.error ? { error: displaySafe(r.error, 300) } : {}) })),
    servers, lock: lockSummary, summary,
  };
}

function serverRef(s: ScanServerResult, all: ConfiguredServer[]) {
  const found = all.find(c => c.id === s.id && c.source === s.source && c.key === s.key);
  return found!.ref;
}

export function exitCode(report: ScanReport, opts: Pick<ScanOptions, 'failOnError'>): number {
  if (report.summary.blocked > 0) return 1;
  if (opts.failOnError && (report.summary.errors > 0 || report.sources.some(s => s.error))) return 1;
  return 0;
}
