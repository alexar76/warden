// ─────────────────────────────────────────────────────────────────────────────
// WARDEN — the MCP security firewall: protocol types
//
// Everything a host needs to talk to WARDEN lives in this file, and nothing
// here depends on a particular agent. Two of these interfaces are host-supplied
// seams rather than data — `PinStore` (where approvals are remembered) and
// `WardenLogger` (where findings are written) — deliberately narrowed to what
// the gates actually call, so a host can satisfy them with a Map and a no-op.
// ─────────────────────────────────────────────────────────────────────────────

export type JSONSchema = Record<string, unknown>;

/** An MCP tool as its server advertises it — the primary attack surface. */
export interface ToolDef {
  name: string;
  description: string;
  inputSchema: JSONSchema;
}

export interface McpServerRef {
  id: string;
  name: string;
  transport: "stdio" | "sse" | "http";
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  /** Optional catalog this server was discovered from. */
  catalog?: string;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface WardenFinding {
  gate: string;
  severity: Severity;
  /** Stable machine code, e.g. "TOOL_DEF_INJECTION". */
  code: string;
  message: string;
  /** Optional tool the finding refers to. */
  tool?: string;
  /**
   * Report-only: this finding NEVER blocks a connection and never costs a tool,
   * at ANY `blockAtSeverity` setting. It is still reported. Whether it affects a
   * gate's score is the gate's decision — the static scanner excludes advisory
   * hits from its score, the pinning gate still rates an unpinned server 0.9.
   *
   * The tier is data, not a consequence of severity, because severity answers
   * "how much attention" and tiering answers "is this a defect at all". A tool
   * whose schema takes an `api_key` is worth pointing at and is not a defect;
   * expressing that by lowering its severity would have made it blocking again
   * for anyone who tightened `blockAtSeverity`.
   */
  advisory?: boolean;
}

export interface WardenVerdict {
  allow: boolean;
  /** 0..1 composite safety score (1 = safe). */
  score: number;
  /** The gate that produced the final decision, if blocked. */
  decidedBy?: string;
  findings: WardenFinding[];
  /** Per-tool decisions when partial allow is in play. */
  allowedTools: string[];
  blockedTools: string[];
  /**
   * Which rule tables produced these findings. A recorded scan is only
   * reproducible together with them: the same server can score differently
   * under a later ruleset, and without the version and digest there is no way
   * to tell that apart from the server having changed.
   */
  rulesets: { staticScan: RulesetRef };
}

/** Identifies an exact rule table: a human version plus a digest of its content. */
export interface RulesetRef {
  /** Monotonic version of the rule table. */
  version: string;
  /** `sha256-<base64>` over the canonical serialization of every rule. */
  digest: string;
}

/** What a gate sees: the server + its advertised tools + accumulating state. */
export interface WardenGateInput {
  server: McpServerRef;
  tools: ToolDef[];
  /** Findings accumulated by earlier gates. */
  prior: WardenFinding[];
  policy: WardenPolicy;
}

export interface WardenGateResult {
  findings: WardenFinding[];
  /** Per-gate score contribution 0..1 (1 = this gate is satisfied). */
  score: number;
  /** If true, short-circuit the chain and block immediately. */
  fatal?: boolean;
}

export interface WardenGate {
  readonly name: string;
  evaluate(input: WardenGateInput): Promise<WardenGateResult>;
}

export interface WardenPolicy {
  /** Block the whole connection if any finding >= this severity. */
  blockAtSeverity: Severity;
  /** Tool names that always require explicit user approval before running. */
  sensitiveToolPatterns: string[];
  /**
   * Allow connecting to servers the operator never declared — that is, servers
   * the host discovered from a remote catalog, which carry
   * `McpServerRef.catalog`. `false` is fail-closed: only servers the operator
   * listed explicitly may connect.
   *
   * This knob used to mean "has no reputation score yet", which no deployment
   * could satisfy: nothing ever passed trust edges to the reputation oracle, so
   * every server came back unvouched and `false` blocked all of them. Catalog
   * provenance is a fact the host actually holds locally, needs no network, and
   * cannot deadlock — a declared server is always known.
   */
  allowUnknownServers: boolean;
  /** Re-approval required if a server's tool defs change after pinning. */
  pinToolDefs: boolean;
}

/** A pinned snapshot of a server's tools, used for drift detection. */
export interface PinnedServer {
  serverId: string;
  /** sha256 over the canonical tool-def set. */
  toolsHash: string;
  approvedAt: string;
  toolNames: string[];
}

/**
 * Where approvals are remembered between runs — the only persistence WARDEN
 * needs. Narrow on purpose: any store with these two methods works, including a
 * Map for tests. Without durable pins, drift detection degrades to "every
 * server is seen for the first time, every time".
 */
export interface PinStore {
  getPin(serverId: string): Promise<PinnedServer | undefined>;
  putPin(p: PinnedServer): Promise<void>;
}

/**
 * Which surface a threat pattern is meaningful against:
 * - `server` — the server's identity/config only (id, name, url, command, args).
 * - `tool` — the advertised tool definitions only (name, description, inputSchema).
 * - `any` — both. This is the default when a record omits `scope`.
 */
export type ThreatScope = "server" | "tool" | "any";

/** A signed threat-intel record about a known-bad server/tool. */
export interface ThreatRecord {
  /** Pattern matched against server identity and/or tool definitions per `scope`. */
  pattern: string;
  severity: Severity;
  code: string;
  reason: string;
  source: string;
  /** Match surface; defaults to `"any"` when absent. */
  scope?: ThreatScope;
}

export type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * Where WARDEN writes. Structurally identical to most host loggers, so an
 * existing one usually satisfies it as-is; `silentLogger()` is provided for
 * hosts that have none.
 */
export interface WardenLogger {
  debug(msg: string, ...a: unknown[]): void;
  info(msg: string, ...a: unknown[]): void;
  warn(msg: string, ...a: unknown[]): void;
  error(msg: string, ...a: unknown[]): void;
  child(scope: string): WardenLogger;
}
