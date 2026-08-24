import { verify, createPublicKey } from "node:crypto";
import { canonicalize, parseJsonStrict, CanonicalizationError } from "./jcs.js";
import type {
  McpServerRef,
  Severity,
  ThreatRecord,
  ThreatScope,
  ToolDef,
  WardenFinding,
  WardenGate,
  WardenGateInput,
  WardenGateResult,
  WardenLogger,
} from "./types.js";

/**
 * Threat-intel feed for known-bad MCP servers/tools.
 *
 * Reputation answers "is this server trusted?"; the threat feed answers "is this
 * server a *known* bad actor?". It ships with a small built-in deny-list of
 * patterns (credential-stealing, destructive commands, crypto-drainer keywords,
 * typosquat-style names) and can be topped up from a signed remote feed.
 *
 * **In the shipping configuration there is no remote feed.** `warden.threatFeedUrl`
 * and `warden.feedPublicKey` default to `undefined` (see `src/config.ts`), so
 * unless an operator sets both, this gate *is* the {@link BUILTIN} list — a fixed
 * floor of 11 patterns, not live intel. That is a deliberate default: ARGUS ships
 * no feed endpoint and no publisher key, because a feed URL baked into the binary
 * is a single point every install would have to trust.
 *
 * When a feed *is* configured, three properties are enforced fail-closed — any of
 * them failing keeps the built-in floor and changes nothing else:
 *
 * - **Authenticity.** An Ed25519 signature over the canonical form of
 *   `{records, timestamp}`, verified with a pre-configured public key. Unsigned
 *   feeds are refused outright.
 * - **Freshness.** The signed `timestamp` must be within {@link
 *   DEFAULT_FEED_MAX_AGE_MS} (configurable). Without this, whoever serves the feed
 *   URL can replay a months-old snapshot forever and silently erase every threat
 *   record added since — a signature says *who* wrote a document, never *when you
 *   were handed it*.
 * - **Determinism.** The signed bytes are RFC 8785 canonical (§4 of
 *   `awr/SPEC.md`), so publisher and verifier agree on them regardless of the key
 *   order the wire used.
 *
 * The remote fetch degrades silently otherwise: a feed outage must never weaken
 * the built-in floor or crash a connection check.
 */

/**
 * Default freshness window for a signed remote feed: 24 h.
 *
 * Rationale for a *default* rather than an opt-in: a feed whose age is unchecked
 * is indistinguishable from a feed that is being replayed. An operator publishing
 * on a slower cadence should raise `warden.feedMaxAgeMs`, not disable the check.
 *
 * (Note the deliberate difference from AWR documents, where age is *policy, not
 * validity* — SPEC §11.3. A work receipt from two years ago is still a true
 * statement about the past; a deny-list from two years ago is a false statement
 * about the present.)
 */
export const DEFAULT_FEED_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Tolerance for a feed timestamp in the future — publisher/host clock skew.
 * Beyond it the feed is refused: a future-dated snapshot would otherwise pass the
 * freshness check for as long as the date it claims.
 */
export const FEED_CLOCK_SKEW_MS = 5 * 60 * 1000;

/** Hard cap on a feed response body (OOM guard). */
const MAX_FEED_BYTES = 512_000;

/**
 * Built-in deny-list. Small but real — patterns seen in poisoned MCP servers.
 *
 * `scope` says where each pattern means something (see {@link ThreatFeed.match}):
 *
 * - `server` for the **command-line and identity** signatures. `rm -rf`, a fork
 *   bomb or a typosquatted name are evidence in `server.command`/`args` or in a
 *   server's name; in prose they are as likely to be documentation as attack — a
 *   security tool's own description may well list `offical-mcp`.
 * - `any` for the **content** signatures. A credential path, a seed phrase or a
 *   drainer keyword appearing in a tool name, description or input schema is
 *   exactly the tool-poisoning shape `static-scan` also looks for, so those
 *   patterns are matched against tool definitions as well as server identity.
 */
const BUILTIN: ThreatRecord[] = [
  {
    pattern: "*~/.ssh*",
    severity: "critical",
    code: "THREAT_SSH_KEY_READ",
    reason: "Server references the user's SSH key directory.",
    source: "builtin",
    scope: "any",
  },
  {
    pattern: "*id_rsa*",
    severity: "critical",
    code: "THREAT_SSH_KEY_READ",
    reason: "Server references a private SSH key file.",
    source: "builtin",
    scope: "any",
  },
  {
    pattern: "*rm -rf*",
    severity: "critical",
    code: "THREAT_DESTRUCTIVE_CMD",
    reason: "Server command performs a destructive recursive delete.",
    source: "builtin",
    scope: "server",
  },
  {
    pattern: "*:(){ :|:&};:*",
    severity: "critical",
    code: "THREAT_FORK_BOMB",
    reason: "Server command contains a shell fork bomb.",
    source: "builtin",
    scope: "server",
  },
  {
    pattern: "*drain*wallet*",
    severity: "critical",
    code: "THREAT_CRYPTO_DRAINER",
    reason: "Crypto-drainer keyword in server identity.",
    source: "builtin",
    scope: "any",
  },
  {
    pattern: "*seed*phrase*",
    severity: "high",
    code: "THREAT_SEED_PHRASE",
    reason: "Server references wallet seed phrases.",
    source: "builtin",
    scope: "any",
  },
  {
    pattern: "*sweep*funds*",
    severity: "critical",
    code: "THREAT_CRYPTO_DRAINER",
    reason: "Crypto-drainer keyword in server identity.",
    source: "builtin",
    scope: "any",
  },
  {
    pattern: "*.env*exfil*",
    severity: "critical",
    code: "THREAT_ENV_EXFIL",
    reason: "Server references exfiltrating environment files.",
    source: "builtin",
    scope: "any",
  },
  // Typosquat-style names mimicking the official reference servers.
  {
    pattern: "*offical-mcp*",
    severity: "high",
    code: "THREAT_TYPOSQUAT",
    reason: "Typosquat of an official MCP server name.",
    source: "builtin",
    scope: "server",
  },
  {
    pattern: "*modelcontextprotocoll*",
    severity: "high",
    code: "THREAT_TYPOSQUAT",
    reason: "Typosquat of modelcontextprotocol.",
    source: "builtin",
    scope: "server",
  },
  {
    pattern: "*filesytem*",
    severity: "medium",
    code: "THREAT_TYPOSQUAT",
    reason: "Typosquat of the filesystem reference server.",
    source: "builtin",
    scope: "server",
  },
];

export interface ThreatFeedOptions {
  /** Ed25519 public key (hex-encoded SPKI DER) of the feed publisher. */
  feedPublicKey?: string;
  /**
   * Maximum age of a signed feed's `timestamp`. Defaults to
   * {@link DEFAULT_FEED_MAX_AGE_MS}; a non-finite or non-positive value falls back
   * to the default rather than disabling the check.
   */
  maxAgeMs?: number;
  log?: WardenLogger;
  /** Clock source. Injectable so freshness is testable without waiting a day. */
  now?: () => number;
}

export class ThreatFeed {
  private records: ThreatRecord[] = [...BUILTIN];
  private feedPublicKey?: string;
  private readonly maxAgeMs: number;
  private readonly now: () => number;
  private readonly log?: WardenLogger;

  constructor(opts?: ThreatFeedOptions) {
    this.feedPublicKey = opts?.feedPublicKey;
    this.maxAgeMs =
      opts?.maxAgeMs != null && Number.isFinite(opts.maxAgeMs) && opts.maxAgeMs > 0
        ? opts.maxAgeMs
        : DEFAULT_FEED_MAX_AGE_MS;
    this.now = opts?.now ?? (() => Date.now());
    this.log = opts?.log;
  }

  /** The built-in floor, always present regardless of remote load state. */
  get builtins(): ThreatRecord[] {
    return [...BUILTIN];
  }

  all(): ThreatRecord[] {
    return [...this.records];
  }

  /**
   * Fetch and verify a signed remote threat feed.
   *
   * Feed format: `{ records: ThreatRecord[], timestamp: number, signature: string }`
   * where `timestamp` is **epoch milliseconds** and `signature` is a hex-encoded
   * Ed25519 signature over the RFC 8785 (JCS) canonical form of
   * `{records, timestamp}` — see {@link canonicalize}. A publisher that signs
   * `JSON.stringify` output instead will not verify here, and that is the point:
   * `JSON.stringify` bytes depend on the key order of whatever object the
   * publisher happened to build, so the same logical feed could be signed and then
   * fail to verify.
   *
   * - Without a configured `feedPublicKey`, remote feeds are refused.
   * - Signature failure logs a warning and preserves the built-in floor.
   * - A missing/non-integer `timestamp`, a snapshot older than `maxAgeMs`, or one
   *   dated further ahead than {@link FEED_CLOCK_SKEW_MS} is refused — a replayed
   *   old snapshot would otherwise erase every newer threat record.
   * - Network/parse errors degrade silently — built-ins remain.
   */
  async load(feedUrl?: string): Promise<void> {
    if (!feedUrl) return;
    if (!this.feedPublicKey) {
      this.log?.warn("threat feed URL configured but no feedPublicKey set — remote feed REFUSED (unsigned feeds not allowed)");
      return;
    }
    try {
      // AbortController with a 10 s timeout — a hanging feed must not block startup.
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 10_000);
      const res = await fetch(feedUrl, { signal: ctrl.signal }).finally(() => clearTimeout(timer));
      if (!res.ok) {
        this.log?.warn(`threat feed fetch returned ${res.status} — keeping built-in floor`);
        return;
      }
      // Reject oversized responses before parsing (OOM guard).
      const cl = res.headers.get("content-length");
      if (cl && Number(cl) > MAX_FEED_BYTES) {
        this.log?.warn(`threat feed: content-length ${cl} exceeds ${MAX_FEED_BYTES} byte limit — rejected`);
        return;
      }
      // Read text, not res.json(): the received characters are what the canonical
      // parser needs for its duplicate-key and number-literal checks.
      const body = await res.text();
      if (Buffer.byteLength(body, "utf8") > MAX_FEED_BYTES) {
        this.log?.warn(`threat feed: body exceeds the ${MAX_FEED_BYTES} byte limit (content-length absent or wrong) — rejected`);
        return;
      }

      let data: unknown;
      try {
        data = parseJsonStrict(body);
      } catch (err) {
        this.log?.warn(`threat feed: body rejected by the canonical JSON parser (${(err as Error).message})`);
        return;
      }
      if (!data || typeof data !== "object") return;
      const pkg = data as Record<string, unknown>;

      const records = pkg.records;
      const signature = pkg.signature;
      const timestamp = pkg.timestamp;
      if (!Array.isArray(records) || typeof signature !== "string") {
        this.log?.warn("threat feed: missing or invalid fields (records, signature) — rejected");
        return;
      }
      // The timestamp is REQUIRED: it is what the freshness check is made of, and
      // an optional one would mean "a feed that omits it is fresh forever".
      if (typeof timestamp !== "number" || !Number.isInteger(timestamp)) {
        this.log?.warn("threat feed: missing or non-integer `timestamp` (epoch ms) — rejected, freshness cannot be checked");
        return;
      }

      // Ed25519 signature over the CANONICAL JSON of {records, timestamp}.
      let payload: string;
      try {
        payload = canonicalize({ records, timestamp });
      } catch (err) {
        const detail = err instanceof CanonicalizationError ? err.message : (err as Error).message;
        this.log?.warn(`threat feed: payload has no canonical form (${detail}) — rejected`);
        return;
      }
      const sigBuf = Buffer.from(signature, "hex");
      let pubKey;
      try {
        pubKey = createPublicKey({
          key: Buffer.from(this.feedPublicKey, "hex"),
          format: "der",
          type: "spki",
        });
      } catch (err) {
        // A misconfigured key must say so out loud: silently degrading here would
        // look exactly like "the feed had nothing new".
        this.log?.warn(`threat feed: feedPublicKey is not a valid hex SPKI DER key (${(err as Error).message}) — feed REFUSED`);
        return;
      }
      const ok = verify(null, Buffer.from(payload, "utf8"), pubKey, sigBuf);
      if (!ok) {
        this.log?.warn("threat feed: Ed25519 signature INVALID — feed rejected, built-in floor preserved");
        return;
      }

      // Freshness is checked only now: until the signature verifies, `timestamp`
      // is a number an attacker chose, and refusing on it would prove nothing.
      const age = this.now() - timestamp;
      if (age > this.maxAgeMs) {
        this.log?.warn(
          `threat feed: signed snapshot is ${formatDuration(age)} old, past the ${formatDuration(this.maxAgeMs)} limit — ` +
            `REJECTED as stale (possible replay of a superseded feed); built-in floor preserved`,
        );
        return;
      }
      if (age < -FEED_CLOCK_SKEW_MS) {
        this.log?.warn(
          `threat feed: signed snapshot is dated ${formatDuration(-age)} in the future, beyond the ` +
            `${formatDuration(FEED_CLOCK_SKEW_MS)} clock-skew allowance — REJECTED; built-in floor preserved`,
        );
        return;
      }

      const remote = records.filter(isThreatRecord);
      this.records = [...BUILTIN, ...remote];
      this.log?.info(
        `threat feed loaded: ${this.records.length} records (${BUILTIN.length} builtin + ${remote.length} remote, ` +
          `signature valid, snapshot ${formatDuration(age)} old)`,
      );
    } catch (err) {
      // Degrade gracefully: built-ins remain in effect.
      this.log?.debug(`threat feed load error: ${(err as Error).message}`);
    }
  }

  /**
   * Match a server — and its advertised tool definitions — against every record.
   * One finding per matched record per surface.
   *
   * Two surfaces, because a threat record about an MCP server is not only a
   * statement about the config the user wrote:
   *
   * - **Server identity** (`id`, `name`, `url`, `command`, `args`): the local
   *   config. This is the only surface a pattern matches when its `scope` is
   *   `"server"`.
   * - **Tool definitions** (`name`, `description`, `inputSchema`): attacker-
   *   controlled text the *server* chose, which is where a poisoned tool actually
   *   lives. Matched for records scoped `"any"` (the default) or `"tool"`.
   *
   * Findings from the tool surface carry `tool`, so `Warden.partitionTools()` can
   * quarantine the one tool instead of attributing the match to the whole
   * connection. The connection is still blocked when the severity reaches
   * `policy.blockAtSeverity` — per-tool attribution narrows the *blame*, it does
   * not soften the policy.
   */
  match(server: McpServerRef, tools: ToolDef[] = []): WardenFinding[] {
    const serverHay = [
      server.id,
      server.name,
      server.url ?? "",
      server.command ?? "",
      (server.args ?? []).join(" "),
    ]
      .join("\n")
      .toLowerCase();

    // Built once: the record loop below would otherwise re-stringify every schema.
    const toolHays = tools.map((tool) => ({
      name: tool.name,
      hay: [tool.name, tool.description ?? "", stringifySchema(tool.inputSchema)].join("\n").toLowerCase(),
    }));

    const findings: WardenFinding[] = [];
    for (const rec of this.records) {
      const scope: ThreatScope = rec.scope ?? "any";

      if (scope !== "tool" && patternMatches(rec.pattern, serverHay)) {
        findings.push({
          gate: "threat-feed",
          severity: rec.severity,
          code: rec.code,
          message: `${rec.reason} (matched "${rec.pattern}" in server identity, source: ${rec.source})`,
        });
      }

      if (scope === "server") continue;
      for (const tool of toolHays) {
        if (patternMatches(rec.pattern, tool.hay)) {
          findings.push({
            gate: "threat-feed",
            severity: rec.severity,
            code: rec.code,
            message: `Tool "${tool.name}": ${rec.reason} (matched "${rec.pattern}" in the tool definition, source: ${rec.source})`,
            tool: tool.name,
          });
        }
      }
    }
    return findings;
  }
}

/**
 * Gate wrapper around a ThreatFeed. Any match is disqualifying for the score; a
 * critical-severity match against the *server's identity* short-circuits the chain
 * (fatal), because nothing about that connection is salvageable.
 *
 * A critical match against a single tool definition is deliberately not fatal: it
 * still scores 0 and still blocks under the default `blockAtSeverity`, but letting
 * the remaining gates run means the verdict names every problem and every affected
 * tool instead of only the first one found.
 */
export class ThreatGate implements WardenGate {
  readonly name = "threat-feed";

  constructor(private readonly feed: ThreatFeed) {}

  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const findings = this.feed.match(input.server, input.tools);
    if (findings.length === 0) return { findings, score: 1 };
    const fatal = findings.some((f) => f.severity === "critical" && !f.tool);
    return { findings, score: 0, fatal };
  }
}

/**
 * Case-insensitive match. `*` is a wildcard (glob); a pattern with no `*` is a
 * plain substring test. `hay` is expected to be pre-lowercased.
 */
function patternMatches(pattern: string, hay: string): boolean {
  const p = pattern.toLowerCase();
  if (!p.includes("*")) return hay.includes(p);
  const re = globToRegExp(p);
  return re.test(hay);
}

/**
 * Translate a `*`-glob into an anchored regex, escaping all other metachars.
 * The `s` (dotAll) flag is essential: a haystack joins several fields with
 * newlines, and without it `.*` would not cross a newline — silently defeating
 * every `*…*` pattern. (Regression-tested in test/warden.test.ts.)
 */
function globToRegExp(glob: string): RegExp {
  const escaped = glob
    .split("*")
    .map((seg) => seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`, "is");
}

/**
 * Flatten a tool's input schema for pattern matching only. Key order is
 * irrelevant here (a glob over a lowercased blob), so plain `JSON.stringify` is
 * the right tool — unlike the signed and hashed paths, which need
 * {@link canonicalize}.
 */
function stringifySchema(schema: unknown): string {
  try {
    return JSON.stringify(schema) ?? "";
  } catch {
    return String(schema ?? "");
  }
}

/** Human-readable duration for log lines: minutes under an hour, else hours. */
function formatDuration(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (Math.abs(minutes) < 60) return `${minutes} min`;
  return `${Math.round(ms / 360_000) / 10} h`;
}

const THREAT_SCOPES: ThreatScope[] = ["server", "tool", "any"];

function isThreatRecord(v: unknown): v is ThreatRecord {
  if (!v || typeof v !== "object") return false;
  const r = v as Record<string, unknown>;
  const severities: Severity[] = ["info", "low", "medium", "high", "critical"];
  return (
    typeof r.pattern === "string" && r.pattern.length > 0 && r.pattern.length <= 2000 &&
    typeof r.code === "string" && r.code.length > 0 && r.code.length <= 200 &&
    typeof r.reason === "string" && r.reason.length > 0 && r.reason.length <= 2000 &&
    typeof r.source === "string" && r.source.length > 0 && r.source.length <= 200 &&
    typeof r.severity === "string" &&
    severities.includes(r.severity as Severity) &&
    // An unrecognised scope drops the record instead of defaulting it: a publisher
    // that meant "server" must not have its pattern silently widened to tool text.
    (r.scope === undefined || (typeof r.scope === "string" && THREAT_SCOPES.includes(r.scope as ThreatScope)))
  );
}
