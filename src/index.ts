import type {
  McpServerRef,
  PinStore,
  Severity,
  ToolDef,
  WardenFinding,
  WardenGate,
  WardenGateResult,
  WardenLogger,
  WardenPolicy,
  WardenVerdict,
} from "./types.js";
import { StaticScanGate, staticScanRulesetRef } from "./static-scan.js";
import { PinningGate } from "./pinning.js";
import { OriginGate } from "./origin.js";
import { ThreatFeed, ThreatGate } from "./threat-feed.js";
import { classifyTools } from "./sandbox.js";
import { silentLogger } from "./logger.js";
import { displaySafe } from "./sanitize.js";

export {
  StaticScanGate,
  staticScanRuleset,
  staticScanRulesetRef,
  STATIC_SCAN_RULESET_VERSION,
} from "./static-scan.js";
export { PinningGate, canonicalToolsHash, tryCanonicalToolsHash, serverIdentityHash, UNCANONICAL_TOOLS_HASH } from "./pinning.js";
export { OriginGate } from "./origin.js";
export { ThreatFeed, ThreatGate, DEFAULT_FEED_MAX_AGE_MS, FEED_CLOCK_SKEW_MS } from "./threat-feed.js";
export { EgressGuard, isSensitiveTool, classifyTools } from "./sandbox.js";
export { canonicalize, parseJsonStrict, CanonicalizationError, MAX_SAFE_JSON_INTEGER } from "./jcs.js";
export type { CanonicalizationCode } from "./jcs.js";
export type { StaticScanRule, StaticScanRuleset } from "./static-scan.js";
export type { ThreatFeedOptions } from "./threat-feed.js";
export { silentLogger } from "./logger.js";
export { displaySafe, DEFAULT_DISPLAY_MAX } from "./sanitize.js";
export { wildcardMatch } from "./glob.js";
export * from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface WardenInit {
  gates: WardenGate[];
  policy: WardenPolicy;
  /** Where decisions are reported. Defaults to `silentLogger()`. */
  log?: WardenLogger;
}

export interface WardenCreateDeps {
  store: PinStore;
  policy: WardenPolicy;
  /**
   * The known-bad feed. Required, not defaulted: a `ThreatFeed` the host never
   * loaded still carries the built-in floor, but silently constructing one here
   * would hide from the host that no external intel is in play.
   */
  threatFeed: ThreatFeed;
  log?: WardenLogger;
}

/**
 * WARDEN — the MCP security firewall.
 *
 * Every MCP server is vetted through an ordered gate chain before its tools are
 * exposed to the agent: cheap static scanning first, then the known-bad threat
 * feed, then origin (declared by the operator, or offered by a remote catalog),
 * then drift/pinning. Findings accumulate across gates; the verdict is allow/block
 * plus a composite 0..1 safety score and a per-tool partition so a mostly-trusted
 * server can have one poisoned tool quarantined without severing the whole
 * connection.
 *
 * The score is WARDEN's OWN — the product of what each gate contributed, computed
 * from local facts. No reputation oracle is consulted and no socket is opened while
 * vetting. Slot three used to be a reputation gate that asked an oracle for a score
 * it had no data to compute; it is gone, and test/no-phantom-gate.test.ts fails if
 * anything like it comes back.
 */
export class Warden {
  private readonly gates: WardenGate[];
  private readonly policy: WardenPolicy;
  private readonly log: WardenLogger;

  constructor(init: WardenInit) {
    this.gates = [...init.gates];
    this.log = (init.log ?? silentLogger()).child("warden");
    this.policy = this.normalizePolicy(init.policy);
  }

  /**
   * Guard against config typos that silently disable blocking, on a COPY.
   *
   * If `blockAtSeverity` isn't a valid Severity key, `SEVERITY_RANK[bad]` is
   * undefined and every comparison `number >= undefined` is false — zero blocks,
   * zero warnings — so the value is repaired. Repairing it in place used to write
   * into the host's own policy object, which is both a surprise (their config
   * silently changes under them, and any other Warden sharing the object sees it)
   * and a crash: `Object.freeze(policy)` is a reasonable thing for a host to do,
   * and assigning to a frozen property throws a TypeError out of the constructor
   * under ESM strict mode. A firewall that refuses to be constructed because the
   * config was immutable is not a firewall.
   */
  private normalizePolicy(policy: WardenPolicy): WardenPolicy {
    const valid: Severity[] = ["info", "low", "medium", "high", "critical"];
    if (valid.includes(policy.blockAtSeverity)) return { ...policy };
    const fallback: Severity = "high";
    this.log.warn(
      `WARDEN: invalid blockAtSeverity "${displaySafe(policy.blockAtSeverity, 40)}" ` +
      `(expected one of ${valid.join(", ")}) — falling back to "${fallback}" to keep blocking enabled`,
    );
    return { ...policy, blockAtSeverity: fallback };
  }

  /** Build the standard gate chain: static → threat → origin → pinning. */
  static create(deps: WardenCreateDeps): Warden {
    const gates: WardenGate[] = [
      new StaticScanGate(deps.log),
      new ThreatGate(deps.threatFeed),
      new OriginGate(),
      new PinningGate(deps.store),
    ];
    return new Warden({ gates, policy: deps.policy, log: deps.log });
  }

  /**
   * Vet a server and its advertised tools. Runs every gate in order, short-
   * circuiting only on a fatal gate result. A connection is blocked if any gate
   * is fatal or any finding reaches policy.blockAtSeverity.
   */
  async vet(server: McpServerRef, tools: ToolDef[]): Promise<WardenVerdict> {
    const findings: WardenFinding[] = [];
    const scores: number[] = [];
    let allow = true;
    let decidedBy: string | undefined;
    const blockThreshold = SEVERITY_RANK[this.policy.blockAtSeverity];

    for (const gate of this.gates) {
      const result = await this.runGate(gate, server, tools, findings);
      findings.push(...result.findings);
      scores.push(clamp01(result.score));

      // Advisory findings never block, at any threshold — see WardenFinding.advisory.
      const tripped = result.findings.some(
        (f) => !f.advisory && SEVERITY_RANK[f.severity] >= blockThreshold,
      );
      if (result.fatal || tripped) {
        if (allow) {
          allow = false;
          decidedBy = gate.name;
        }
        if (result.fatal) {
          this.log.warn(`gate "${displaySafe(gate.name, 60)}" returned fatal for server ${displaySafe(server.id)}`);
          break; // short-circuit only on an explicit fatal
        }
      }
    }

    // Composite score: product of gate contributions (one bad gate drags it down).
    const score = scores.reduce((acc, s) => acc * s, 1);

    const { allowedTools, blockedTools } = this.partitionTools(tools, findings, blockThreshold);

    if (!allow) {
      this.log.warn(
        `BLOCK ${displaySafe(server.id)} (decidedBy=${displaySafe(decidedBy ?? "-", 60)}, ` +
          `score=${score.toFixed(3)}, findings=${findings.length})`,
      );
    } else {
      this.log.info(`ALLOW ${displaySafe(server.id)} (score=${score.toFixed(3)}, sensitive=${blockedTools.length === 0 ? this.sensitiveCount(tools) : "?"})`);
    }

    return {
      allow,
      score: clamp01(score),
      decidedBy,
      findings,
      allowedTools,
      blockedTools,
      rulesets: { staticScan: staticScanRulesetRef() },
    };
  }

  /**
   * Run one gate, converting a thrown error into a blocking finding.
   *
   * A gate that crashed did not clear the server, so the honest result is a
   * finding at `high` with a zero score — which blocks at the default threshold
   * and, under a report-only policy (`blockAtSeverity: "critical"`), is reported
   * without blocking, exactly like every other high-severity finding.
   *
   * Letting the exception escape instead was worse than it looks: `vet()`
   * rejected, so the host got no verdict at all — not the findings the earlier
   * gates had already produced, not the per-tool partition — and whether that
   * ended in a blocked connection or an unhandled rejection was up to the host.
   * A store with a full disk or a custom gate with a bug should not be able to
   * decide that.
   */
  private async runGate(
    gate: WardenGate,
    server: McpServerRef,
    tools: ToolDef[],
    prior: WardenFinding[],
  ): Promise<WardenGateResult> {
    try {
      const result = await gate.evaluate({ server, tools, prior: [...prior], policy: this.policy });
      // A third-party gate is not obliged to be well-behaved either.
      return {
        findings: Array.isArray(result?.findings) ? result.findings : [],
        score: typeof result?.score === "number" ? result.score : 0,
        ...(result?.fatal ? { fatal: true } : {}),
      };
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      this.log.error(`gate "${displaySafe(gate.name, 60)}" threw: ${displaySafe(detail, 300)}`);
      return {
        findings: [
          {
            gate: gate.name,
            severity: "high",
            code: "GATE_ERROR",
            message:
              `Gate "${displaySafe(gate.name, 60)}" failed to complete (${displaySafe(detail, 300)}), so this ` +
              `server was not checked by it.`,
          },
        ],
        score: 0,
      };
    }
  }

  /**
   * Record the user's approval: pin the current tool defs so future drift is
   * detected. Idempotent — re-approving just refreshes the snapshot.
   */
  async approve(server: McpServerRef, tools: ToolDef[]): Promise<void> {
    const pinning = this.gates.find((g): g is PinningGate => g instanceof PinningGate);
    if (!pinning) {
      this.log.warn("approve() called but no PinningGate in the chain; nothing to pin");
      return;
    }
    await pinning.pin(server, tools);
    this.log.info(`pinned tool defs for ${displaySafe(server.id)} (${tools.length} tools)`);
  }

  /**
   * A tool is blocked if a finding naming it reaches the block threshold.
   * Sensitive tools (per policy) stay allowed but are surfaced as flagged so the
   * agent loop can demand per-call approval at run time.
   */
  private partitionTools(
    tools: ToolDef[],
    findings: WardenFinding[],
    blockThreshold: number,
  ): { allowedTools: string[]; blockedTools: string[] } {
    const blockedByFinding = new Set<string>();
    for (const f of findings) {
      if (f.advisory) continue; // report-only, never costs a tool
      if (f.tool && SEVERITY_RANK[f.severity] >= blockThreshold) blockedByFinding.add(f.tool);
    }

    const allowedTools: string[] = [];
    const blockedTools: string[] = [];
    for (const tool of tools) {
      if (blockedByFinding.has(tool.name)) blockedTools.push(tool.name);
      else allowedTools.push(tool.name);
    }
    return { allowedTools, blockedTools };
  }

  private sensitiveCount(tools: ToolDef[]): number {
    return classifyTools(tools, this.policy).sensitive.length;
  }
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}
