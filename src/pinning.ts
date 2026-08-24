import { createHash } from "node:crypto";
import { canonicalize, CanonicalizationError } from "./jcs.js";
import type {
  McpServerRef,
  PinStore,
  PinnedServer,
  ToolDef,
  WardenFinding,
  WardenGate,
  WardenGateInput,
  WardenGateResult,
} from "./types.js";

/**
 * Tool-definition pinning + drift detection ("rug-pull" defence).
 *
 * A server can advertise benign tools at approval time and silently swap in a
 * poisoned definition later. We hash the canonical tool-def set on approval and
 * compare on every subsequent connection: a changed hash means the contract the
 * user approved no longer holds, so (under policy.pinToolDefs) we block and force
 * re-approval. First-contact servers are flagged UNPINNED so the chain knows the
 * pin is established only when the user approves.
 */
export class PinningGate implements WardenGate {
  readonly name = "pinning";

  constructor(private readonly store: PinStore) {}

  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const pin = await this.store.getPin(input.server.id);

    let hash: string;
    try {
      hash = canonicalToolsHash(input.tools);
    } catch (err) {
      if (!(err instanceof CanonicalizationError)) throw err;
      return this.uncanonical(input, pin, err);
    }

    if (!pin) {
      const finding: WardenFinding = {
        gate: this.name,
        severity: "info",
        code: "TOOL_DEF_UNPINNED",
        message: `Server "${input.server.id}" has no pinned tool-def snapshot yet; it will be pinned on approval.`,
        // Report-only by necessity, not by preference: a server at first contact
        // cannot be anything but unpinned, and Warden.approve() runs only after
        // vet() passes. Letting this finding block — which it did at
        // blockAtSeverity "info" — makes first contact impossible for every
        // server, so no pin can ever be created.
        advisory: true,
      };
      // Neutral-to-good: unpinned isn't unsafe, it's just unestablished.
      return { findings: [finding], score: 0.9 };
    }

    if (pin.toolsHash !== hash) {
      const finding: WardenFinding = {
        gate: this.name,
        severity: "high",
        code: "TOOL_DEF_DRIFT",
        message:
          `Tool definitions for "${input.server.id}" changed since approval ` +
          `(pinned ${short(pin.toolsHash)} → now ${short(hash)}). Possible rug-pull; re-approval required.`,
      };
      return {
        findings: [finding],
        score: 0,
        fatal: input.policy.pinToolDefs === true,
      };
    }

    return { findings: [], score: 1 };
  }

  /**
   * The tool-def set has no canonical form (see {@link canonicalToolsHash}), so no
   * hash can be produced for it. What that means depends on whether a pin exists:
   *
   * - **No pin yet** — nothing is being contradicted; the pin simply cannot be
   *   established, which is a `medium` warning and not evidence of an attack.
   * - **Pin exists** — the snapshot the user approved can no longer be re-verified,
   *   which is indistinguishable from drift and is treated as drift. Otherwise a
   *   server could disarm the rug-pull defence at will by adding one fractional
   *   number to a schema.
   */
  private uncanonical(input: WardenGateInput, pin: PinnedServer | undefined, err: CanonicalizationError): WardenGateResult {
    if (!pin) {
      return {
        findings: [
          {
            gate: this.name,
            severity: "medium",
            code: "TOOL_DEF_UNCANONICAL",
            message:
              `Tool definitions for "${input.server.id}" have no canonical form (${err.message}), ` +
              `so no reproducible pin can be taken — drift detection is unavailable for this server.`,
          },
        ],
        score: 0.5,
      };
    }
    return {
      findings: [
        {
          gate: this.name,
          severity: "high",
          code: "TOOL_DEF_UNCANONICAL",
          message:
            `Tool definitions for "${input.server.id}" have no canonical form (${err.message}), so the pinned ` +
            `snapshot ${short(pin.toolsHash)} cannot be re-verified. Treated as drift; re-approval required.`,
        },
      ],
      score: 0,
      fatal: input.policy.pinToolDefs === true,
    };
  }

  /**
   * Persist the current tool-def set as the trusted snapshot for this server.
   * Called by Warden.approve() once a user has accepted the connection.
   *
   * Throws {@link CanonicalizationError} when the set has no canonical form; the
   * caller (`McpHost.connect`) already reports a pin failure as a degraded
   * rug-pull defence rather than failing the connection.
   */
  async pin(server: McpServerRef, tools: ToolDef[]): Promise<void> {
    const pinned: PinnedServer = {
      serverId: server.id,
      toolsHash: canonicalToolsHash(tools),
      approvedAt: new Date().toISOString(),
      toolNames: [...tools.map((t) => t.name)].sort(),
    };
    await this.store.putPin(pinned);
  }
}

/**
 * Marker used where a tool-def hash is *recorded* rather than compared, and the set
 * turned out to have no canonical form. It can never collide with a sha256 hex
 * digest, so anything that later compares it simply reports a mismatch.
 */
export const UNCANONICAL_TOOLS_HASH = "uncanonical:non-canonical-tool-defs";

/**
 * sha256 over the canonical tool-def set: tools sorted by name, each reduced to
 * the security-relevant fields (name, description, schema), serialised with
 * {@link canonicalize} — RFC 8785 (JCS) as profiled in `awr/SPEC.md` §4.
 *
 * This digest is quoted in receipts and re-checked elsewhere (`argus verify`, the
 * sealed mandate), so it has to be reproducible by an implementation that is not
 * this one. Two consequences:
 *
 * - **Ordering is by UTF-16 code unit, never `localeCompare`.** `localeCompare`
 *   depends on the host locale and ICU version — `["a", "B"]` sorts one way under
 *   `en-US` and another under the C locale — so a digest built on it is not even
 *   stable across two machines running this same code, let alone across languages.
 *   JavaScript's `<`/`>` on strings compare UTF-16 code units, which is exactly
 *   RFC 8785 §3.2.3's rule.
 * - **Non-integer numbers are refused** (`AWR-CANON-001`, SPEC §4.3) rather than
 *   serialised. Whether `1` is an integer or a double is a language accident that
 *   silently changes the bytes, so a schema carrying e.g. `"multipleOf": 0.01` has
 *   no canonical form here and this function throws
 *   {@link CanonicalizationError}. Callers must handle that — refusing to emit a
 *   digest is honest; emitting one nobody else can reproduce is not.
 */
export function canonicalToolsHash(tools: ToolDef[]): string {
  const canonical = [...tools]
    .sort((a, b) => compareCodeUnits(a.name, b.name))
    .map((t) => ({
      name: t.name,
      description: t.description ?? "",
      inputSchema: t.inputSchema ?? {},
    }));
  return createHash("sha256").update(canonicalize(canonical), "utf8").digest("hex");
}

/**
 * Like {@link canonicalToolsHash} but total: returns `undefined` instead of
 * throwing, for call sites that record a hash rather than enforce one.
 */
export function tryCanonicalToolsHash(tools: ToolDef[]): string | undefined {
  try {
    return canonicalToolsHash(tools);
  } catch (err) {
    if (err instanceof CanonicalizationError) return undefined;
    throw err;
  }
}

/** RFC 8785 §3.2.3 ordering: arrays of UTF-16 code units as unsigned integers. */
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function short(hash: string): string {
  return hash.slice(0, 12);
}
