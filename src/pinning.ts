import { createHash } from "node:crypto";
import { canonicalize, canonicalizeRfc8785, CanonicalizationError } from "./jcs.js";
import { displaySafe } from "./sanitize.js";
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

  /** Identity-only check: safe before starting the untrusted process. */
  async evaluateLaunch(input: WardenGateInput): Promise<WardenGateResult> {
    const pin = await this.store.getPin(input.server.id);
    const drift = this.identityDrift(input, pin);
    return { findings: drift ? [drift] : [], score: drift ? 0 : 1,
      fatal: !!drift && (input.policy.pinToolDefs || input.policy.requireApproval === true) };
  }

  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const pin = await this.store.getPin(input.server.id);

    let hash: string;
    try {
      hash = pinToolsHash(input.tools);
    } catch (err) {
      if (!(err instanceof CanonicalizationError)) throw err;
      return this.uncanonical(input, pin, err);
    }

    const identityDrift = this.identityDrift(input, pin);

    if (input.policy.requireApproval && (!pin || pin.approvalMode !== "operator" ||
        pin.toolsHashVersion !== 2 || !pin.identityHash)) {
      return { score: 0, fatal: true, findings: [{ gate: this.name, severity: "high",
        code: "TOOL_DEF_APPROVAL_REQUIRED",
        message: "Tool definitions have no explicit operator approval covering every field and the server identity." }] };
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

    const findings: WardenFinding[] = [];
    if (pin.toolsHashVersion !== 2 && input.tools.some(t => Object.keys(t).some(k => !["name", "description", "inputSchema"].includes(k) && t[k] !== undefined))) {
      findings.push({ gate: this.name, severity: "high", code: "PIN_FORMAT_UPGRADE_REQUIRED",
        message: "This legacy approval did not cover extended tool fields; review and approve a v2 snapshot." });
    }
    if (pin.toolsHash !== hash) {
      findings.push({
        gate: this.name,
        severity: "high",
        code: "TOOL_DEF_DRIFT",
        message:
          `Tool definitions for "${displaySafe(input.server.id)}" changed since approval ` +
          `(pinned ${short(pin.toolsHash)} → now ${short(hash)}). Possible rug-pull; re-approval required.`,
      });
    }
    // Both are reported when both changed: "the tools moved AND so did the
    // program serving them" is a different picture from either one alone, and
    // returning on the first one found used to hide the second.
    if (identityDrift) findings.push(identityDrift);

    if (findings.length > 0) {
      return { findings, score: 0, fatal: input.policy.pinToolDefs === true || input.policy.requireApproval === true };
    }

    return { findings: [], score: 1 };
  }

  /**
   * Has the program behind this server changed since approval?
   *
   * Silent when the pin predates {@link PinnedServer.identityHash}: an absent
   * value is "not recorded", never "changed". The next `approve()` records it.
   */
  private identityDrift(input: WardenGateInput, pin: PinnedServer | undefined): WardenFinding | undefined {
    if (!pin?.identityHash) return undefined;
    const now = serverIdentityHash(input.server);
    if (now === pin.identityHash) return undefined;
    return {
      gate: this.name,
      severity: "high",
      code: "SERVER_IDENTITY_DRIFT",
      message:
        `The launch identity of "${displaySafe(input.server.id)}" changed since approval ` +
        `(pinned ${short(pin.identityHash)} → now ${short(now)}): transport, command, args, url or name ` +
        `is not what was approved. The advertised tools may be identical while the program serving them is not.`,
    };
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
              `Tool definitions for "${displaySafe(input.server.id)}" have no canonical form (${err.message}), ` +
              `so no reproducible pin can be taken — drift detection is unavailable for this server.`,
          },
        ],
        score: 0.5,
        fatal: input.policy.requireApproval === true,
      };
    }
    return {
      findings: [
        {
          gate: this.name,
          severity: "high",
          code: "TOOL_DEF_UNCANONICAL",
          message:
            `Tool definitions for "${displaySafe(input.server.id)}" have no canonical form (${err.message}), so the pinned ` +
            `snapshot ${short(pin.toolsHash)} cannot be re-verified. Treated as drift; re-approval required.`,
        },
      ],
      score: 0,
      fatal: input.policy.pinToolDefs === true || input.policy.requireApproval === true,
    };
  }

  /**
   * Persist the current tool-def set as the trusted snapshot for this server.
   * Called by Warden.approve() once a user has accepted the connection.
   *
   * Throws {@link CanonicalizationError} only when the set has no RFC 8785 form at
   * all (a lone surrogate, nesting past the bound); fractional numbers are pinned
   * with {@link pinToolsHash}. The host must fail closed when pinning is required.
   */
  async pin(server: McpServerRef, tools: ToolDef[], approvalMode: "operator" | "automatic" = "operator"): Promise<void> {
    const pinned: PinnedServer = {
      serverId: server.id,
      toolsHash: pinToolsHash(tools),
      toolsHashVersion: 2,
      approvedAt: new Date().toISOString(),
      approvalMode,
      toolNames: [...tools.map((t) => t.name)].sort(compareCodeUnits),
      identityHash: serverIdentityHash(server),
      tools: structuredClone(tools),
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
 * all advertised fields (including title, outputSchema, annotations and extensions), serialised with
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
  return createHash("sha256").update(canonicalize(canonicalToolSet(tools)), "utf8").digest("hex");
}

/** Prefix of a {@link pinToolsHash} taken over plain RFC 8785 because the set has fractional numbers. */
export const RFC8785_PIN_PREFIX = "rfc8785:";

/**
 * The hash a host pins and re-checks ITSELF: {@link canonicalToolsHash} wherever
 * that exists, so every existing pin still matches; otherwise `rfc8785:` + sha256
 * over plain RFC 8785, which serialises a fractional number (`"default": 0.7`) in
 * its ECMAScript form instead of refusing it.
 *
 * About one public server in fourteen has a fractional number somewhere in its
 * schemas. Refusing to pin those made them impossible to wrap at all. Drift is
 * still caught: adding or removing a fractional number moves the set between the
 * two forms, and the two never compare equal. The `rfc8785:` form is local
 * state, never a receipt digest — receipts keep {@link tryCanonicalToolsHash}.
 */
export function pinToolsHash(tools: ToolDef[]): string {
  try {
    return canonicalToolsHash(tools);
  } catch (err) {
    if (!(err instanceof CanonicalizationError) || (err.code !== "AWR-CANON-001" && err.code !== "AWR-CANON-002")) throw err;
    return RFC8785_PIN_PREFIX + createHash("sha256").update(canonicalizeRfc8785(canonicalToolSet(tools)), "utf8").digest("hex");
  }
}

function canonicalToolSet(tools: ToolDef[]): Array<Record<string, unknown>> {
  return [...tools]
    .sort((a, b) => compareCodeUnits(a.name, b.name))
    .map((t) => ({
      ...Object.fromEntries(Object.entries(t).filter(([, value]) => value !== undefined)),
      name: t.name,
      description: t.description ?? "",
      inputSchema: t.inputSchema ?? {},
    }));
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

/**
 * sha256 over the server's launch identity: transport, command, args, url, name.
 *
 * Deliberately NOT the whole `McpServerRef`: `catalog` is provenance rather than
 * identity (the origin gate is what has an opinion about it), and `env` holds
 * secrets that must not be hashed into a value stored on disk next to the pin.
 *
 * Missing fields serialize as empty rather than being omitted, so a server that
 * gains a `url` reads as a change instead of hashing the same as before.
 */
export function serverIdentityHash(server: McpServerRef): string {
  const identity = {
    transport: server.transport,
    command: server.command ?? "",
    args: server.args ?? [],
    url: server.url ?? "",
    name: server.name,
  };
  return createHash("sha256").update(canonicalize(identity), "utf8").digest("hex");
}

/** RFC 8785 §3.2.3 ordering: arrays of UTF-16 code units as unsigned integers. */
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function short(hash: string): string {
  return hash.slice(0, 12);
}
