import { describe, it, expect, vi, afterEach } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { ThreatFeed, Warden } from "../src/index.js";
import { silentLogger } from "../src/logger.js";
import type { McpServerRef, PinStore, PinnedServer, ToolDef, WardenPolicy } from "../src/types.js";

/**
 * Regression guard for a removed reputation gate.
 *
 * That gate called a trust oracle without ever supplying trust edges, so the
 * oracle returned its neutral default *before* making a request — and the gate
 * then told the user the oracle was unreachable. Nothing had been tried. These
 * tests fail if any gate reports unreachability without a request, and if a gate
 * that measured nothing taxes the composite score.
 *
 * The oracle-side half of this guard lives in the host that owns the oracle
 * client (ARGUS, `test/lumen-no-phantom-oracle.test.ts`); this half constrains
 * the gate chain, which performs no network I/O at all.
 */

const policy: WardenPolicy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: [],
  allowUnknownServers: true,
  pinToolDefs: true,
};

const clean: ToolDef = {
  name: "add",
  description: "Add two integers and return the sum.",
  inputSchema: { type: "object", properties: {} },
};
const declared: McpServerRef = { id: "svc@0", name: "svc", transport: "stdio", command: "node" };
const silent = silentLogger();

function makeStore(): PinStore {
  const pins = new Map<string, PinnedServer>();
  return {
    getPin: async (id) => pins.get(id),
    putPin: async (p) => void pins.set(p.serverId, p),
  };
}

async function builtinFeed(): Promise<ThreatFeed> {
  const feed = new ThreatFeed();
  await feed.load(); // no URL → built-ins only, no network
  return feed;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("no gate may report an oracle as unreachable without asking it", () => {
  it("vetting a server opens no socket and claims no unreachability", async () => {
    const feed = await builtinFeed();
    const spy = vi.spyOn(globalThis, "fetch");
    const w = Warden.create({ store: makeStore(), policy, threatFeed: feed, log: silent });

    const verdict = await w.vet(declared, [clean]);

    expect(spy).not.toHaveBeenCalled();
    const text = verdict.findings.map((f) => `${f.code} ${f.message}`).join("\n");
    expect(text).not.toMatch(/unreachab|unavailab/i);
    expect(verdict.findings.some((f) => f.code.startsWith("REPUTATION_"))).toBe(false);
  });

  it("does not tax the composite score with a gate that measured nothing", async () => {
    const feed = await builtinFeed();
    const w = Warden.create({ store: makeStore(), policy, threatFeed: feed, log: silent });

    const verdict = await w.vet(declared, [clean]);

    // static 1 × threat 1 × origin 1 × pinning 0.9 (first sight) = 0.9.
    // The removed reputation gate contributed a constant 0.6 on every single
    // connection, which capped this at 0.54 for a server with nothing wrong.
    expect(verdict.allow).toBe(true);
    expect(verdict.score).toBeCloseTo(0.9, 10);
  });

  it("source guard: no gate claims a remote service could not be reached", () => {
    const dir = fileURLToPath(new URL("../src/", import.meta.url));
    const offenders: string[] = [];
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".ts"))) {
      const code = readFileSync(join(dir, file), "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "") // block comments
        .replace(/(^|[^:])\/\/.*$/gm, "$1"); // line comments
      // "unreachable" in any form, or an oracle described as unavailable. NOT a
      // plain "unavailable": a gate saying a LOCAL capability is unavailable is
      // fine and true — the pinning gate reports that drift detection is
      // unavailable when a tool-def set has no canonical form.
      if (/unreachab/i.test(code) || /oracle[\s\S]{0,40}unavailab|unavailab[\s\S]{0,40}oracle/i.test(code)) {
        offenders.push(file);
      }
    }
    // A gate may only describe a service as unreachable after attempting to reach
    // it. No gate in the chain performs a request, so no gate may say it.
    expect(offenders).toEqual([]);
  });
});
