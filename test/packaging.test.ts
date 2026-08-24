import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import * as warden from "../src/index.js";
import { Warden, ThreatFeed, silentLogger } from "../src/index.js";
import type { WardenPolicy } from "../src/types.js";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Record<string, any>;

/**
 * The whole argument for shipping WARDEN separately from the agent it was born
 * in is that a security-conscious host can adopt the firewall without adopting
 * anything else. That claim is only true while these invariants hold, and none
 * of them are enforced by the compiler.
 */
describe("packaging — the standalone claim", () => {
  it("has no runtime dependencies", () => {
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(pkg.peerDependencies ?? {}).toEqual({});
  });

  it("imports nothing outside the package except the node: builtins it declares", () => {
    const allowed = new Set(["node:crypto"]);
    const offenders: string[] = [];
    for (const file of readdirSync(join(root, "src")).filter((f) => f.endsWith(".ts"))) {
      const src = readFileSync(join(root, "src", file), "utf8");
      for (const m of src.matchAll(/from\s+"([^"]+)"/g)) {
        const spec = m[1]!;
        if (spec.startsWith("./")) continue;
        if (allowed.has(spec)) continue;
        offenders.push(`${file} → ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("publishes only built output and docs", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.main).toBe("./dist/index.js");
    expect(pkg.types).toBe("./dist/index.d.ts");
    expect(pkg.exports["."].types).toBe("./dist/index.d.ts");
    // The canonicalizer is a documented subpath: other implementations verify
    // our RFC 8785 bytes against it without pulling the gate chain.
    expect(pkg.exports["./jcs"].import).toBe("./dist/jcs.js");
  });

  it("exports the full enforcement surface from the entry point", () => {
    for (const name of [
      "Warden",
      "StaticScanGate",
      "ThreatFeed",
      "ThreatGate",
      "OriginGate",
      "PinningGate",
      "EgressGuard",
      "isSensitiveTool",
      "classifyTools",
      "canonicalize",
      "parseJsonStrict",
      "canonicalToolsHash",
      "tryCanonicalToolsHash",
      "staticScanRuleset",
      "staticScanRulesetRef",
      "STATIC_SCAN_RULESET_VERSION",
      "silentLogger",
    ]) {
      expect(warden, `missing export: ${name}`).toHaveProperty(name);
    }
  });

  it("runs without a host logger", async () => {
    const policy: WardenPolicy = {
      blockAtSeverity: "high",
      sensitiveToolPatterns: [],
      allowUnknownServers: true,
      pinToolDefs: true,
    };
    const feed = new ThreatFeed();
    await feed.load();
    const pins = new Map<string, any>();
    // No `log` — a host with no logger of its own must still get enforcement.
    const w = Warden.create({
      store: { getPin: async (id) => pins.get(id), putPin: async (p) => void pins.set(p.serverId, p) },
      policy,
      threatFeed: feed,
    });
    const verdict = await w.vet(
      { id: "svc@0", name: "svc", transport: "stdio", command: "node" },
      [{ name: "add", description: "Add two integers.", inputSchema: { type: "object" } }],
    );
    expect(verdict.allow).toBe(true);
    expect(silentLogger().child("x").child("y")).toBeDefined();
  });
});
