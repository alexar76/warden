import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { callMcpTool, MCP_TOOLS } from "../src/mcp-tools.js";
import { consumeLsp, handleRpc, listedTools, packageVersion, PROTOCOL } from "../src/mcp-rpc.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const CLEAN_TOOLS = [
  { name: "add", description: "Add two integers.", inputSchema: { type: "object" } },
];

describe("MCP tool definitions (TDQS surface)", () => {
  it("ships six coherent tools with titles, annotations, and output schemas", () => {
    const names = MCP_TOOLS.map((t) => t.name);
    expect(names).toEqual([
      "vet_mcp_server",
      "static_scan_tools",
      "classify_sensitive_tools",
      "check_egress_url",
      "canonicalize_json",
      "list_scan_rules",
    ]);
    for (const t of MCP_TOOLS) {
      expect(t.title.length, t.name).toBeGreaterThan(t.name.length);
      expect(t.title).not.toBe(t.name);
      expect(t.description.length, t.name).toBeGreaterThan(80);
      expect(t.description, t.name).toMatch(/When to use/i);
      expect(t.description, t.name).toMatch(/When NOT to use/i);
      expect(t.annotations.readOnlyHint).toBe(true);
      expect(t.annotations.destructiveHint).toBe(false);
      expect(t.annotations.idempotentHint).toBe(true);
      expect(t.annotations.openWorldHint).toBe(false);
      expect(t.inputSchema).toMatchObject({ type: "object" });
      expect(t.outputSchema).toMatchObject({ type: "object" });
      const props = (t.inputSchema.properties ?? {}) as Record<string, { description?: string }>;
      for (const [key, schema] of Object.entries(props)) {
        expect(schema.description, `${t.name}.${key}`).toBeTruthy();
      }
    }
  });

  it("names siblings in when-not so tools are not interchangeable", () => {
    const vet = MCP_TOOLS.find((t) => t.name === "vet_mcp_server")!;
    expect(vet.description).toContain("static_scan_tools");
    expect(vet.description).toContain("classify_sensitive_tools");
    const scan = MCP_TOOLS.find((t) => t.name === "static_scan_tools")!;
    expect(scan.description).toContain("vet_mcp_server");
    expect(scan.description).toContain("list_scan_rules");
  });
});

describe("MCP tool handlers", () => {
  it("vets a clean server as allow", async () => {
    const { structured } = await callMcpTool("vet_mcp_server", {
      server: { id: "demo@0", name: "demo", transport: "stdio", command: "node" },
      tools: CLEAN_TOOLS,
    });
    expect(structured.allow).toBe(true);
    expect(structured.score).toBeGreaterThan(0.5);
    expect(structured.allowedTools).toContain("add");
    expect(structured.rulesets).toHaveProperty("staticScan");
  });

  it("static-scans without running origin or pinning", async () => {
    const { structured } = await callMcpTool("static_scan_tools", { tools: CLEAN_TOOLS });
    expect(structured.score).toBe(1);
    expect(structured.findings).toEqual([]);
    expect(structured.ruleset).toHaveProperty("digest");
  });

  it("classifies glob-sensitive names", async () => {
    const { structured } = await callMcpTool("classify_sensitive_tools", {
      tools: [
        { name: "add", description: "Add.", inputSchema: { type: "object" } },
        { name: "delete_repo", description: "Delete a repository.", inputSchema: { type: "object" } },
      ],
      patterns: ["*delete*"],
    });
    expect(structured.sensitive).toEqual(["delete_repo"]);
    expect(structured.safe).toEqual(["add"]);
  });

  it("checks egress fail-closed on an empty allowlist", async () => {
    const { structured } = await callMcpTool("check_egress_url", {
      url: "https://evil.example/x",
      allowlist: [],
    });
    expect(structured.allowed).toBe(false);
    expect(String(structured.reason)).toMatch(/empty allowlist/i);
  });

  it("allows an exact host on the egress list", async () => {
    const { structured } = await callMcpTool("check_egress_url", {
      url: "https://api.github.com/repos",
      allowlist: ["api.github.com"],
    });
    expect(structured).toEqual({ allowed: true, host: "api.github.com" });
  });

  it("canonicalizes RFC 8785 key order", async () => {
    const { structured } = await callMcpTool("canonicalize_json", { value: { b: 1, a: 2 } });
    expect(structured.canonical).toBe('{"a":2,"b":1}');
  });

  it("lists the published ruleset without regex bodies by default", async () => {
    const { structured } = await callMcpTool("list_scan_rules", {});
    expect(structured.version).toBeTruthy();
    expect(Array.isArray(structured.rules)).toBe(true);
    expect((structured.rules as object[]).length).toBeGreaterThan(10);
    expect((structured.rules as { source?: string }[])[0]?.source).toBeUndefined();
  });

  it("rejects an empty tools array", async () => {
    await expect(callMcpTool("static_scan_tools", { tools: [] })).rejects.toThrow(/non-empty/);
  });
});

describe("MCP JSON-RPC (Glama health: initialize + tools/list)", () => {
  it("initialize then tools/list returns every tool with schemas", async () => {
    const init = await handleRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: "probe", version: "0" } },
    });
    expect(init?.result).toMatchObject({
      protocolVersion: PROTOCOL,
      serverInfo: { name: "warden", version: packageVersion() },
    });
    expect((init?.result as { instructions?: string }).instructions).toContain("vet_mcp_server");

    const listed = await handleRpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    const tools = (listed?.result as { tools: { name: string; inputSchema: unknown; outputSchema: unknown }[] }).tools;
    expect(tools.map((t) => t.name)).toEqual(listedTools().map((t) => t.name));
    for (const t of tools) {
      expect(t.inputSchema).toBeTruthy();
      expect(t.outputSchema).toBeTruthy();
    }
  });

  it("ignores notifications/initialized", async () => {
    expect(await handleRpc({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
  });

  it("tools/call vet_mcp_server returns structuredContent", async () => {
    const res = await handleRpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "canonicalize_json",
        arguments: { value: { z: 0, a: 1 } },
      },
    });
    const result = res?.result as { structuredContent: { canonical: string }; isError?: boolean };
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent.canonical).toBe('{"a":1,"z":0}');
  });

  it("unknown method is JSON-RPC -32601", async () => {
    const res = await handleRpc({ jsonrpc: "2.0", id: 9, method: "nope/nope" });
    expect(res?.error?.code).toBe(-32601);
  });
});

describe("Content-Length framing", () => {
  it("splits one LSP-framed message", () => {
    const body = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
    const frame = Buffer.from(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    const { rest, bodies } = consumeLsp(frame);
    expect(bodies).toEqual([body]);
    expect(rest.length).toBe(0);
  });
});

describe("stdio process health (what Glama runs)", () => {
  it("built mcp-server.js answers initialize over Content-Length", async () => {
    const { existsSync } = await import("node:fs");
    const bin = join(root, "dist", "mcp-server.js");
    if (!existsSync(bin)) {
      console.warn("skipping stdio spawn — dist/mcp-server.js missing (run npm run build)");
      return;
    }
    const child = spawn(process.execPath, [bin], { stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    const got = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`no initialize reply: ${Buffer.concat(chunks).toString()}`));
      }, 4000);
      child.stdout.on("data", (c: Buffer) => {
        chunks.push(c);
        const { bodies } = consumeLsp(Buffer.concat(chunks));
        if (bodies.length >= 1) {
          clearTimeout(timer);
          resolve(bodies[0]!);
        }
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
      const body = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: "probe", version: "0" } },
      });
      child.stdin.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    });
    child.kill("SIGTERM");
    const msg = JSON.parse(got) as { result?: { serverInfo?: { name?: string } } };
    expect(msg.result?.serverInfo?.name).toBe("warden");
  }, 10_000);
});
