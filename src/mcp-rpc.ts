/**
 * JSON-RPC MCP methods for the stdio server (no transport).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { callMcpTool, MCP_INSTRUCTIONS, MCP_TOOLS, McpToolError, payloadTooLarge } from "./mcp-tools.js";

export const PROTOCOL = "2025-03-26";
const FALLBACK_VERSION = "0.5.0";

export function packageVersion(): string {
  try {
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return typeof pkg.version === "string" ? pkg.version : FALLBACK_VERSION;
  } catch {
    return FALLBACK_VERSION;
  }
}

export interface JsonRpcReq {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
}

export interface JsonRpcRes {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string };
}

export function listedTools() {
  return MCP_TOOLS.map((t) => ({
    name: t.name,
    title: t.title,
    description: t.description,
    inputSchema: t.inputSchema,
    outputSchema: t.outputSchema,
    annotations: t.annotations,
  }));
}

export function consumeLsp(buf: Buffer): { rest: Buffer; bodies: string[] } {
  const bodies: string[] = [];
  while (true) {
    const headerEnd = buf.indexOf("\r\n\r\n");
    if (headerEnd < 0) return { rest: buf, bodies };
    const header = buf.subarray(0, headerEnd).toString("ascii");
    const match = /Content-Length:\s*(\d+)/i.exec(header);
    if (!match) {
      buf = buf.subarray(headerEnd + 4);
      continue;
    }
    const len = Number(match[1]);
    const start = headerEnd + 4;
    if (buf.length < start + len) return { rest: buf, bodies };
    bodies.push(buf.subarray(start, start + len).toString("utf8"));
    buf = buf.subarray(start + len);
  }
}

export async function handleRpc(msg: JsonRpcReq): Promise<JsonRpcRes | null> {
  const method = msg.method ?? "";
  const id = msg.id;
  if (method.startsWith("notifications/")) return null;

  const ok = (result: unknown): JsonRpcRes => ({ jsonrpc: "2.0", id: id ?? null, result });
  const fail = (code: number, message: string): JsonRpcRes => ({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message },
  });

  switch (method) {
    case "initialize":
      return ok({
        protocolVersion: PROTOCOL,
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: "warden",
          title: "WARDEN MCP security firewall",
          version: packageVersion(),
        },
        instructions: MCP_INSTRUCTIONS,
      });
    case "ping":
      return ok({});
    case "tools/list":
      return ok({ tools: listedTools() });
    case "tools/call": {
      if (id === undefined) return null;
      const params = (msg.params ?? {}) as { name?: unknown; arguments?: unknown };
      const name = typeof params.name === "string" ? params.name : "";
      if (!name) return fail(-32602, "tools/call requires params.name");
      const args =
        params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
          ? (params.arguments as Record<string, unknown>)
          : {};
      if (payloadTooLarge(args)) {
        return ok({ content: [{ type: "text", text: "payload exceeds 256 KiB" }], isError: true });
      }
      try {
        const { structured } = await callMcpTool(name, args);
        return ok({
          content: [{ type: "text", text: JSON.stringify(structured, null, 2) }],
          structuredContent: structured,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!(err instanceof McpToolError) && !(err instanceof Error)) {
          return ok({ content: [{ type: "text", text: String(err) }], isError: true });
        }
        return ok({ content: [{ type: "text", text: message }], isError: true });
      }
    }
    case "resources/list":
      return ok({ resources: [] });
    case "resources/templates/list":
      return ok({ resourceTemplates: [] });
    case "prompts/list":
      return ok({ prompts: [] });
    default:
      if (id === undefined) return null;
      return fail(-32601, `method not found: ${method}`);
  }
}
