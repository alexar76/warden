#!/usr/bin/env node
/**
 * WARDEN stdio MCP server — Glama / Claude Desktop / Cursor.
 *
 * stdout is the MCP wire. Logs go to stderr. No environment variables required.
 *
 * Wire format (MCP stdio spec): newline-delimited JSON. Glama's mcp-proxy and the
 * official TypeScript SDK both speak NDJSON; LSP-style Content-Length framing on
 * *stdout* is treated as non-JSON noise and the health check times out.
 *
 * Input still accepts Content-Length (legacy probes) and mirrors that framing on
 * the reply so old clients keep working. Fresh `{…}\n` peers get `{…}\n` back.
 */

import { stderr, stdin, stdout } from "node:process";
import { consumeLsp, handleRpc, MAX_FRAME_BYTES } from "./mcp-rpc.js";

type FrameMode = "unknown" | "lsp" | "ndjson";

let mode: FrameMode = "unknown";

function writeMessage(msg: object): void {
  const body = JSON.stringify(msg);
  if (mode === "lsp") {
    const buf = Buffer.from(body, "utf8");
    stdout.write(`Content-Length: ${buf.length}\r\n\r\n`);
    stdout.write(buf);
    return;
  }
  // Default + Glama / TS SDK: NDJSON
  stdout.write(`${body}\n`);
}

async function dispatchBody(body: string): Promise<void> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    writeMessage({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    return;
  }
  const res = await handleRpc(parsed);
  if (res) writeMessage(res);
}

async function main(): Promise<void> {
  let buf: Buffer = Buffer.alloc(0);
  for await (const chunk of stdin) {
    buf = Buffer.concat([buf, Buffer.from(chunk as Uint8Array)]);
    if (mode === "unknown") {
      const prefix = buf.toString("ascii").trimStart();
      if (!prefix || "content-length:".startsWith(prefix.toLowerCase())) {
        if (buf.length > 8192) throw new Error("MCP header too large");
        continue;
      }
      mode = prefix.toLowerCase().startsWith("content-length:") ? "lsp" : "ndjson";
    }
    if (mode === "lsp") {
      const parsed = consumeLsp(buf);
      buf = Buffer.from(parsed.rest);
      for (const body of parsed.bodies) await dispatchBody(body);
    } else {
      let newline: number;
      while ((newline = buf.indexOf(10)) >= 0) {
        if (newline > MAX_FRAME_BYTES) throw new Error("MCP frame too large");
        const body = buf.subarray(0, newline).toString("utf8").trim();
        buf = Buffer.from(buf.subarray(newline + 1));
        if (body) await dispatchBody(body);
      }
      if (buf.length > MAX_FRAME_BYTES) throw new Error("MCP frame too large");
    }
  }
  if (mode === "ndjson" && buf.length) await dispatchBody(buf.toString("utf8"));
  if (mode === "lsp" && buf.length) throw new Error("Incomplete MCP frame");
}

main().catch((err) => {
  stderr.write(`warden-mcp: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
