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
import { consumeLsp, handleRpc, type JsonRpcReq } from "./mcp-rpc.js";

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
  let parsed: JsonRpcReq;
  try {
    parsed = JSON.parse(body) as JsonRpcReq;
  } catch {
    writeMessage({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    return;
  }
  const res = await handleRpc(parsed);
  if (res) writeMessage(res);
}

function skipWs(buf: Buffer): Buffer {
  let i = 0;
  while (i < buf.length) {
    const b = buf[i];
    if (b !== 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) break;
    i++;
  }
  return buf.subarray(i);
}

async function main(): Promise<void> {
  let buf: Buffer = Buffer.from([]);
  let ndjson = "";

  for await (const chunk of stdin) {
    const piece = Buffer.from(chunk as Uint8Array);
    if (mode === "unknown") {
      buf = Buffer.concat([buf, piece]);
      const trimmed = skipWs(buf);
      if (trimmed.length === 0) continue;
      if (trimmed[0] === 0x7b) {
        mode = "ndjson";
        ndjson = buf.toString("utf8");
      } else {
        mode = "lsp";
        const { rest, bodies } = consumeLsp(buf);
        buf = Buffer.from(rest);
        for (const body of bodies) await dispatchBody(body);
      }
    } else if (mode === "lsp") {
      buf = Buffer.concat([buf, piece]);
      const { rest, bodies } = consumeLsp(buf);
      buf = Buffer.from(rest);
      for (const body of bodies) await dispatchBody(body);
    } else {
      ndjson += piece.toString("utf8");
    }

    if (mode === "ndjson") {
      const lines = ndjson.split("\n");
      ndjson = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) await dispatchBody(trimmed);
      }
    }
  }

  if (mode === "ndjson" && ndjson.trim()) await dispatchBody(ndjson.trim());
}

main().catch((err) => {
  stderr.write(`warden-mcp: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
