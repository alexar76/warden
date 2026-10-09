import type { ToolDef } from './types.js';

/** Byte budget for one server's whole tool list, across pages. */
export const LIST_BYTES = 1_048_576;
/** Most tools one server may advertise before the list is refused as abusive. */
export const MAX_TOOLS = 256;
/** Most `tools/list` pages followed before a server is refused as looping. */
export const MAX_PAGES = 32;

export interface ToolPage { result: unknown; bytes: number }

export interface ListLimits { maxTools: number; maxBytes: number }
/** The live proxy's bounds: a list past them is refused before any of it reaches a client. */
export const WRAP_LIST_LIMITS: ListLimits = { maxTools: MAX_TOOLS, maxBytes: LIST_BYTES };
/**
 * `scan` reads once and exposes nothing, so it can afford the real servers that exceed the
 * proxy's bounds: the 2026-10-01 corpus has servers with 302, 438 and 453 tools (1.2 MB).
 */
export const SCAN_LIST_LIMITS: ListLimits = { maxTools: 4096, maxBytes: 16 * 1024 * 1024 };

/**
 * Collect every page of a server's `tools/list`, validating each definition the
 * way the wrap proxy always has: a tool is an object with a non-empty, unique
 * string name; `description` and `title` are strings when present; `inputSchema`,
 * `outputSchema` and `annotations` are objects when present. Missing description
 * and schema are filled in, so every gate sees the same shape.
 *
 * Shared by `wrap` (the live proxy) and `scan` (the one-shot client) so that a
 * definition the proxy would refuse is refused by the scanner too, and vice versa.
 */
export async function listAllTools(requestPage: (cursor?: string) => Promise<ToolPage>, limits: ListLimits = WRAP_LIST_LIMITS): Promise<ToolDef[]> {
  const tools: ToolDef[] = [], names = new Set<string>(), cursors = new Set<string>();
  let cursor: string | undefined, bytes = 0;
  for (let page = 0; page < MAX_PAGES; page++) {
    const response = await requestPage(cursor), listed = response.result as { tools?: unknown; nextCursor?: unknown } | null;
    bytes += response.bytes;
    if (bytes > limits.maxBytes) throw new Error(`MCP tools/list exceeds ${limits.maxBytes === LIST_BYTES ? '1 MiB' : `${limits.maxBytes} bytes`}`);
    if (!listed || typeof listed !== 'object' || !Array.isArray(listed.tools)) throw new Error('Invalid MCP tools/list');
    if (tools.length + listed.tools.length > limits.maxTools) throw new Error(`MCP tools/list exceeds ${limits.maxTools} tools`);
    for (const raw of listed.tools) {
      const t = raw as Record<string, unknown> | null;
      if (!t || typeof t !== 'object' || Array.isArray(t) || typeof t.name !== 'string' || !t.name || names.has(t.name) ||
          (t.description !== undefined && typeof t.description !== 'string') || (t.title !== undefined && typeof t.title !== 'string')) throw new Error('Invalid or duplicate MCP tool definition');
      for (const key of ['inputSchema', 'outputSchema', 'annotations']) {
        if (t[key] !== undefined && (!t[key] || typeof t[key] !== 'object' || Array.isArray(t[key]))) throw new Error(`Invalid MCP ${key}`);
      }
      names.add(t.name);
      tools.push({ ...t, name: t.name, description: (t.description as string | undefined) ?? '', inputSchema: (t.inputSchema as Record<string, unknown> | undefined) ?? { type: 'object', properties: {} } });
    }
    if (listed.nextCursor === undefined) return tools;
    cursor = listed.nextCursor as string;
    if (typeof cursor !== 'string' || !cursor || cursors.has(cursor)) throw new Error('Invalid or repeated MCP next-page token');
    cursors.add(cursor);
  }
  throw new Error(`MCP tools/list exceeds ${MAX_PAGES} pages`);
}
