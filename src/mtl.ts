import { createHash } from 'node:crypto';
import { canonicalizeRfc8785, CanonicalizationError } from './jcs.js';
import type { ToolDef } from './types.js';

/**
 * MTL/1 tool-set digest — the digest HISTOR's public log keys tool sets by
 * (awr/adoption/mcp-trust-label/PROFILE.md §5, histor/subject.py).
 *
 * It is NOT {@link pinToolsHash}: a pin covers every advertised field and is
 * local state; this digest covers exactly `name`, `description`, `inputSchema`
 * and (only when present) `outputSchema`, sorted by UTF-16 code units of the
 * name, serialised as RFC 8785 with every number a double (MTL/1.1 §5.4: the
 * AWR/2 bytes wherever the set has integers only), and is what two strangers can
 * compare without exchanging the definitions themselves. That property is why
 * `scan --histor` sends only this value: the log answers "same / different /
 * previously observed" without ever receiving a tool description.
 *
 * Throws {@link MtlError}: `MTL-SUBJ-001` (not an object / no name) and
 * `MTL-NUM-001` (a number with no double, which only a non-JSON value can be).
 * MTL/1.0 also refused empty sets, duplicate names and every fraction; 1.1
 * digests them, so HISTOR answers for the servers that carry them.
 */
export class MtlError extends Error {
  constructor(readonly code: string, detail: string) { super(`${code}: ${detail}`); this.name = 'MtlError'; }
}

export const MTL_DIGESTED_FIELDS = ['name', 'description', 'inputSchema', 'outputSchema'] as const;

function normaliseTool(tool: unknown): Record<string, unknown> {
  if (!tool || typeof tool !== 'object' || Array.isArray(tool)) throw new MtlError('MTL-SUBJ-001', 'tool entry is not a JSON object');
  const t = tool as Record<string, unknown>;
  if (typeof t.name !== 'string' || !t.name) throw new MtlError('MTL-SUBJ-001', 'tool entry has no non-empty string name');
  const entry: Record<string, unknown> = {
    name: t.name,
    description: typeof t.description === 'string' ? t.description : '',
    inputSchema: t.inputSchema && typeof t.inputSchema === 'object' && !Array.isArray(t.inputSchema) ? t.inputSchema : {},
  };
  // Present iff the observed object carried it: absence and {} are different tool sets.
  if (t.outputSchema && typeof t.outputSchema === 'object' && !Array.isArray(t.outputSchema)) entry.outputSchema = t.outputSchema;
  return entry;
}

/** The normalised, sorted tool array MTL/1 digests. May be empty; may repeat a name. */
export function mtlToolSet(tools: readonly unknown[]): Record<string, unknown>[] {
  const entries = tools.map(normaliseTool);
  // RFC 8785 §3.2.3 order: UTF-16 code units, which is what `<` compares on strings.
  // Entries sharing a name follow by their canonical UTF-8 bytes (§5.3), so listing order never counts.
  const bytes = new Map<Record<string, unknown>, Buffer>();
  const tie = (e: Record<string, unknown>): Buffer => {
    let b = bytes.get(e);
    if (!b) { b = Buffer.from(canonicalEntry(e), 'utf8'); bytes.set(e, b); }
    return b;
  };
  return entries.sort((a, b) => {
    const x = a.name as string, y = b.name as string;
    return x < y ? -1 : x > y ? 1 : Buffer.compare(tie(a), tie(b));
  });
}

function canonicalEntry(value: unknown): string {
  try { return canonicalizeRfc8785(value); }
  catch (err) {
    // RFC 8785 refuses only a number with no double; JSON.parse makes one of `1e400` (Infinity).
    if (err instanceof CanonicalizationError && err.code === 'AWR-CANON-001') {
      throw new MtlError('MTL-NUM-001', 'a tool schema contains a number with no IEEE 754 double');
    }
    if (err instanceof CanonicalizationError) throw new MtlError('MTL-SUBJ-001', `a tool entry is not canonicalizable (${err.code})`);
    throw err;
  }
}

/** `sha256-<base64>` over the canonical MTL/1 tool set. */
export function mtlToolSetDigest(tools: readonly ToolDef[] | readonly unknown[]): string {
  const canonical = canonicalEntry(mtlToolSet(tools));
  return 'sha256-' + createHash('sha256').update(canonical, 'utf8').digest('base64');
}
