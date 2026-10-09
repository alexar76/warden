import { createHash } from 'node:crypto';
import { canonicalize, CanonicalizationError } from './jcs.js';
import type { ToolDef } from './types.js';

/**
 * MTL/1 tool-set digest — the digest HISTOR's public log keys tool sets by
 * (awr/adoption/mcp-trust-label/PROFILE.md §5, histor/subject.py).
 *
 * It is NOT {@link pinToolsHash}: a pin covers every advertised field and is
 * local state; this digest covers exactly `name`, `description`, `inputSchema`
 * and (only when present) `outputSchema`, sorted by UTF-16 code units of the
 * name, serialised with the AWR/2 canonicalizer, and is what two strangers can
 * compare without exchanging the definitions themselves. That property is why
 * `scan --histor` sends only this value: the log answers "same / different /
 * previously observed" without ever receiving a tool description.
 *
 * Throws {@link MtlError}: `MTL-SUBJ-001` (not an object / no name),
 * `MTL-SUBJ-002` (empty set), `MTL-SUBJ-003` (duplicate name), `MTL-NUM-001`
 * (a non-integer number, which the profile withholds a digest for rather than
 * guessing how another implementation would print it).
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

/** The normalised, sorted tool array MTL/1 digests. */
export function mtlToolSet(tools: readonly unknown[]): Record<string, unknown>[] {
  if (!tools.length) throw new MtlError('MTL-SUBJ-002', 'the tool set is empty; there is nothing to pin');
  const entries = tools.map(normaliseTool);
  const seen = new Map<string, number>();
  entries.forEach((entry, index) => {
    const name = entry.name as string;
    if (seen.has(name)) throw new MtlError('MTL-SUBJ-003', `duplicate tool name ${JSON.stringify(name)} at positions ${seen.get(name)} and ${index}`);
    seen.set(name, index);
  });
  // RFC 8785 §3.2.3 order: UTF-16 code units, which is what `<` compares on strings.
  return entries.sort((a, b) => (a.name as string) < (b.name as string) ? -1 : (a.name as string) > (b.name as string) ? 1 : 0);
}

/** `sha256-<base64>` over the canonical MTL/1 tool set. */
export function mtlToolSetDigest(tools: readonly ToolDef[] | readonly unknown[]): string {
  const entries = mtlToolSet(tools);
  let canonical: string;
  try { canonical = canonicalize(entries); }
  catch (err) {
    if (err instanceof CanonicalizationError && (err.code === 'AWR-CANON-001' || err.code === 'AWR-CANON-002')) {
      throw new MtlError('MTL-NUM-001', `a tool schema contains a JSON number MTL/1 cannot digest reproducibly (${err.code})`);
    }
    if (err instanceof CanonicalizationError) throw new MtlError('MTL-SUBJ-001', `a tool entry is not canonicalizable (${err.code})`);
    throw err;
  }
  return 'sha256-' + createHash('sha256').update(canonical, 'utf8').digest('base64');
}
