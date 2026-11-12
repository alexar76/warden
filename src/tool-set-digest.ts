import { createHash } from 'node:crypto';
import { canonicalizeRfc8785, CanonicalizationError } from './jcs.js';
import { mtlToolSet, mtlToolSetDigest, MtlError } from './mtl.js';

/**
 * The digests of the specification `mcp-tool-set-digest/1`: one way to hash a `tools/list`
 * result that tools which never exchanged the tool text can compare. The specification's
 * vectors are in test/fixtures/tool-set-digest-vectors.json and run in test/interceptor.test.ts.
 *
 * - The **contract digest** covers `name`, `description`, `inputSchema` and (when the server
 *   sent one) `outputSchema`: what a model reads and a call must satisfy. It is the digest
 *   {@link mtlToolSetDigest} already computes and HISTOR's public log keys tool sets by.
 * - The **extras digest** covers everything else a tool carries (`title`, `annotations`, `icons`,
 *   `_meta`, vendor members), so it moves when an annotation flips or a title is edited. A set in
 *   which no tool has extras has none.
 *
 * Neither is {@link pinToolsHash}: a pin is WARDEN's local state and is compared only with
 * itself. These two are for comparing with someone else.
 */
export const TOOL_SET_DIGEST_SPEC = 'mcp-tool-set-digest/1';

/** A digest the specification says cannot be computed: `TSD-TOOL`, `TSD-NUMBER`, `TSD-TEXT`, `TSD-NAME`. */
export class ToolSetDigestError extends Error {
  constructor(readonly code: 'TSD-TOOL' | 'TSD-NUMBER' | 'TSD-TEXT' | 'TSD-NAME', detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'ToolSetDigestError';
  }
}

function canonical(value: unknown): string {
  try { return canonicalizeRfc8785(value); }
  catch (err) {
    if (err instanceof CanonicalizationError && err.code === 'AWR-CANON-001') {
      throw new ToolSetDigestError('TSD-NUMBER', 'a number with no IEEE 754 double');
    }
    if (err instanceof CanonicalizationError) throw new ToolSetDigestError('TSD-TEXT', `not canonicalizable (${err.code})`);
    throw err;
  }
}

function toolObject(tool: unknown): Record<string, unknown> {
  if (!tool || typeof tool !== 'object' || Array.isArray(tool)) throw new ToolSetDigestError('TSD-TOOL', 'a tool entry is not a JSON object');
  const t = tool as Record<string, unknown>;
  if (typeof t.name !== 'string' || !t.name) throw new ToolSetDigestError('TSD-TOOL', 'a tool entry has no non-empty string name');
  return t;
}

const sri = (text: string): string => 'sha256-' + createHash('sha256').update(text, 'utf8').digest('base64');

/** `sha256-<base64>` over the contract members of every tool (SPEC.md sections 4 to 7). */
export function contractDigest(tools: readonly unknown[]): string {
  try { return mtlToolSetDigest(tools); }
  catch (err) {
    if (!(err instanceof MtlError)) throw err;
    // MTL-SUBJ-001 covers both "not a tool" and "a string RFC 8785 refuses"; the specification tells them apart.
    if (err.code === 'MTL-NUM-001') throw new ToolSetDigestError('TSD-NUMBER', 'a number with no IEEE 754 double');
    throw new ToolSetDigestError(/not canonicalizable/.test(err.message) ? 'TSD-TEXT' : 'TSD-TOOL', err.message.replace(/^MTL-SUBJ-001: /, ''));
  }
}

const CONTRACT_MEMBERS = new Set(['name', 'description', 'inputSchema', 'outputSchema']);

/**
 * `{"tools": {name: extras}}` for the tools that carry a member outside the contract, or
 * undefined when none does (SPEC.md section 8). Two tools with one name that both carry extras
 * are `TSD-NAME`: an object keyed by name cannot hold both.
 */
export function extrasObject(tools: readonly unknown[]): { tools: Record<string, unknown> } | undefined {
  const byName = new Map<string, Record<string, unknown>>();
  for (const item of tools) {
    const tool = toolObject(item);
    const extra = Object.fromEntries(Object.entries(tool).filter(([key]) => !CONTRACT_MEMBERS.has(key)));
    if (!Object.keys(extra).length) continue;
    const name = tool.name as string;
    if (byName.has(name)) throw new ToolSetDigestError('TSD-NAME', `two tools named ${JSON.stringify(name)} both carry extras`);
    byName.set(name, extra);
  }
  if (!byName.size) return undefined;
  // A null-prototype object, filled with defineProperty, keeps a tool named "__proto__" an ordinary member.
  const members = Object.create(null) as Record<string, unknown>;
  for (const [name, extra] of byName) Object.defineProperty(members, name, { value: extra, enumerable: true });
  return { tools: members };
}

/** `sha256-<base64>` over the extras object (SPEC.md section 8); undefined when no tool has extras. */
export function extrasDigest(tools: readonly unknown[]): string | undefined {
  const body = extrasObject(tools);
  return body ? sri(canonical(body)) : undefined;
}

/** Per tool, lowercase hex SHA-256 of its canonical contract entry (SPEC.md section 9), in digest order. */
export function perToolContract(tools: readonly unknown[]): Array<{ name: string; contract: string }> {
  return mtlToolSet(tools).map(entry => ({
    name: entry.name as string,
    contract: createHash('sha256').update(canonical(entry), 'utf8').digest('hex'),
  }));
}

/** The canonical text of one whole tool definition, or the code of the reason it has none. */
export function definitionText(tool: unknown): { text?: string; code?: string } {
  try { return { text: canonical(toolObject(tool)) }; }
  catch (err) {
    if (!(err instanceof ToolSetDigestError)) throw err;
    return { code: err.code };
  }
}

/** Read `sha256-<base64>` or `sha256:<hex>` as the 32 bytes both name; undefined when it is neither. */
export function digestBytes(text: unknown): Buffer | undefined {
  if (typeof text !== 'string') return undefined;
  const hex = /^sha256:([0-9a-f]{64})$/.exec(text);
  if (hex) return Buffer.from(hex[1]!, 'hex');
  const b64 = /^sha256-([A-Za-z0-9+/]{43}=)$/.exec(text);
  if (!b64) return undefined;
  const bytes = Buffer.from(b64[1]!, 'base64');
  return bytes.length === 32 ? bytes : undefined;
}

/** True when two digest strings, in either form, name the same 32 bytes. */
export function sameDigest(a: unknown, b: unknown): boolean {
  const x = digestBytes(a), y = digestBytes(b);
  return !!x && !!y && x.equals(y);
}
