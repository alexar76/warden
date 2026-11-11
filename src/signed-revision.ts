/**
 * OWASP MCPSTG-SUPP-06: compare a live tools/list against the publisher-signed
 * revision HISTOR ingested (signedRevision on POST /api/v1/check).
 *
 * Canonical form matches histor.revision: snapshot fields keyed by tool name,
 * RFC 8785, SHA-256. Privileged tools/call must not proceed when the served
 * digest differs from the signed tip (Secure path).
 */
import { createHash } from 'node:crypto';
import { canonicalizeRfc8785 } from './jcs.js';
import { historCheck, DEFAULT_HISTOR_URL, type HistorCheck, type HistorOptions, type HistorQuery } from './histor.js';

const TOOL_FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations', 'execution'] as const;

export type SignedRevisionVerdict =
  | { ok: true; match: 'same'; revision: number; logIndex: string; manifestDigest: string }
  | { ok: false; reason: 'no_signed_revision' | 'digest_mismatch' | 'histor_error'; detail: string; check?: HistorCheck };

export function supp06ManifestDigest(tools: readonly Record<string, unknown>[]): string {
  const manifest: Record<string, Record<string, unknown>> = {};
  for (const tool of tools) {
    const name = tool.name;
    if (typeof name !== 'string' || !name) throw new Error('a tool without a string name');
    if (name in manifest) throw new Error(`two tools named ${JSON.stringify(name)}`);
    const entry: Record<string, unknown> = {};
    for (const k of TOOL_FIELDS) if (k in tool) entry[k] = tool[k];
    manifest[name] = entry;
  }
  return 'sha256:' + createHash('sha256').update(canonicalizeRfc8785(manifest), 'utf8').digest('hex');
}

export interface SignedRevisionQuery extends HistorQuery {
  tools: readonly Record<string, unknown>[];
}

/**
 * Ask HISTOR for the latest signed tip, compute the local SUPP-06 digest, compare.
 * Prefer the local digest over trusting HISTOR's match alone (client verifies).
 */
export async function checkSignedRevision(
  query: SignedRevisionQuery,
  opts: HistorOptions & { historUrl?: string } = {},
): Promise<SignedRevisionVerdict> {
  const served = supp06ManifestDigest(query.tools);
  let answer: HistorCheck;
  try {
    answer = await historCheck(opts.historUrl ?? DEFAULT_HISTOR_URL, {
      endpoint: query.endpoint,
      package: query.package,
      name: query.name,
    }, opts);
  } catch (err) {
    return { ok: false, reason: 'histor_error', detail: err instanceof Error ? err.message : String(err) };
  }
  const sr = (answer as HistorCheck & { signedRevision?: {
    revision?: number; logIndex?: string; manifestDigest?: string; match?: string; alerts?: string[];
  } }).signedRevision;
  if (!sr || typeof sr.manifestDigest !== 'string' || typeof sr.revision !== 'number') {
    return { ok: false, reason: 'no_signed_revision', detail: 'HISTOR has no publisher-signed revision for this server', check: answer };
  }
  if (served !== sr.manifestDigest) {
    return {
      ok: false,
      reason: 'digest_mismatch',
      detail: `served ${served} ≠ signed revision ${sr.revision} ${sr.manifestDigest}`,
      check: answer,
    };
  }
  return {
    ok: true,
    match: 'same',
    revision: sr.revision,
    logIndex: String(sr.logIndex ?? ''),
    manifestDigest: sr.manifestDigest,
  };
}
