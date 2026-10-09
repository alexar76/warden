/**
 * HISTOR — the public transparency log of MCP tool definitions
 * (https://histor.modelmarket.dev, source github.com/alexar76/histor).
 *
 * `scan --histor` asks the log one question per remote server: is the tool set
 * this machine was served the one the log observes for everyone? The request
 * carries the server's endpoint and the MTL/1 digest of the set, nothing else:
 * no tool description ever leaves the machine, and the log cannot learn what a
 * private server advertises. The answer is signed by the log and says `same`,
 * `different` (you were served something the log never saw: a targeted
 * definition, or a change the crawl has not reached yet), `previously-observed`
 * (a set the log saw earlier: stale or rolled back), or that the server is not
 * listed / not observed.
 */
export const DEFAULT_HISTOR_URL = 'https://histor.modelmarket.dev';
export const HISTOR_RESPONSE_BYTES = 256 * 1024;

export type HistorMatch = 'same' | 'different' | 'previously-observed' | 'not-listed' | 'not-observed' | 'no-digest' | 'undigestible';

export interface HistorQuery {
  endpoint?: string;
  name?: string;
  /** `sha256-<base64>` from {@link mtlToolSetDigest}. */
  toolSetDigest?: string;
}

export interface HistorCheck {
  match: HistorMatch | string;
  note?: string;
  checkedAt?: string;
  issuer?: string;
  target?: { id?: string; name?: string; endpoint?: string; page?: string; badge?: string; lastStatus?: string; listed?: boolean };
  observed?: { toolSetDigest?: string; subjectDigest?: string; toolCount?: number; firstPinned?: string; unchangedSince?: string; lastObserved?: string; observations?: number; changes?: number };
  seenBefore?: unknown;
  patternScan?: unknown;
  classifier?: unknown;
  log?: { treeSize?: number; rootHash?: string; timestamp?: string };
  [field: string]: unknown;
}

export interface HistorOptions {
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  userAgent?: string;
}

export class HistorError extends Error {}

/** POST /api/v1/check with endpoint/name + digest only. */
export async function historCheck(base: string, query: HistorQuery, opts: HistorOptions = {}): Promise<HistorCheck> {
  const root = new URL(base);
  if (root.protocol !== 'https:' && root.protocol !== 'http:') throw new HistorError('HISTOR URL must be http(s)');
  if (!query.endpoint && !query.name) throw new HistorError('a HISTOR check needs an endpoint or a name');
  // Only these three fields, ever. `tools` and `contribute` are deliberately not forwarded.
  const body: HistorQuery = {};
  if (query.endpoint) body.endpoint = query.endpoint;
  if (query.name) body.name = query.name;
  if (query.toolSetDigest) body.toolSetDigest = query.toolSetDigest;
  const url = new URL('/api/v1/check', root);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await (opts.fetchImpl ?? fetch)(url, {
      method: 'POST', signal: controller.signal, redirect: 'error',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': opts.userAgent ?? 'warden-scan' },
      body: JSON.stringify(body),
    });
    const text = await readBounded(res, HISTOR_RESPONSE_BYTES);
    if (!res.ok) throw new HistorError(`HISTOR answered HTTP ${res.status}`);
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { throw new HistorError('HISTOR answered non-JSON'); }
    if (!parsed || typeof parsed !== 'object' || typeof (parsed as HistorCheck).match !== 'string') throw new HistorError('HISTOR answer has no match field');
    return parsed as HistorCheck;
  } catch (err) {
    if (err instanceof HistorError) throw err;
    throw new HistorError(controller.signal.aborted ? 'HISTOR timed out' : `HISTOR did not answer (${err instanceof Error ? err.message : String(err)})`);
  } finally { clearTimeout(timer); }
}

/** Read a response body up to `limit` bytes; refuse a longer one. */
export async function readBounded(res: Response, limit: number): Promise<string> {
  if (!res.body) return '';
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
    total += chunk.byteLength;
    if (total > limit) { await res.body.cancel().catch(() => {}); throw new HistorError(`response exceeds ${limit} bytes`); }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}
