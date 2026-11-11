import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { canonicalizeRfc8785 } from '../src/jcs.js';
import { checkSignedRevision, supp06ManifestDigest } from '../src/signed-revision.js';

const TOOLS = [
  {
    name: 'search',
    description: 'Search the docs.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] },
  },
];

describe('supp06ManifestDigest', () => {
  it('matches histor.revision digests for the same tools', () => {
    const digest = supp06ManifestDigest(TOOLS);
    const manifest: Record<string, unknown> = {
      search: {
        name: 'search',
        description: 'Search the docs.',
        inputSchema: TOOLS[0].inputSchema,
      },
    };
    const expected = 'sha256:' + createHash('sha256').update(canonicalizeRfc8785(manifest), 'utf8').digest('hex');
    expect(digest).toBe(expected);
  });
});

describe('checkSignedRevision', () => {
  it('returns digest_mismatch when HISTOR tip differs from served tools', async () => {
    const tip = 'sha256:' + 'ab'.repeat(32);
    const fetchImpl = async () =>
      new Response(JSON.stringify({
        match: 'no-digest',
        signedRevision: { revision: 1, logIndex: '1', manifestDigest: tip },
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    const verdict = await checkSignedRevision(
      { name: 'io.github.alexar76/histor', tools: TOOLS },
      { fetchImpl: fetchImpl as typeof fetch, historUrl: 'https://histor.example' },
    );
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toBe('digest_mismatch');
  });

  it('returns ok when digests match', async () => {
    const digest = supp06ManifestDigest(TOOLS);
    const fetchImpl = async () =>
      new Response(JSON.stringify({
        match: 'no-digest',
        signedRevision: { revision: 1, logIndex: '3803861704', manifestDigest: digest },
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    const verdict = await checkSignedRevision(
      { name: 'io.github.alexar76/histor', tools: TOOLS },
      { fetchImpl: fetchImpl as typeof fetch, historUrl: 'https://histor.example' },
    );
    expect(verdict).toEqual({
      ok: true,
      match: 'same',
      revision: 1,
      logIndex: '3803861704',
      manifestDigest: digest,
    });
  });
});
