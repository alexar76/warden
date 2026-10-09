import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mtlToolSetDigest, MtlError } from '../src/mtl.js';

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/mtl-vectors.json', import.meta.url)), 'utf8'));

describe('MTL/1 tool-set digest (HISTOR interop)', () => {
  it.each(['basic', 'output', 'unicode'])('matches HISTOR\'s own digest: %s', name => {
    expect(mtlToolSetDigest(vectors[name].tools)).toBe(vectors[name].digest);
  });
  it('withholds a digest for fractional numbers, as HISTOR does', () => {
    expect(vectors.fraction).toBe('MTL-NUM-001');
    expect(() => mtlToolSetDigest([{ name: 'x', description: '', inputSchema: { default: 0.7 } }])).toThrow(MtlError);
    try { mtlToolSetDigest([{ name: 'x', description: '', inputSchema: { default: 0.7 } }]); } catch (e) { expect((e as MtlError).code).toBe('MTL-NUM-001'); }
  });
  it('refuses empty sets and duplicate names', () => {
    expect(() => mtlToolSetDigest([])).toThrow(/MTL-SUBJ-002/);
    expect(() => mtlToolSetDigest([{ name: 'a', description: '', inputSchema: {} }, { name: 'a', description: '', inputSchema: {} }])).toThrow(/MTL-SUBJ-003/);
  });
  it('ignores fields outside the profile, and order', () => {
    const a = [{ name: 'a', description: 'x', inputSchema: {}, annotations: { readOnlyHint: true } }, { name: 'b', description: 'y', inputSchema: {} }];
    const b = [{ name: 'b', description: 'y', inputSchema: {} }, { name: 'a', description: 'x', inputSchema: {} }];
    expect(mtlToolSetDigest(a)).toBe(mtlToolSetDigest(b));
  });
});
