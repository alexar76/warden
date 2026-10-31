import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mtlToolSetDigest, MtlError } from '../src/mtl.js';

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/mtl-vectors.json', import.meta.url)), 'utf8'));

describe('MTL/1 tool-set digest (HISTOR interop)', () => {
  it.each(['basic', 'output', 'unicode'])('matches HISTOR\'s own digest: %s', name => {
    expect(mtlToolSetDigest(vectors[name].tools)).toBe(vectors[name].digest);
  });
  // MTL/1.1: what 1.0 refused, written by HISTOR's Python and read back through JSON.parse here.
  it.each(['fraction', 'exponent', 'largeInteger', 'empty', 'duplicate'])('digests what MTL/1.0 refused, as HISTOR does: %s', name => {
    expect(mtlToolSetDigest(vectors[name].tools)).toBe(vectors[name].digest);
  });
  it('withholds a digest only for a number with no double', () => {
    const tools = JSON.parse('[{"name":"x","description":"","inputSchema":{"maximum":1e400}}]');
    expect(() => mtlToolSetDigest(tools)).toThrow(MtlError);
    try { mtlToolSetDigest(tools); } catch (e) { expect((e as MtlError).code).toBe('MTL-NUM-001'); }
  });
  it('does not depend on the order of tools that share a name', () => {
    const tools = vectors.duplicate.tools as unknown[];
    expect(mtlToolSetDigest([...tools].reverse())).toBe(vectors.duplicate.digest);
  });
  it('writes 5.0 as 5, as JSON.parse already does', () => {
    const asFloat = JSON.parse('[{"name":"x","description":"","inputSchema":{"default":5.0}}]');
    expect(mtlToolSetDigest(asFloat)).toBe(mtlToolSetDigest([{ name: 'x', description: '', inputSchema: { default: 5 } }]));
  });
  it('refuses an entry with no name', () => {
    expect(() => mtlToolSetDigest([{ description: '', inputSchema: {} }])).toThrow(/MTL-SUBJ-001/);
  });
  it('ignores fields outside the profile, and order', () => {
    const a = [{ name: 'a', description: 'x', inputSchema: {}, annotations: { readOnlyHint: true } }, { name: 'b', description: 'y', inputSchema: {} }];
    const b = [{ name: 'b', description: 'y', inputSchema: {} }, { name: 'a', description: 'x', inputSchema: {} }];
    expect(mtlToolSetDigest(a)).toBe(mtlToolSetDigest(b));
  });
});
