import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  urlRefusal, parseDeclarationFile, cleanWhen, withSet, serverJsonBlock, parseDeclareArgs, runDeclare,
  DeclareError, DeclareUsage, MAX_FILE_SETS, MAX_ENTRY_SETS, MAX_FILE_BYTES, PUBLISHER_PROVIDED, DECLARATION_FIELD,
  type DeclareDeps, type DeclarationFile,
} from '../src/declare.js';
import { mtlToolSetDigest } from '../src/mtl.js';
import type { ToolDef } from '../src/types.js';

/** Produced by HISTOR's own implementation (histor/histor/declared.py): what WARDEN accepts, HISTOR takes. */
const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/declaration-vectors.json', import.meta.url)), 'utf8'));
const tools: ToolDef[] = [
  { name: 'screenshot', description: 'Take a screenshot.', inputSchema: { type: 'object' } },
  { name: 'click', description: 'Click at a point.', inputSchema: { type: 'object', properties: { x: { type: 'number' } } } },
];
const DIGEST = mtlToolSetDigest(tools);
const D = (c: string) => `sha256-${c.repeat(43)}=`;

function harness(files: Record<string, string> = {}, extra: Partial<DeclareDeps> = {}) {
  const out: string[] = [], err: string[] = [];
  const deps: DeclareDeps = {
    fetch: async () => ({ tools }),
    readFile: async p => { if (!(p in files)) throw new Error('ENOENT'); return files[p]!; },
    writeFile: async (p, t) => { files[p] = t; },
    out: t => out.push(t), err: t => err.push(t), ...extra,
  };
  return { files, out, err, deps };
}

describe('declare: the same rules as HISTOR', () => {
  it('binds a file URL to the domain the registry verified, exactly as HISTOR does', () => {
    expect(vectors.urls.length).toBeGreaterThan(20);
    for (const v of vectors.urls) expect([v.url, urlRefusal(v.url, v.server) ?? null]).toEqual([v.url, v.refusal]);
  });

  it('reads a declaration file exactly as HISTOR does', () => {
    for (const v of vectors.files) {
      let got: unknown;
      try { got = parseDeclarationFile(v.text); } catch (e) { got = { error: (e as Error).message }; }
      expect(got).toEqual(v.error !== undefined ? { error: v.error } : { sets: v.sets, ignored: v.ignored });
    }
  });

  it('cleans a condition exactly as HISTOR does', () => {
    for (const v of vectors.whens) expect(cleanWhen(v.input) ?? null).toEqual(v.output);
  });
});

describe('declare: building a declaration', () => {
  it('adds a set to a file, replaces the same digest in place and keeps the rest', () => {
    let file: DeclarationFile | undefined;
    file = withSet(file, { digest: D('A'), when: 'runner 1.4, macOS' });
    file = withSet(file, { digest: D('B'), when: 'runner 1.4, Linux' });
    file = withSet(file, { digest: D('A'), count: 3, when: 'runner 1.4, macOS (fixed)' });
    expect(file).toEqual({ mtl: '1', sets: [{ digest: D('A'), count: 3, when: 'runner 1.4, macOS (fixed)' }, { digest: D('B'), when: 'runner 1.4, Linux' }] });
    const full: DeclarationFile = { mtl: '1', sets: Array.from({ length: MAX_FILE_SETS }, (_, i) => ({ digest: `sha256-${String(i).padStart(4, '0')}${'A'.repeat(39)}=` })) };
    expect(() => withSet(full, { digest: D('Z') })).toThrow(/at most 64/);
  });

  it('prints the server.json block the registry keeps for downstream registries', () => {
    expect(serverJsonBlock([{ digest: DIGEST, count: 2 }], 'https://acme.dev/sets.json')).toEqual({
      _meta: { [PUBLISHER_PROVIDED]: { [DECLARATION_FIELD]: { mtl: '1', sets: [{ digest: DIGEST, count: 2 }], url: 'https://acme.dev/sets.json' } } },
    });
    expect(serverJsonBlock([], 'https://acme.dev/sets.json')).toEqual({ _meta: { [PUBLISHER_PROVIDED]: { [DECLARATION_FIELD]: { mtl: '1', url: 'https://acme.dev/sets.json' } } } });
    expect(() => serverJsonBlock(Array.from({ length: MAX_ENTRY_SETS + 1 }, (_, i) => ({ digest: D(String.fromCharCode(65 + i)) })))).toThrow(/--link/);
  });

  it('parses its arguments and refuses mixed or missing ones', () => {
    expect(parseDeclareArgs(['--when', 'runner 1.4', '--out', 'f.json', '--', 'npx', '-y', '@acme/launcher']))
      .toMatchObject({ mode: 'set', when: 'runner 1.4', out: 'f.json', ref: { transport: 'stdio', command: 'npx', args: ['-y', '@acme/launcher'] } });
    expect(parseDeclareArgs(['--url', 'https://acme.dev/mcp'])).toMatchObject({ ref: { transport: 'http', url: 'https://acme.dev/mcp' } });
    expect(parseDeclareArgs(['--server-json', '--link', 'https://acme.dev/sets.json'])).toMatchObject({ serverJson: true, link: 'https://acme.dev/sets.json' });
    expect(parseDeclareArgs(['--check', 'https://acme.dev/sets.json', '--name', 'dev.acme/x'])).toMatchObject({ mode: 'check', name: 'dev.acme/x' });
    expect(() => parseDeclareArgs(['--help'])).toThrow(DeclareUsage);
    for (const bad of [[], ['--out', 'f'], ['--check', 'https://acme.dev/s.json'], ['--out', 'f', '--server-json', '--', 'x'],
      ['--link', 'https://x', '--', 'x'], ['--url', 'https://a', '--', 'x'], ['--when'], ['--bogus'], ['--timeout', '5', '--', 'x']]) {
      expect(() => parseDeclareArgs(bad), bad.join(' ')).toThrow(DeclareError);
    }
  });
});

describe('declare: running it', () => {
  const ref = parseDeclareArgs(['--when', 'runner​ 1.4, macOS', '--', 'npx', '-y', '@acme/launcher']);

  it('prints the set this machine gets', async () => {
    const h = harness();
    expect(await runDeclare(ref, h.deps)).toBe(0);
    expect(JSON.parse(h.out.join('\n'))).toEqual({ digest: DIGEST, count: 2, when: 'runner 1.4, macOS' });
  });

  it('writes and merges a declaration file, and never overwrites one HISTOR could not read', async () => {
    const h = harness({ 'sets.json': JSON.stringify({ mtl: '1', sets: [{ digest: D('A'), when: 'runner 1.3, macOS' }] }) });
    expect(await runDeclare({ ...ref, out: 'sets.json' }, h.deps)).toBe(0);
    expect(JSON.parse(h.files['sets.json']!).sets).toEqual([{ digest: D('A'), when: 'runner 1.3, macOS' }, { digest: DIGEST, count: 2, when: 'runner 1.4, macOS' }]);
    expect(await runDeclare({ ...ref, out: 'sets.json' }, h.deps)).toBe(0);
    expect(JSON.parse(h.files['sets.json']!).sets).toHaveLength(2);
    expect(h.out.at(-1)).toMatch(/^Updated/);

    const broken = harness({ 'sets.json': '{"mtl": "2"}' });
    expect(await runDeclare({ ...ref, out: 'sets.json' }, broken.deps)).toBe(1);
    expect(broken.files['sets.json']).toBe('{"mtl": "2"}');
    expect(broken.err.join('\n')).toMatch(/not overwriting/);
  });

  it('prints the registry block, and says when the server did not answer or has no digest', async () => {
    const h = harness();
    expect(await runDeclare({ ...ref, serverJson: true }, h.deps)).toBe(0);
    expect(JSON.parse(h.out.join('\n'))._meta[PUBLISHER_PROVIDED][DECLARATION_FIELD].sets[0].digest).toBe(DIGEST);

    const down = harness({}, { fetch: async () => { throw new Error('spawn npx ENOENT'); } });
    expect(await runDeclare(ref, down.deps)).toBe(1);
    expect(down.err.join('\n')).toMatch(/did not answer tools\/list: spawn npx ENOENT/);

    // MTL/1.1 digests a fraction; a tool with no name still has no digest.
    const fraction = harness({}, { fetch: async () => ({ tools: [{ name: 'x', inputSchema: { type: 'object', default: 1.5 } } as unknown as ToolDef] }) });
    expect(await runDeclare(ref, fraction.deps)).toBe(0);
    const odd = harness({}, { fetch: async () => ({ tools: [{ inputSchema: { type: 'object' } } as unknown as ToolDef] }) });
    expect(await runDeclare(ref, odd.deps)).toBe(1);
    expect(odd.err.join('\n')).toMatch(/no MTL\/1 digest \(MTL-SUBJ-001\)/);
  });

  it('checks a published file the way HISTOR will read it', async () => {
    const good = JSON.stringify({ mtl: '1', sets: [{ digest: DIGEST, when: 'runner 1.4, macOS' }, { digest: 'bad' }] });
    const site = (status: number, body = '') => harness({}, { get: async () => ({ status, body }) });
    const check = (url: string) => parseDeclareArgs(['--check', url, '--name', 'dev.acme/launcher']);

    let h = site(200, good);
    expect(await runDeclare(check('https://acme.dev/.well-known/mcp-tool-sets.json'), h.deps)).toBe(0);
    expect(h.out[0]).toMatch(/HISTOR will take 1 set from this file \(1 skipped/);
    expect(h.err[0]).toMatch(/skipped: sets\[1\]/);

    h = site(200, good);
    expect(await runDeclare(check('https://elsewhere.example/sets.json'), h.deps)).toBe(1);
    expect(h.err[0]).toMatch(/must be on acme.dev or a subdomain/);
    for (const [status, body, why] of [[301, '', /redirects are not followed/], [404, '', /http-404/],
      [200, ' '.repeat(MAX_FILE_BYTES + 1), /larger than 64 KiB/], [200, '{"mtl":"1","sets":[{"digest":"x"}]}', /will not take this file/]] as const) {
      h = site(status, body);
      expect(await runDeclare(check('https://acme.dev/sets.json'), h.deps)).toBe(1);
      expect(h.err.join('\n')).toMatch(why);
    }
    h = site(200, '{"mtl":"1","sets":[]}');
    expect(await runDeclare(check('https://acme.dev/sets.json'), h.deps)).toBe(0);
    expect(h.out[0]).toMatch(/withdraw every set/);

    const local = harness({ 'sets.json': good });
    expect(await runDeclare(parseDeclareArgs(['--check', 'sets.json']), local.deps)).toBe(0);
  });
});
