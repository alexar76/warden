import { afterEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Exercise the compiled stdio boundary, including the approval gate, without inheriting
// operator credentials, opt-ins or real pin paths. Every child has its own explicit state.
const root = fileURLToPath(new URL('../', import.meta.url));
const dirs: string[] = [];
const server = { id: 'server-info-contract', name: 'Contract Fixture', transport: 'http', url: 'https://fixture.invalid/mcp' };
const tools = [{ name: 'fixture_read', description: 'Read a synthetic fixture.', inputSchema: { type: 'object', properties: {} } }];
const unknownKeyError = 'server_info may contain only name and version';

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function ownState(): string {
  const dir = mkdtempSync(join(tmpdir(), 'warden-server-info-'));
  dirs.push(dir);
  return dir;
}

function rpc(dir: string, name: string, args: object, allowPins = false): any {
  const child = spawnSync(process.execPath, [join(root, 'dist/mcp-server.js')], {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 2 * 1024 * 1024,
    env: {
      PATH: process.env.PATH,
      WARDEN_STATE_DIR: dir,
      WARDEN_ALLOW_PIN_CHANGES: allowPins ? '1' : '0',
    },
    input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) + '\n',
  });
  expect(child.error).toBeUndefined();
  expect(child.status, child.stderr).toBe(0);
  const lines = child.stdout.trim().split('\n');
  expect(lines).toHaveLength(1);
  const response = JSON.parse(lines[0]!);
  expect(response.jsonrpc).toBe('2.0');
  expect(response.id).toBe(1);
  expect(response.error).toBeUndefined();
  return response.result;
}

function status(dir: string, extra: object = {}, allowPins = false): any {
  return rpc(dir, 'status_mcp_server', { server, tools, ...extra }, allowPins);
}

function reviewedArguments(review: any): object {
  return {
    server, tools,
    reviewed_tools_hash: review.currentToolsHash,
    reviewed_identity_hash: review.currentIdentityHash,
    previous_pin_revision: review.previousRevision,
  };
}

function files(dir: string, relative = ''): Record<string, string> {
  const result: Record<string, string> = {};
  for (const entry of readdirSync(join(dir, relative), { withFileTypes: true })) {
    const path = join(relative, entry.name);
    if (entry.isDirectory()) Object.assign(result, files(dir, path));
    else result[path] = readFileSync(join(dir, path)).toString('base64');
  }
  return result;
}

function toolError(result: any, message: string): void {
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toBeUndefined();
  expect(result.content).toEqual([{ type: 'text', text: message }]);
}

const unknownInfo = [
  ['extra', JSON.parse('{"name":"fixture","version":"1.2.0","extra":true}')],
  // A __proto__ literal changes a prototype rather than adding a JSON key. Parse the
  // actual wire shape so this regression covers an own property, as Object.keys sees it.
  ['__proto__', JSON.parse('{"name":"fixture","version":"1.2.0","__proto__":{"polluted":true}}')],
  ['constructor', JSON.parse('{"name":"fixture","version":"1.2.0","constructor":"unexpected"}')],
] as const;

describe('status server_info at the stdio boundary', () => {
  it.each(unknownInfo)('rejects unknown own key %s without writing state', (key, info) => {
    expect(Object.hasOwn(info, key)).toBe(true);
    const dir = ownState();
    toolError(status(dir, { server_info: info }), unknownKeyError);
    expect(readdirSync(dir)).toEqual([]);
  });

  it.each([
    ['omitted', {}],
    ['undefined serialized as omitted', { server_info: undefined }],
    ['null', { server_info: null }],
    ['empty object', { server_info: {} }],
    ['name only', { server_info: { name: 'fixture' } }],
    ['version only', { server_info: { version: '1.2.0' } }],
    ['full metadata', { server_info: { name: 'fixture', version: '1.2.0' } }],
    ['empty strings', { server_info: { name: '', version: '' } }],
    ['200 character boundary', { server_info: { name: 'n'.repeat(200), version: '1'.repeat(200) } }],
  ])('keeps compatible %s input', (_label, args) => {
    const dir = ownState();
    const result = status(dir, args as object);
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      previous: null, previousRevision: null, mutationsEnabled: false,
      origin: { approvedVersion: null, launch: null },
    });
    expect(result.structuredContent.currentToolsHash).toMatch(/^(?:rfc8785:)?[0-9a-f]{64}$/);
    expect(readdirSync(dir)).toEqual([]);
  });

  it.each([
    ['numeric version', { version: 7 }, 'server_info.version must be a string of at most 200 characters'],
    ['numeric name', { name: 7 }, 'server_info.name must be a string of at most 200 characters'],
    ['long version', { version: 'v'.repeat(201) }, 'server_info.version must be a string of at most 200 characters'],
    ['long name', { name: 'n'.repeat(201) }, 'server_info.name must be a string of at most 200 characters'],
    ['array', [], 'server_info must be the serverInfo object from initialize'],
    ['string', 'fixture', 'server_info must be the serverInfo object from initialize'],
  ])('continues rejecting %s', (_label, info, message) => {
    const dir = ownState();
    toolError(status(dir, { server_info: info }), message as string);
    expect(readdirSync(dir)).toEqual([]);
  });
});

describe('enabled approvals reject invalid metadata before changing pins', () => {
  it.each(unknownInfo)('unknown %s cannot create or replace an approval', (_key, info) => {
    const dir = ownState();
    const first = status(dir, {}, true).structuredContent;
    expect(first.mutationsEnabled).toBe(true);
    toolError(rpc(dir, 'approve_mcp_server', { ...reviewedArguments(first), server_info: info }, true), unknownKeyError);
    expect(readdirSync(dir)).toEqual([]);

    // The old call shape without server_info remains a valid explicit approval.
    const approved = rpc(dir, 'approve_mcp_server', reviewedArguments(first), true);
    expect(approved.isError).not.toBe(true);
    expect(approved.structuredContent.approved).toBe(true);
    expect(approved.structuredContent.pin).not.toHaveProperty('serverInfo');
    const saved = files(dir);
    expect(Object.keys(saved)).toHaveLength(1);

    const review = status(dir, {}, true).structuredContent;
    expect(review.previousRevision).toMatch(/^[0-9a-f]{64}$/);
    // These are current, valid review hashes and revision: refusal must concern metadata,
    // not disabled writes or a stale compare-and-swap token.
    toolError(rpc(dir, 'approve_mcp_server', { ...reviewedArguments(review), server_info: info }, true), unknownKeyError);
    expect(files(dir)).toEqual(saved);
    const unchanged = status(dir, {}, true).structuredContent;
    expect(unchanged.previousRevision).toBe(review.previousRevision);
    expect(unchanged.previous).toEqual(review.previous);
  });

  it('still stores valid partial metadata with an explicitly reviewed approval', () => {
    const dir = ownState();
    const first = status(dir, { server_info: { version: '1.2.0' } }, true).structuredContent;
    const approved = rpc(dir, 'approve_mcp_server', {
      ...reviewedArguments(first), server_info: { version: '1.2.0' },
    }, true);
    expect(approved.isError).not.toBe(true);
    expect(approved.structuredContent.pin.serverInfo).toEqual({ version: '1.2.0' });
    const review = status(dir, {}, true).structuredContent;
    expect(review.origin.approvedVersion).toBe('1.2.0');
  });
});
