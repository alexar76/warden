import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import type { McpServerRef } from './types.js';

/**
 * Where MCP clients keep the servers they start, and how to read those files.
 *
 * `scan` reads the configuration a developer already has instead of asking for a
 * tools/list dump: the servers in these files are the ones that reach a model on
 * this machine, so they are the ones worth vetting.
 */
export type ClientKind = 'claude-code' | 'claude-desktop' | 'cursor' | 'vscode' | 'windsurf' | 'file';
export const CLIENT_KINDS: readonly ClientKind[] = ['claude-code', 'claude-desktop', 'cursor', 'vscode', 'windsurf'];

export interface ConfigSource {
  client: ClientKind;
  path: string;
  /** `user` files hold every project's servers; `project` files sit in the working tree. */
  scope: 'user' | 'project';
}

export interface ConfiguredServer {
  /** The pin identity, a slug: the config key when it is one, otherwise derived from it. */
  id: string;
  /** The key under which the client lists this server. */
  key: string;
  client: ClientKind;
  source: string;
  scope: 'user' | 'project';
  ref: McpServerRef;
  /** Remote servers: headers the client would send (may hold credentials; never printed). */
  headers?: Record<string, string>;
  /** The client already starts this server through `warden-mcp wrap`. */
  wrapped: boolean;
  /** Why this entry cannot be scanned. A skipped entry is still listed, never silently dropped. */
  skipped?: string;
}

export interface DiscoveryEnv {
  home: string;
  cwd: string;
  platform: NodeJS.Platform;
  env: Record<string, string | undefined>;
}

/** Every file a known client reads, whether or not it exists. */
export function knownConfigSources(d: DiscoveryEnv): ConfigSource[] {
  const appData = d.env.APPDATA ?? join(d.home, 'AppData', 'Roaming');
  const xdg = d.env.XDG_CONFIG_HOME ?? join(d.home, '.config');
  const appSupport = (app: string) => d.platform === 'darwin' ? join(d.home, 'Library', 'Application Support', app)
    : d.platform === 'win32' ? join(appData, app) : join(xdg, app);
  return [
    { client: 'claude-code', scope: 'project', path: join(d.cwd, '.mcp.json') },
    { client: 'claude-code', scope: 'user', path: join(d.home, '.claude.json') },
    { client: 'claude-desktop', scope: 'user', path: join(appSupport('Claude'), 'claude_desktop_config.json') },
    { client: 'cursor', scope: 'project', path: join(d.cwd, '.cursor', 'mcp.json') },
    { client: 'cursor', scope: 'user', path: join(d.home, '.cursor', 'mcp.json') },
    { client: 'vscode', scope: 'project', path: join(d.cwd, '.vscode', 'mcp.json') },
    { client: 'vscode', scope: 'user', path: join(appSupport('Code'), 'User', 'mcp.json') },
    { client: 'windsurf', scope: 'user', path: join(d.home, '.codeium', 'windsurf', 'mcp_config.json') },
  ];
}

/** Which client a file given on the command line belongs to, from its name and path. */
export function guessClient(path: string): ClientKind {
  const name = basename(path), norm = path.replace(/\\/g, '/');
  if (name === '.mcp.json' || name === '.claude.json') return 'claude-code';
  if (name === 'claude_desktop_config.json') return 'claude-desktop';
  if (name === 'mcp_config.json' || norm.includes('/windsurf/')) return 'windsurf';
  if (norm.includes('/.cursor/')) return 'cursor';
  if (norm.includes('/.vscode/') || norm.includes('/Code/User/')) return 'vscode';
  return 'file';
}

const SLUG = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

/** A pin id from a config key: the key itself when it is a slug, else a slug made from it. */
export function pinIdFor(key: string): string {
  if (SLUG.test(key)) return key;
  const slug = key.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^[^a-zA-Z0-9]+/, '').slice(0, 128);
  return SLUG.test(slug) ? slug : 'server-' + createHash('sha256').update(key).digest('hex').slice(0, 16);
}

/**
 * Strip `//` and `/* *\/` comments and trailing commas, outside strings. VS Code's
 * `mcp.json` is JSONC; the others are plain JSON, for which this is a no-op.
 */
export function stripJsonc(text: string): string {
  // Two string-aware passes: comments first, so a trailing comma before a comment is still seen.
  const scan = (input: string, onChar: (c: string, i: number, out: string[]) => number): string => {
    const out: string[] = [];
    let i = 0;
    while (i < input.length) {
      if (input[i] === '"') {
        let j = i + 1;
        while (j < input.length && input[j] !== '"') { if (input[j] === '\\') j++; j++; }
        out.push(input.slice(i, j + 1)); i = j + 1; continue;
      }
      i = onChar(input[i]!, i, out);
    }
    return out.join('');
  };
  const noComments = scan(text, (c, i, out) => {
    if (c === '/' && text[i + 1] === '/') { let j = i; while (j < text.length && text[j] !== '\n') j++; return j; }
    if (c === '/' && text[i + 1] === '*') { const end = text.indexOf('*/', i + 2); return end < 0 ? text.length : end + 2; }
    out.push(c); return i + 1;
  });
  return scan(noComments, (c, i, out) => {
    if (c === ',') {
      let j = i + 1;
      while (j < noComments.length && /\s/.test(noComments[j]!)) j++;
      if (noComments[j] === '}' || noComments[j] === ']') return i + 1;
    }
    out.push(c); return i + 1;
  });
}

/**
 * If a config entry starts a server through `warden-mcp wrap`, return the server
 * behind it, so `scan` vets the real program and the same pin the proxy uses.
 */
export function unwrapWarden(command: string, args: readonly string[]): { id?: string; command: string; args: string[] } | undefined {
  const base = basename(command).toLowerCase();
  let rest: readonly string[] | undefined;
  if (base === 'warden-mcp' || base === 'warden-mcp.cmd') rest = args;
  else if ((base === 'node' || base === 'nodejs' || base === 'node.exe') && args[0] && /mcp-server\.js$/.test(args[0])) rest = args.slice(1);
  else if (['npx', 'npx.cmd', 'bunx', 'pnpx', 'pnpm', 'npm'].includes(base)) {
    const at = args.findIndex(a => /^@aimarket\/warden(@[^\s]*)?$/.test(a));
    if (at >= 0) rest = args.slice(at + 1);
  }
  if (!rest || rest[0] !== 'wrap') return undefined;
  const dash = rest.indexOf('--');
  if (dash < 0 || !rest[dash + 1]) return undefined;
  const idAt = rest.indexOf('--id');
  const id = idAt > 0 && idAt < dash ? rest[idAt + 1] : undefined;
  return { id, command: rest[dash + 1]!, args: [...rest.slice(dash + 2)] };
}

function substitute(value: string, d: DiscoveryEnv): string {
  return value
    .replace(/\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, name: string) => d.env[name] ?? '')
    .replace(/\$\{workspaceFolder\}/g, d.cwd)
    .replace(/\$\{userHome\}/g, d.home);
}

function stringMap(value: unknown, d: DiscoveryEnv): Record<string, string> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) if (v !== undefined && v !== null) out[k] = substitute(String(v), d);
  return out;
}

/** Parse one client file into the servers it starts. Throws on a file that is not JSON. */
export function parseConfigText(text: string, source: ConfigSource, d: DiscoveryEnv): ConfiguredServer[] {
  let root: unknown;
  try { root = JSON.parse(stripJsonc(text)); }
  catch (err) { throw new Error(`${source.path}: not JSON (${err instanceof Error ? err.message : String(err)})`); }
  if (!root || typeof root !== 'object' || Array.isArray(root)) throw new Error(`${source.path}: top level is not an object`);
  const r = root as Record<string, unknown>;
  const maps: Array<Record<string, unknown>> = [];
  const pick = (v: unknown) => { if (v && typeof v === 'object' && !Array.isArray(v)) maps.push(v as Record<string, unknown>); };
  if (source.client === 'vscode') { pick(r.servers); pick(r.mcpServers); }
  else {
    pick(r.mcpServers);
    if (source.client === 'file') pick(r.servers);
    if (source.client === 'claude-code' && source.scope === 'user' && r.projects && typeof r.projects === 'object') {
      // ~/.claude.json keeps every project's local-scope servers; only this project's start here.
      const projects = r.projects as Record<string, unknown>;
      for (const key of new Set([d.cwd, resolve(d.cwd)])) {
        const p = projects[key];
        if (p && typeof p === 'object') pick((p as Record<string, unknown>).mcpServers);
      }
    }
  }
  const servers: ConfiguredServer[] = [];
  for (const map of maps) {
    for (const [key, raw] of Object.entries(map)) {
      const skip = (reason: string): ConfiguredServer => ({ id: pinIdFor(key), key, client: source.client, source: source.path, scope: source.scope,
        ref: { id: pinIdFor(key), name: key, transport: 'stdio' }, wrapped: false, skipped: reason });
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) { servers.push(skip('entry is not an object')); continue; }
      const e = raw as Record<string, unknown>;
      if (e.disabled === true) { servers.push(skip('disabled in the client config')); continue; }
      const texts = JSON.stringify([e.command, e.args, e.url, e.serverUrl, e.headers, e.env]);
      if (texts.includes('${input:')) { servers.push(skip('needs an input value the client prompts for')); continue; }
      const type = typeof e.type === 'string' ? e.type.toLowerCase() : undefined;
      const url = typeof e.url === 'string' ? e.url : typeof e.serverUrl === 'string' ? e.serverUrl : undefined;
      if (url) {
        const transport = type === 'sse' ? 'sse' : 'http';
        const id = pinIdFor(key);
        servers.push({ id, key, client: source.client, source: source.path, scope: source.scope, wrapped: false,
          ref: { id, name: key, transport, url: substitute(url, d) }, headers: stringMap(e.headers, d) });
        continue;
      }
      if (typeof e.command !== 'string' || !e.command) { servers.push(skip('no command or url')); continue; }
      let command = substitute(e.command, d);
      let args = Array.isArray(e.args) ? e.args.map(a => substitute(String(a), d)) : [];
      const env = stringMap(e.env, d);
      const inner = unwrapWarden(command, args);
      let id = pinIdFor(key);
      if (inner) {
        command = inner.command; args = inner.args;
        // The id `wrap` itself uses, so its pins apply: --id when given, else its hash of the launch.
        id = inner.id ?? createHash('sha256').update(JSON.stringify([command, args])).digest('hex');
      }
      servers.push({ id, key, client: source.client, source: source.path, scope: source.scope, wrapped: !!inner,
        ref: { id, name: inner ? id : key, transport: 'stdio', command, args, ...(env ? { env } : {}) } });
    }
  }
  return servers;
}

export interface SourceResult { source: ConfigSource; servers: ConfiguredServer[]; error?: string }

/**
 * Read the given files, or every known client file that exists. A file that
 * cannot be parsed is reported, not skipped: a config the client cannot read is
 * not a config the client starts servers from, but the scan should say so.
 */
export async function discoverServers(paths: readonly string[] | undefined, d: DiscoveryEnv, clients?: readonly ClientKind[]): Promise<SourceResult[]> {
  const sources: ConfigSource[] = paths?.length
    ? paths.map(p => ({ client: guessClient(p), scope: 'project' as const, path: resolve(d.cwd, p) }))
    : knownConfigSources(d).filter(s => existsSync(s.path) && (!clients || clients.includes(s.client)));
  const results: SourceResult[] = [];
  for (const source of sources) {
    try { results.push({ source, servers: parseConfigText(await readFile(source.path, 'utf8'), source, d) }); }
    catch (err) { results.push({ source, servers: [], error: err instanceof Error ? err.message : String(err) }); }
  }
  return results;
}
