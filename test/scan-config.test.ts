import { describe, it, expect } from 'vitest';
import { parseConfigText, stripJsonc, unwrapWarden, pinIdFor, guessClient, knownConfigSources, type ConfigSource, type DiscoveryEnv } from '../src/scan-config.js';

const d: DiscoveryEnv = { home: '/home/u', cwd: '/work/proj', platform: 'linux', env: { TOKEN: 'abc' } };
const src = (client: ConfigSource['client'], scope: ConfigSource['scope'] = 'project', path = '/work/proj/.mcp.json'): ConfigSource => ({ client, scope, path });

describe('client config discovery', () => {
  it('knows every client file, per platform', () => {
    const mac = knownConfigSources({ ...d, platform: 'darwin' }).map(s => s.path);
    expect(mac).toContain('/home/u/Library/Application Support/Claude/claude_desktop_config.json');
    expect(mac).toContain('/home/u/Library/Application Support/Code/User/mcp.json');
    const linux = knownConfigSources(d).map(s => s.path);
    expect(linux).toContain('/home/u/.config/Claude/claude_desktop_config.json');
    expect(linux).toEqual(expect.arrayContaining(['/work/proj/.mcp.json', '/home/u/.claude.json', '/work/proj/.cursor/mcp.json', '/home/u/.cursor/mcp.json', '/work/proj/.vscode/mcp.json', '/home/u/.codeium/windsurf/mcp_config.json']));
    const win = knownConfigSources({ ...d, platform: 'win32', env: { APPDATA: 'C:/Users/u/AppData/Roaming' } }).map(s => s.path);
    expect(win.some(p => p.includes('C:/Users/u/AppData/Roaming') && p.endsWith('claude_desktop_config.json'))).toBe(true);
  });

  it('guesses the client of a file given on the command line', () => {
    expect(guessClient('/x/.mcp.json')).toBe('claude-code');
    expect(guessClient('/x/claude_desktop_config.json')).toBe('claude-desktop');
    expect(guessClient('/x/.cursor/mcp.json')).toBe('cursor');
    expect(guessClient('/x/.vscode/mcp.json')).toBe('vscode');
    expect(guessClient('/x/.codeium/windsurf/mcp_config.json')).toBe('windsurf');
    expect(guessClient('/x/servers.json')).toBe('file');
  });

  it('reads stdio, http and sse entries, substitutes variables and lists what it cannot scan', () => {
    const servers = parseConfigText(JSON.stringify({ mcpServers: {
      fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '${workspaceFolder}'], env: { KEY: '${env:TOKEN}' } },
      remote: { type: 'http', url: 'https://example.com/mcp', headers: { Authorization: 'Bearer ${env:TOKEN}' } },
      legacy: { type: 'sse', url: 'https://example.com/sse' },
      windsurfStyle: { serverUrl: 'https://example.com/w' },
      off: { command: 'x', disabled: true },
      prompt: { command: 'x', args: ['${input:apiKey}'] },
      bad: 'nope',
      empty: {},
    } }), src('claude-code'), d);
    const by = Object.fromEntries(servers.map(s => [s.key, s]));
    expect(by.fs!.ref).toMatchObject({ transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/work/proj'], env: { KEY: 'abc' } });
    expect(by.remote!.ref).toMatchObject({ transport: 'http', url: 'https://example.com/mcp' });
    expect(by.remote!.headers).toEqual({ Authorization: 'Bearer abc' });
    expect(by.legacy!.ref.transport).toBe('sse');
    expect(by.windsurfStyle!.ref.url).toBe('https://example.com/w');
    expect(by.off!.skipped).toMatch(/disabled/);
    expect(by.prompt!.skipped).toMatch(/input/);
    expect(by.bad!.skipped).toMatch(/not an object/);
    expect(by.empty!.skipped).toMatch(/no command or url/);
  });

  it('reads VS Code JSONC with comments and trailing commas, under "servers"', () => {
    const text = `{
      // personal servers
      "servers": {
        "a": { "type": "stdio", "command": "node", "args": ["a.js", "// not a comment",], }, /* block */
      },
    }`;
    expect(stripJsonc('{"u":"http://x//y","a":1,}')).toBe('{"u":"http://x//y","a":1}');
    const [a] = parseConfigText(text, src('vscode', 'project', '/work/proj/.vscode/mcp.json'), d);
    expect(a!.ref.args).toEqual(['a.js', '// not a comment']);
  });

  it("reads this project's entries from ~/.claude.json, not other projects'", () => {
    const text = JSON.stringify({ mcpServers: { userwide: { command: 'u' } }, projects: {
      '/work/proj': { mcpServers: { mine: { command: 'm' } } },
      '/other': { mcpServers: { theirs: { command: 't' } } },
    } });
    const keys = parseConfigText(text, src('claude-code', 'user', '/home/u/.claude.json'), d).map(s => s.key);
    expect(keys.sort()).toEqual(['mine', 'userwide']);
  });

  it('sees through warden-mcp wrap to the server it protects, with wrap\'s own pin id', () => {
    expect(unwrapWarden('npx', ['-y', '@aimarket/warden@0.9.0', 'wrap', '--id', 'fs', '--', 'npx', '-y', 'srv', '/d'])).toEqual({ id: 'fs', command: 'npx', args: ['-y', 'srv', '/d'] });
    expect(unwrapWarden('warden-mcp', ['wrap', '--', 'node', 's.js'])).toEqual({ id: undefined, command: 'node', args: ['s.js'] });
    expect(unwrapWarden('node', ['/x/dist/mcp-server.js', 'wrap', '--id', 'n', '--', 'node', 's.js'])?.id).toBe('n');
    expect(unwrapWarden('npx', ['-y', '@aimarket/warden'])).toBeUndefined();
    const [wrapped] = parseConfigText(JSON.stringify({ mcpServers: { files: { command: 'npx', args: ['-y', '@aimarket/warden', 'wrap', '--', 'node', 's.js'] } } }), src('claude-code'), d);
    expect(wrapped!.wrapped).toBe(true);
    expect(wrapped!.ref.command).toBe('node');
    expect(wrapped!.id).toMatch(/^[a-f0-9]{64}$/);   // the hash wrap derives without --id
    expect(wrapped!.ref.name).toBe(wrapped!.id);
  });

  it('derives a slug pin id from any config key', () => {
    expect(pinIdFor('github')).toBe('github');
    expect(pinIdFor('my server (dev)')).toBe('my-server-dev-');
    expect(pinIdFor('Ⅻ')).toMatch(/^server-[a-f0-9]{16}$/);
  });

  it('refuses a file that is not JSON instead of reading it as empty', () => {
    expect(() => parseConfigText('{ nope', src('claude-code'), d)).toThrow(/not JSON/);
    expect(() => parseConfigText('[]', src('claude-code'), d)).toThrow(/not an object/);
  });
});
