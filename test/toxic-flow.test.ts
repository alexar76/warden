import { describe, it, expect } from 'vitest';
import { toolCapabilities, toxicFlows, words, flowSentence, boundCapabilities } from '../src/toxic-flow.js';
import { pinToolsHash, serverIdentityHash } from '../src/pinning.js';
import type { ToolDef } from '../src/types.js';

const t = (name: string, ...params: string[]): ToolDef => ({ name, description: '', inputSchema: { type: 'object', properties: Object.fromEntries(params.map(p => [p, { type: 'string' }])) } });
const caps = (tool: ToolDef) => [...toolCapabilities(tool)].sort();

describe('toxic flows: capabilities from names and parameters', () => {
  it('splits identifiers into words', () => {
    expect(words('searchFiles')).toEqual(['search', 'files']);
    expect(words('get-library-docs')).toEqual(['get', 'library', 'docs']);
    expect(words('slack_post_message')).toEqual(['slack', 'post', 'message']);
    expect(words('HTTPRequest')).toEqual(['http', 'request']);
  });

  it('reads real servers the way a reviewer would', () => {
    // @modelcontextprotocol/server-filesystem
    expect(caps(t('read_file', 'path'))).toEqual(['private']);
    expect(caps(t('list_directory', 'path'))).toEqual(['private']);
    expect(caps(t('write_file', 'path', 'content'))).toEqual([]);
    expect(caps(t('move_file', 'source', 'destination'))).toEqual([]);
    // mcp-server-fetch
    expect(caps(t('fetch', 'url', 'max_length'))).toEqual(['outbound', 'untrusted']);
    // github
    expect(caps(t('get_issue', 'owner', 'repo', 'issue_number'))).toEqual(['private', 'untrusted']);
    expect(caps(t('create_issue', 'owner', 'repo', 'title', 'body'))).toEqual(['outbound']);
    expect(caps(t('add_issue_comment', 'owner', 'repo', 'issue_number', 'body'))).toEqual(['outbound']);
    expect(caps(t('get_comment', 'id'))).toEqual(['untrusted']);
    // gmail / slack
    expect(caps(t('read_email', 'messageId'))).toEqual(['private', 'untrusted']);
    expect(caps(t('send_email', 'to', 'subject', 'body'))).toEqual(['outbound']);
    expect(caps(t('slack_post_message', 'channel_id', 'text'))).toEqual(['outbound']);
    expect(caps(t('slack_get_channel_history', 'channel_id'))).toContain('untrusted');
    // browsers
    expect(caps(t('browser_navigate', 'url'))).toEqual(['outbound', 'untrusted']);
    expect(caps(t('browser_snapshot'))).toEqual(['untrusted']);
    // nothing to say about these
    expect(caps(t('get-library-docs', 'context7CompatibleLibraryID'))).toEqual([]);
    expect(caps(t('sequentialthinking', 'thought'))).toEqual([]);
    expect(caps(t('get_current_time', 'timezone'))).toEqual([]);
    expect(caps(t('create_entities', 'entities'))).toEqual([]);
  });
});

describe('toxic flows: per client', () => {
  const fs = [t('read_file', 'path'), t('list_directory', 'path')];
  const fetch = [t('fetch', 'url')];
  const memory = [t('read_graph'), t('create_entities', 'entities')];
  const gmail = [t('read_email', 'messageId'), t('send_email', 'to', 'subject', 'body')];

  it('reports the trifecta across servers, per client, and not where a leg is missing', () => {
    const flows = toxicFlows([
      { client: 'claude-code', key: 'filesystem', tools: fs },
      { client: 'claude-code', key: 'fetch', tools: fetch },
      { client: 'cursor', key: 'memory', tools: memory },
      { client: 'cursor', key: 'fetch', tools: fetch },
      { client: 'vscode', key: 'gmail', tools: gmail },
    ].map(s => ({ ...s, capabilities: Object.fromEntries(s.tools.map(t => [t.name, [...toolCapabilities(t)]])) })));
    expect(flows.map(f => [f.client, f.servers])).toEqual([['claude-code', 2], ['cursor', 2], ['vscode', 1]]);
    const cc = flows[0]!;
    expect(cc.private.map(x => `${x.server}.${x.tool}`)).toEqual(['filesystem.read_file', 'filesystem.list_directory']);
    expect(cc.outbound).toEqual([{ server: 'fetch', tool: 'fetch' }]);
    expect(flowSentence(cc, x => `${x.server}.${x.tool}`)).toMatch(/^claude-code can read private data \(filesystem\.read_file, filesystem\.list_directory\), take in text from outside \(fetch\.fetch\) and send data out \(fetch\.fetch\)/);
    expect(toxicFlows([{ client: 'claude-code', key: 'filesystem', tools: fs, capabilities: Object.fromEntries(fs.map(t => [t.name, ['private' as const]])) }, { client: 'claude-code', key: 'memory', tools: memory, capabilities: Object.fromEntries(memory.map(t => [t.name, []])) }])).toEqual([]);
    expect(toxicFlows([{ client: 'x', key: 'empty', tools: [] }, { client: 'x', key: 'none' }])).toEqual([]);
  });
});


describe('operator-bound, language-independent capabilities', () => {
  const server = { id: 'bound', name: 'bound', transport: 'stdio' as const, command: 'node', args: ['fixture'] };
  const tools = [t('прочитать_файл', 'путь')];
  const binding = () => ({ serverId: server.id, identityHash: serverIdentityHash(server), toolsHash: pinToolsHash(tools), tools: { прочитать_файл: ['private' as const] } });
  it('requires unchanged identity and all definitions', () => {
    expect(boundCapabilities(server, tools, [binding()])).toEqual(binding().tools);
    expect(boundCapabilities({ ...server, args: ['different'] }, tools, [binding()])).toBeUndefined();
    expect(boundCapabilities(server, [{ ...tools[0]!, description: 'changed' }], [binding()])).toBeUndefined();
    expect(boundCapabilities(server, tools, [{ ...binding(), tools: {} }])).toBeUndefined();
    expect(boundCapabilities(server, tools, [binding(), binding()])).toBeUndefined();
  });
  it('never interprets an unknown identifier or self-declared capability as safe', () => {
    for (const name of ['读取文件', 'прочитать_файл', 'résumer', 'xyz123']) {
      const flows = toxicFlows([{ client: 'c', key: 's', tools: [{ ...t(name), capabilities: [] }] }]);
      expect(flows[0]?.certainty).toBe('possible');
      expect(flowSentence(flows[0]!, x => x.tool)).toContain('unknown');
      expect(toxicFlows([{ client: 'c', key: 's', tools: [t(name)], capabilities: { [name]: [] } }])).toEqual([]);
    }
  });
});
