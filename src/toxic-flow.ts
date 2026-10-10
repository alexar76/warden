/**
 * Toxic flows: tools that are safe one by one and dangerous together.
 *
 * A client hands every server's tools to the same model. If one tool reads the
 * user's private data, one lets text from outside in (a web page, an issue, an
 * email), and one can send data out, then text arriving through the second can
 * tell the model to read with the first and send with the third — Simon
 * Willison's "lethal trifecta". No single server is at fault, so no per-server
 * verdict sees it; it is a property of the config.
 *
 * Capability decisions come from operator policy bound to the launch identity and
 * complete tool-set hash. Unbound tools remain unknown in every language. Legacy
 * identifier heuristics below are review hints only, never evidence of safety.
 */
import { pinToolsHash, serverIdentityHash } from './pinning.js';
import type { CapabilityBinding, McpServerRef } from './types.js';
import type { ToolDef } from './types.js';

export type Capability = 'private' | 'untrusted' | 'outbound';
export const CAPABILITIES: readonly Capability[] = ['private', 'untrusted', 'outbound'];

/** The words of an identifier: `searchFiles`, `read_file`, `get-issue` → search files / read file / get issue. */
export function words(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

const set = (...w: string[]) => new Set(w);
// Moving data off the machine: sending, posting, browsing to an address, or creating something others read.
const SEND = set('send', 'post', 'publish', 'tweet', 'reply', 'upload', 'share', 'notify', 'webhook', 'forward', 'sms', 'push',
  'gist', 'invite', 'transfer', 'pay', 'submit', 'broadcast', 'dispatch');
const BROWSE = set('browse', 'navigate', 'goto', 'visit', 'http', 'request', 'curl');
const WRITE = set('create', 'add', 'open', 'write', 'new', 'make', 'leave');
const PUBLIC_OBJECTS = set('issue', 'comment', 'gist', 'pr', 'pull', 'post', 'tweet', 'message', 'review', 'discussion', 'reply');
const URL_PARAMS = set('url', 'uri', 'href', 'endpoint', 'webhook', 'webhookurl', 'link');
const RECIPIENT_PARAMS = set('to', 'recipient', 'recipients', 'cc', 'bcc', 'channel', 'chatid', 'phone');
// Reading the outside world: whatever arrives was written by someone else.
const UNTRUSTED_WORDS = set('fetch', 'browse', 'navigate', 'scrape', 'crawl', 'web', 'url', 'html', 'rss', 'feed', 'website',
  'goto', 'visit', 'snapshot', 'screenshot', 'tweets', 'reddit', 'youtube', 'transcript');
const READ_VERBS = set('read', 'get', 'list', 'search', 'query', 'find', 'fetch', 'view', 'show', 'cat', 'load', 'retrieve',
  'lookup', 'describe', 'download', 'export', 'check');
const INBOUND_OBJECTS = set('email', 'emails', 'mail', 'mails', 'inbox', 'issue', 'issues', 'comment', 'comments', 'message', 'messages',
  'pr', 'prs', 'pull', 'review', 'reviews', 'ticket', 'tickets', 'thread', 'threads', 'post', 'posts', 'chat', 'chats',
  'notification', 'notifications', 'discussion', 'discussions', 'tweet', 'mentions', 'channel', 'conversation', 'conversations');
const SEARCH_ENGINES = set('google', 'bing', 'brave', 'duckduckgo', 'tavily', 'exa', 'serp', 'serper', 'perplexity', 'internet', 'online', 'web');
// The user's own data.
const PRIVATE_OBJECTS = set('file', 'files', 'directory', 'directories', 'dir', 'folder', 'note', 'notes', 'email', 'emails', 'mail',
  'inbox', 'message', 'messages', 'calendar', 'event', 'events', 'contact', 'contacts', 'repo', 'repos', 'repository', 'repositories',
  'code', 'secret', 'secrets', 'credential', 'credentials', 'env', 'database', 'db', 'table', 'tables', 'sql', 'record', 'records',
  'row', 'rows', 'memory', 'memories', 'entity', 'entities', 'graph', 'drive', 'sheet', 'sheets', 'spreadsheet', 'customer',
  'customers', 'invoice', 'invoices', 'account', 'accounts', 'wallet', 'balance', 'key', 'keys', 'photo', 'photos', 'clipboard',
  'history', 'vault', 'workspace', 'issue', 'issues', 'branch', 'commit', 'commits', 'diff', 'log', 'logs');
const PRIVATE_PARAMS = set('path', 'paths', 'filepath', 'filename', 'file', 'directory', 'dir', 'folder', 'sql', 'statement', 'repo', 'repository');
const PRIVATE_WORDS = set('sql', 'execute', 'filesystem', 'fs');

function paramNames(tool: ToolDef): string[] {
  const props = (tool.inputSchema as { properties?: unknown } | undefined)?.properties;
  return props && typeof props === 'object' && !Array.isArray(props) ? Object.keys(props).map(k => k.toLowerCase().replace(/[^a-z0-9]/g, '')) : [];
}

/** What a tool can do, read from its name and parameter names. */
export function toolCapabilities(tool: ToolDef): Set<Capability> {
  const w = words(tool.name);
  const has = (s: Set<string>) => w.some(x => s.has(x));
  const params = paramNames(tool);
  const param = (s: Set<string>) => params.some(p => s.has(p));
  const reads = has(READ_VERBS);
  const out = new Set<Capability>();
  if (has(SEND) || has(BROWSE) || (has(WRITE) && has(PUBLIC_OBJECTS)) || param(URL_PARAMS) || (!reads && param(RECIPIENT_PARAMS))) out.add('outbound');
  if (has(UNTRUSTED_WORDS) || (reads && has(INBOUND_OBJECTS)) || (w.includes('search') && has(SEARCH_ENGINES)) || param(URL_PARAMS)) out.add('untrusted');
  if ((reads && has(PRIVATE_OBJECTS)) || has(PRIVATE_WORDS) || (reads && param(PRIVATE_PARAMS))) out.add('private');
  return out;
}

/** A package cannot self-declare trusted capabilities in its schema or annotations. */
export function boundCapabilities(server: McpServerRef, tools: ToolDef[], bindings: readonly CapabilityBinding[] = []): Record<string, Capability[]> | undefined {
  const matches = bindings.filter(b => b.serverId === server.id);
  if (matches.length !== 1) return undefined;
  const b = matches[0]!;
  try {
    if (b.identityHash !== serverIdentityHash(server) || b.toolsHash !== pinToolsHash(tools)) return undefined;
    if (tools.some(t => !Object.hasOwn(b.tools, t.name))) return undefined;
    return b.tools;
  } catch { return undefined; }
}

export interface FlowTool { server: string; tool: string }
export interface ToxicFlow {
  client: string;
  certainty: 'confirmed' | 'possible';
  unknown: FlowTool[];
  private: FlowTool[];
  untrusted: FlowTool[];
  outbound: FlowTool[];
  /** How many servers the three legs span: 1 means one server carries the whole path. */
  servers: number;
}

const SHOWN = 3;

/** Per client: the three legs, if every one is present among the servers it starts. */
export function toxicFlows(servers: ReadonlyArray<{ client: string; key: string; tools?: readonly ToolDef[]; capabilities?: Record<string, Capability[]> }>): ToxicFlow[] {
  const byClient = new Map<string, Array<{ key: string; tools: readonly ToolDef[]; capabilities?: Record<string, Capability[]> }>>();
  for (const s of servers) if (s.tools?.length) {
    const list = byClient.get(s.client) ?? [];
    list.push({ key: s.key, tools: s.tools, capabilities: s.capabilities });
    byClient.set(s.client, list);
  }
  const flows: ToxicFlow[] = [];
  for (const [client, list] of byClient) {
    const legs: Record<Capability, FlowTool[]> = { private: [], untrusted: [], outbound: [] };
    const unknown: FlowTool[] = [];
    for (const s of list) for (const t of s.tools) {
      const approved = s.capabilities && Object.hasOwn(s.capabilities, t.name) ? s.capabilities[t.name] : undefined;
      if (!approved) unknown.push({ server: s.key, tool: t.name });
      // Unknown capabilities can contain every leg, whatever language the identifier uses.
      for (const cap of approved ?? CAPABILITIES) legs[cap].push({ server: s.key, tool: t.name });
    }
    if (!CAPABILITIES.every(c => legs[c].length)) continue;
    const involved = new Set([...legs.private, ...legs.untrusted, ...legs.outbound].map(t => t.server));
    flows.push({ client, certainty: unknown.length ? 'possible' : 'confirmed', unknown, private: legs.private.slice(0, SHOWN), untrusted: legs.untrusted.slice(0, SHOWN), outbound: legs.outbound.slice(0, SHOWN), servers: involved.size });
  }
  return flows;
}

export function flowSentence(f: ToxicFlow, show: (t: FlowTool) => string): string {
  const leg = (ts: FlowTool[]) => ts.map(show).join(', ');
  if (f.unknown.length) return `${f.client} has a possible private-data / untrusted-input / outbound path: capabilities of ${leg(f.unknown.slice(0, SHOWN))} are unknown. Review and bind operator capabilities to the launch identity and definitions; unrecognized names are not evidence of safety.`;
  return `${f.client} can read private data (${leg(f.private)}), take in text from outside (${leg(f.untrusted)}) and send data out (${leg(f.outbound)}). ` +
    'Text that arrives through the second can tell the model to read with the first and send with the third.';
}
