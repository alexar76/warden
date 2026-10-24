/** Flow guard: the policy, per-session state and decision types every part shares. */
import type { ScreenView } from './flow-guard-screen.js';

export type FlowLabel = 'private' | 'untrusted' | 'outbound' | 'destructive';
export type FlowMode = 'ask' | 'deny' | 'audit' | 'off';
/** When the Stop hook tells the user that an answer drew on outside text. */
export type AnswerNote = 'always' | 'instruction' | 'off';

export interface GuiActionRule {
  /** Exact MCP tool name; no globs. */
  tool: string;
  action: 'click' | 'type' | 'key';
  target: { role: string; accessibilityId: string };
  /** At least one scope is required; both, when present, must match. */
  context: { origin?: string; application?: string };
  /** One supported navigation chord, required for key rules. */
  keys?: string;
  /** Required for type rules, measured in UTF-16 code units. */
  maxTextLength?: number;
}
export interface GuiPolicy {
  mode: 'strict' | 'policy';
  maxSnapshotAgeMs: number;
  allow: GuiActionRule[];
  /** Parser diagnostic, not a configurable field. */
  invalid?: true;
}

export interface PublicRequestRule { tool: string; requestSha256: string }
export interface CredentialEgressPolicy { allow: PublicRequestRule[]; invalid?: true }
export interface TaskAdapterPolicy {
  mode: 'strict' | 'capabilities' | 'review';
  /** Operator-controlled MCP server name, bound to WARDEN's built-in `task` command. */
  server: string;
  /** Pins <state dir>/task-manifest.json, never a page-supplied manifest. */
  manifestSha256: string;
  invalid?: true;
}
export interface FlowPolicy {
  mode: FlowMode;
  /** Tool-name globs → the labels an operator assigns; replaces the built-in guess for that tool. */
  labels: Record<string, FlowLabel[]>;
  /** Hosts whose content does not taint the session (docs you trust). `*.example.com` covers subdomains. */
  trustedSources: string[];
  /** Hosts an outbound call may reach in a tainted session without asking. Fingerprint checks and the credential boundary still apply. */
  allowedDestinations: string[];
  /** Treat every local file the agent reads as outside text (strict). Default: only foreign paths. */
  taintLocalFiles: boolean;
  /** Tool-name globs → argument names whose values are destinations or targets (recipient, file id). */
  destinationArgs: Record<string, string[]>;
  /** Explicitly trusted, read-only contact lookup tools. Results must contain structured name/email records. */
  contactTools?: string[];
  /** Stop hook: name the outside text a turn read (always), only text that addressed the model (instruction), or stay silent. */
  answerNote: AnswerNote;
  /** Legacy schema, parsed for migration only. Untrusted GUI metadata never grants permission. */
  gui?: GuiPolicy;
  /** Reviewed exact public requests, each usable once per session after a credential read. */
  credentialEgress?: CredentialEgressPolicy;
  taskAdapter?: TaskAdapterPolicy;
}

export interface FlowSource { tool: string; src: string; at: string; /** The text addressed the model as if instructing it. */ hint?: boolean; /** The user's prompt count when it was read. */ turn?: number }
/** The last characters each argument sent out this session, so a value split over several calls is seen whole. */
export interface OutTail { t: string; a: string }
export interface FragmentRecord { group: string; hash: string; offset: number; size?: number; edge?: true }
export interface FlowState {
  v: 1;
  untrusted: FlowSource[];
  private: Array<FlowSource & { secret: boolean }>;
  notified: boolean;
  /** Fingerprint store reached its cap: later private reads are not fingerprinted. */
  full: boolean;
  /** What the user typed this session (normalized, capped): a destination named here is the user's choice. */
  intent?: string[];
  /** The same, lower-cased with spacing kept, for whole-word matches of short names and numbers. */
  intentRaw?: string[];
  /** Addresses resolved by explicitly trusted contact tools, bound to full display names. */
  resolved?: Array<{ v: string; names: string[] }>;
  resolvedVersion?: 2;
  /** Per argument name: the tail of what outbound calls carried after outside text (see OutTail). */
  tails?: Record<string, OutTail>;
  /** Hash-only short-fragment index and observations, shared by every proxy in this session. */
  fragments?: { v: 1 | 2; index: FragmentRecord[]; seen: FragmentRecord[]; full?: true };
  /** How many prompts the user has sent: the Stop hook names only outside text read in the latest turn. */
  turn?: number;
  /** MCP tools seen without an operator label, with the labels the guard guessed (`warden-mcp flow-labels`). */
  unlabeled?: Record<string, FlowLabel[]>;
  /** Per MCP server: what its latest screen result showed, so a click is judged by its target (see ScreenView). */
  screens?: Record<string, ScreenView>;
  /** A forwarded input/paste may have populated an outbound form. Never reset within the session. */
  guiInputSeen?: true;
  /** Sticky even when the bounded private-source history rotates. */
  credentialRead?: true;
  /** Exact public-request grants already consumed; never reset by prompts. */
  credentialGrants?: string[];
}

export interface Classified {
  labels: Set<FlowLabel>;
  /** Hosts named in the call (URLs, ssh/scp targets). */
  hosts: string[];
  /** For results: a short description of where the text came from. */
  src: string;
  /** Private read of a credential path. */
  secret: boolean;
  /** The call writes WARDEN's policy/state or Claude Code's hook/MCP settings. */
  protectedTouch: boolean;
  /** Shell code that is not a small literal read-only command. Destination exemptions never apply. */
  opaqueShell?: boolean;
  /** An MCP tool without an operator label: its labels are the guard's guess. */
  guessed?: boolean;
}

export interface FlowDecision { permissionDecision: 'ask' | 'deny'; permissionDecisionReason: string }
/** Set by the integration, never by tool arguments. A proxy cannot display an approval dialog itself; `elicit` is
 *  `wrap` asking through the client's own form (MCP elicitation), whose answer it records with flowApproval. */
export type FlowPresentation = 'hook' | 'refuse' | 'audit' | 'elicit';
