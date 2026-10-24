/** Server-side CAS for a trusted, server-owned surface. Not a lock around remote OS input.
 * All mutations, including handler/recipient/focus changes, must pass through replace/commit.
 * apply must commit synchronously against the resolved target in this same authority;
 * enqueueing a coordinate click or awaiting another process does NOT implement this contract. */
import { randomBytes } from 'node:crypto';
import { canonicalizeRfc8785 } from './jcs.js';
import { screenObservation, screenResponseEvidence } from './flow-guard.js';

export const ATOMIC_SCREEN_PROTOCOL = 'warden.screen.atomic.v1';
export const ATOMIC_SCREEN_PREPARE = 'warden/screen/prepare';
export const ATOMIC_SCREEN_COMMIT = 'warden/screen/commit';
export const ATOMIC_SCREEN_CANCEL = 'warden/screen/cancel';
const MAX_AGE = 300_000, MAX_TICKETS = 256;
const opaque = () => randomBytes(32).toString('hex');
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const toolName = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,99}$/.test(v);
function copy<T>(v: T, max = 1_048_576): T {
  const text = canonicalizeRfc8785(v);
  if (Buffer.byteLength(text) > max) throw new Error('Atomic screen value exceeds limit');
  // These bytes were just serialized by our canonicalizer (no duplicate keys,
  // cycles, non-JSON fields or non-finite values). Geometry may contain fractions;
  // the separate AWR integer-only wire parser is not appropriate here.
  return JSON.parse(text) as T;
}
export interface AtomicScreenAction { name: string; arguments: Record<string, unknown> }
export interface AtomicScreenExpectation { revision: string; stamp: string }
export interface AtomicScreenPrepared extends AtomicScreenExpectation {
  protocol: typeof ATOMIC_SCREEN_PROTOCOL; ticket: string; expiresAt: number; observation: Record<string, unknown>;
}
export type AtomicScreenReceipt =
  | { protocol: typeof ATOMIC_SCREEN_PROTOCOL; status: 'refused'; reason: 'stale' | 'expired' | 'unknown' | 'mismatch' | 'unavailable' }
  | { protocol: typeof ATOMIC_SCREEN_PROTOCOL; status: 'committed'; revisionBefore: string; revisionAfter: string; stamp: string; result: Record<string, unknown> };
export function atomicScreenAction(value: unknown): AtomicScreenAction {
  const action = copy(value, 65_536);
  if (!exact(action, ['name', 'arguments']) || !toolName(action.name) || !record(action.arguments)) throw new Error('Invalid atomic screen action');
  return action as unknown as AtomicScreenAction;
}
export function atomicScreenPrepared(value: unknown, now = Date.now()): AtomicScreenPrepared {
  const v = copy(value);
  if (!exact(v, ['protocol', 'ticket', 'revision', 'stamp', 'expiresAt', 'observation']) || v.protocol !== ATOMIC_SCREEN_PROTOCOL ||
    !hex(v.ticket) || !hex(v.revision) || !hex(v.stamp) || !Number.isSafeInteger(v.expiresAt) || (v.expiresAt as number) <= now ||
    (v.expiresAt as number) > now + MAX_AGE || !record(v.observation)) throw new Error('Invalid or expired atomic screen preparation');
  return v as unknown as AtomicScreenPrepared;
}
export function atomicScreenReceipt(value: unknown, expected: AtomicScreenExpectation): AtomicScreenReceipt {
  const v = copy(value, 2_097_152);
  if (exact(v, ['protocol', 'status', 'reason']) && v.protocol === ATOMIC_SCREEN_PROTOCOL && v.status === 'refused' &&
    ['stale', 'expired', 'unknown', 'mismatch', 'unavailable'].includes(v.reason as string)) return v as unknown as AtomicScreenReceipt;
  if (!exact(v, ['protocol', 'status', 'revisionBefore', 'revisionAfter', 'stamp', 'result']) || v.protocol !== ATOMIC_SCREEN_PROTOCOL || v.status !== 'committed' ||
    v.revisionBefore !== expected.revision || v.stamp !== expected.stamp || !hex(v.revisionAfter) || v.revisionAfter === v.revisionBefore || !record(v.result)) throw new Error('Invalid atomic screen receipt; execution is uncertain');
  return v as unknown as AtomicScreenReceipt;
}

/** Single authority for a surface, shared by every connection. Restart invalidates all tickets.
 * The callback is trusted backend code, not model/page code. An async/remote click backend is unsupported. */
export class AtomicScreenServer {
  private revision = opaque();
  private snapshot: Record<string, unknown>;
  private busy = false;
  private poisoned = false;
  private readonly tickets = new Map<string, Omit<AtomicScreenPrepared, 'observation'> & { action: AtomicScreenAction; deadline: bigint }>();
  private readonly actions: Set<string>;
  private readonly observation: AtomicScreenAction;
  constructor(options: {
    observation: AtomicScreenAction; actions: string[]; snapshot: Record<string, unknown>;
    apply: (action: AtomicScreenAction, target: string) => { result: Record<string, unknown>; snapshot: Record<string, unknown> };
  }) {
    this.observation = atomicScreenAction(options.observation);
    if (!screenObservation(`mcp__atomic__${this.observation.name}`, this.observation.arguments) || !options.actions.length ||
      options.actions.length > 64 || new Set(options.actions).size !== options.actions.length || options.actions.some(n => !toolName(n)) ||
      typeof options.apply !== 'function' || ['AsyncFunction', 'GeneratorFunction', 'AsyncGeneratorFunction'].includes(options.apply.constructor.name)) throw new Error('Unsupported atomic surface backend');
    this.actions = new Set(options.actions);
    this.apply = options.apply;
    this.snapshot = copy(options.snapshot);
  }
  private readonly apply: (action: AtomicScreenAction, target: string) => { result: Record<string, unknown>; snapshot: Record<string, unknown> };
  read(): Record<string, unknown> {
    if (this.busy || this.poisoned) throw new Error('Atomic surface unavailable');
    return copy(this.snapshot);
  }
  /** Call for EVERY mutation, even an invisible handler change or A -> B -> A transition. */
  replace(snapshot: Record<string, unknown>): void {
    if (this.busy) throw new Error('Atomic surface transaction already running');
    // Invalidate BEFORE parsing: a backend reporting an unrepresentable new state
    // must never leave an old approval usable against its changed real state.
    this.revision = opaque(); this.poisoned = true;
    this.snapshot = copy(snapshot); this.poisoned = false;
  }
  prepare(params: unknown): AtomicScreenPrepared {
    if (this.busy || this.poisoned) throw new Error('Atomic surface unavailable');
    const p = copy(params, 65_536);
    if (!exact(p, ['protocol', 'observation', 'action']) || p.protocol !== ATOMIC_SCREEN_PROTOCOL || canonicalizeRfc8785(p.observation) !== canonicalizeRfc8785(this.observation)) throw new Error('Invalid atomic preparation');
    const action = atomicScreenAction(p.action);
    if (!this.actions.has(action.name)) throw new Error('Unsupported atomic action');
    const evidence = screenResponseEvidence(`mcp__atomic__${action.name}`, action.arguments, `mcp__atomic__${this.observation.name}`, this.observation.arguments, this.snapshot);
    if (!evidence) throw new Error('Atomic target is ambiguous or unsupported');
    const now = Date.now(), monotonic = process.hrtime.bigint();
    for (const [id, ticket] of this.tickets) if (ticket.expiresAt <= now || ticket.deadline <= monotonic) this.tickets.delete(id);
    if (this.tickets.size >= MAX_TICKETS) throw new Error('Too many pending atomic approvals');
    const prepared: AtomicScreenPrepared = { protocol: ATOMIC_SCREEN_PROTOCOL, ticket: opaque(), revision: this.revision, stamp: evidence.stamp, expiresAt: now + MAX_AGE, observation: copy(this.snapshot) };
    const { observation: _observation, ...binding } = prepared;
    this.tickets.set(prepared.ticket, { ...binding, action, deadline: monotonic + BigInt(MAX_AGE) * 1_000_000n });
    return copy(prepared);
  }
  cancel(params: unknown): void {
    if (!exact(params, ['protocol', 'ticket']) || params.protocol !== ATOMIC_SCREEN_PROTOCOL || !hex(params.ticket)) throw new Error('Invalid atomic cancellation');
    this.tickets.delete(params.ticket);
  }
  commit(params: unknown): AtomicScreenReceipt {
    const p = copy(params, 65_536);
    if (!exact(p, ['protocol', 'ticket', 'expected', 'action']) || p.protocol !== ATOMIC_SCREEN_PROTOCOL || !hex(p.ticket) || !exact(p.expected, ['revision', 'stamp']) ||
      !hex(p.expected.revision) || !hex(p.expected.stamp)) throw new Error('Invalid atomic commit');
    const action = atomicScreenAction(p.action), prepared = this.tickets.get(p.ticket);
    const refuse = (reason: Extract<AtomicScreenReceipt, { status: 'refused' }>['reason']): AtomicScreenReceipt => ({ protocol: ATOMIC_SCREEN_PROTOCOL, status: 'refused', reason });
    if (!prepared) return refuse('unknown');
    this.tickets.delete(p.ticket); // One attempt, before any possible effect, even on mismatch/failure.
    if (this.busy || this.poisoned) return refuse('unavailable');
    const expired = () => {
      const now = Date.now();
      return prepared.expiresAt <= now || prepared.expiresAt > now + MAX_AGE || prepared.deadline <= process.hrtime.bigint();
    };
    if (expired()) return refuse('expired');
    if (canonicalizeRfc8785(action) !== canonicalizeRfc8785(prepared.action) || p.expected.revision !== prepared.revision || p.expected.stamp !== prepared.stamp) return refuse('mismatch');
    if (this.revision !== prepared.revision) return refuse('stale');
    const evidence = screenResponseEvidence(`mcp__atomic__${action.name}`, action.arguments, `mcp__atomic__${this.observation.name}`, this.observation.arguments, this.snapshot);
    if (!evidence || evidence.stamp !== prepared.stamp) return refuse('stale');
    const boundAction = copy(action);
    if (expired()) return refuse('expired');
    // No await/event-loop handoff between comparison and exact-target synchronous commit.
    this.busy = true;
    try {
      const effect = this.apply(boundAction, evidence.target);
      if (!exact(effect, ['result', 'snapshot']) || !record(effect.result) || !record(effect.snapshot)) throw new Error('Invalid synchronous atomic effect');
      const result = copy(effect.result), snapshot = copy(effect.snapshot);
      this.snapshot = snapshot; this.revision = opaque();
      return { protocol: ATOMIC_SCREEN_PROTOCOL, status: 'committed', revisionBefore: prepared.revision, revisionAfter: this.revision, stamp: prepared.stamp, result };
    } catch {
      this.poisoned = true; this.revision = opaque();
      throw new Error('Atomic effect failed or is uncertain; reconcile the surface before authorizing again');
    } finally { this.busy = false; }
  }
}
