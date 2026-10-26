/** Optional host-supplied constraint evidence. No natural-language inference or permission grants. */
import { createHash } from 'node:crypto';

type Scalar = number | boolean;
interface Rule { field: string; op: 'lte' | 'gte' | 'eq'; value: Scalar }
interface Item { id: string; attributes: Record<string, Scalar> }
export interface AnswerConstraintCheck {
  schema: 'warden-answer-check/1';
  sessionId: string;
  turn: number;
  answerSha256: string;
  /** The host derives these from the real user/policy, never server-authored instructions. */
  rules: Rule[];
  /** A bounded captured record snapshot; checks are conditional on these source facts. */
  records: Item[];
  /** Explicit claims extracted by the host adapter; not an automatic semantic parser. */
  claims: { selectedId: string; eligibleIds: string[] };
}
export interface ConstraintViolation { item: number; rule: number; op: Rule['op']; limit: Scalar; actual: Scalar }
export interface ConstraintEvidence {
  status: 'absent' | 'invalid' | 'checked' | 'partial';
  factsSha256?: string;
  violations: ConstraintViolation[];
  unknownReferences: number;
  text: string;
}

const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const exact = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const scalar = (value: unknown): value is Scalar => typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= 1e12;
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/.test(value);
const field = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value) && !['constructor', 'prototype'].includes(value);
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const same = (a: Scalar, b: Scalar) => typeof a === typeof b && a === b;

/** Fixed templates + finite scalars/positions only. No names, quotes, URLs or source-authored field labels. */
export function checkAnswerConstraints(value: unknown, answer: string, sessionId: string, turn: number): ConstraintEvidence {
  const empty = (status: 'absent' | 'invalid'): ConstraintEvidence => ({ status, violations: [], unknownReferences: 0, text: status === 'invalid' ? 'WARDEN: constraint evidence is unavailable because the host check did not validate. This is not a passed check.' : '' });
  if (value === undefined) return empty('absent');
  if (!object(value) || !exact(value, ['schema', 'sessionId', 'turn', 'answerSha256', 'rules', 'records', 'claims']) || value.schema !== 'warden-answer-check/1' ||
      value.sessionId !== sessionId || !Number.isSafeInteger(value.turn) || (value.turn as number) < 1 || value.turn !== turn || value.answerSha256 !== hash(answer) ||
      !Array.isArray(value.rules) || !value.rules.length || value.rules.length > 16 || !Array.isArray(value.records) || !value.records.length || value.records.length > 256 || !object(value.claims)) return empty('invalid');
  const rules: Rule[] = [];
  for (const candidate of value.rules) {
    if (!object(candidate) || !exact(candidate, ['field', 'op', 'value']) || !field(candidate.field) || typeof candidate.op !== 'string' || !['lte', 'gte', 'eq'].includes(candidate.op) || !scalar(candidate.value) || candidate.op !== 'eq' && typeof candidate.value !== 'number') return empty('invalid');
    rules.push(candidate as unknown as Rule);
  }
  const records: Item[] = [];
  const seen = new Set<string>();
  for (const candidate of value.records) {
    if (!object(candidate) || !exact(candidate, ['id', 'attributes']) || !id(candidate.id) || seen.has(candidate.id) || !object(candidate.attributes) || Object.keys(candidate.attributes).length > 32 ||
        !Object.entries(candidate.attributes).every(([key, entry]) => field(key) && scalar(entry))) return empty('invalid');
    records.push(candidate as unknown as Item); seen.add(candidate.id);
  }
  const claims = value.claims;
  if (!exact(claims, ['selectedId', 'eligibleIds']) || !id(claims.selectedId) || !Array.isArray(claims.eligibleIds) || claims.eligibleIds.length > 128 || !claims.eligibleIds.every(id) || new Set(claims.eligibleIds).size !== claims.eligibleIds.length) return empty('invalid');
  // Stable facts identity is independent of selected claims and the generated answer.
  const factsSha256 = hash(JSON.stringify({ rules, records: records.map(record => ({ id: record.id, attributes: Object.fromEntries(Object.entries(record.attributes).sort(([a], [b]) => a.localeCompare(b))) })) }));
  const map = new Map(records.map(record => [record.id, record]));
  const referenced = [...new Set([claims.selectedId, ...claims.eligibleIds])] as string[];
  const violations: ConstraintViolation[] = [];
  let unknownReferences = 0;
  for (const itemId of referenced) {
    const record = map.get(itemId);
    if (!record) { unknownReferences++; continue; }
    for (const [index, rule] of rules.entries()) {
      if (!Object.hasOwn(record.attributes, rule.field)) { unknownReferences++; continue; }
      const actual = record.attributes[rule.field]!;
      if (rule.op !== 'eq' && typeof actual !== 'number') { unknownReferences++; continue; }
      const passes = rule.op === 'eq' ? same(actual, rule.value) : rule.op === 'lte' ? (actual as number) <= (rule.value as number) : (actual as number) >= (rule.value as number);
      if (!passes) violations.push({ item: records.indexOf(record) + 1, rule: index + 1, op: rule.op, limit: rule.value, actual });
    }
  }
  const snippets = violations.slice(0, 8).map(v => `Source snapshot record #${v.item} (1-based source-record order, not claim-list order) violates rule #${v.rule}: actual ${v.actual}; required ${v.op === 'lte' ? '<=' : v.op === 'gte' ? '>=' : '==='} ${v.limit}.`);
  const status = unknownReferences ? 'partial' : 'checked';
  const text = snippets.length ? 'WARDEN constraint evidence (conditional on the host record snapshot): ' + snippets.join(' ') + (violations.length > 8 ? ` ${violations.length - 8} more contradictions recorded.` : '') + (unknownReferences ? ' Some references or fields are unknown; this is not a complete check.' : '') : unknownReferences ? 'WARDEN: some claimed items or rule fields are unknown. Constraint checking is incomplete, not passed.' : '';
  return { status, factsSha256, violations, unknownReferences, text };
}
