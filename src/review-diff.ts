/**
 * What changed between the tool definitions a person approved and the ones a server serves now,
 * field by field, for the re-approval review.
 *
 * A pin is a hash: it says THAT something changed. A reviewer needs WHAT changed. Over four weeks
 * of HISTOR's log (snapshot 2026-10-20, 23,821 changes), 52% changed the words of a tool or
 * parameter description and 23% added or removed tools, while about one change in eight touched
 * nothing but digits or whitespace (live counters written into descriptions). A review that shows
 * two full JSON blobs for each of those trains people to approve without reading. This module
 * shows the path of every changed value, the words added and removed in text, and marks a change
 * made only of numbers. It marks; it never approves: a changed limit is also a number.
 */
import type { ToolDef } from "./types.js";

export type WordOp = ["=" | "+" | "-", string];

export interface FieldChange {
  /** Dotted path inside the tool, e.g. `description` or `inputSchema.properties.days.maximum`. */
  path: string;
  /** Absent when the value did not exist on that side. */
  before?: unknown;
  after?: unknown;
  /** For a string on both sides: the word diff. */
  words?: WordOp[];
  /** Only digits, separators or whitespace differ (a counter, a date, a limit). Still a change. */
  numbersOnly: boolean;
}

export interface ToolChange {
  tool: string;
  kind: "added" | "removed" | "changed";
  /** For `changed`: every value that differs. */
  fields: FieldChange[];
  /** For `added` / `removed`: the whole definition. */
  definition?: ToolDef;
  /** A changed tool whose every field change is numbers only. */
  numbersOnly: boolean;
}

export interface DefinitionDiff {
  changes: ToolChange[];
  added: number;
  removed: number;
  changed: number;
  /** Changed tools whose changes are numbers only. */
  numbersOnly: number;
}

const NUMERIC_TEXT = /^[\s\d.,:\-/+%]*$/;
/** Above this many token pairs the word diff falls back to "common start, common end, the middle replaced". */
const LCS_LIMIT = 4_000_000;
const MAX_FIELDS_PER_TOOL = 200;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isPrimitive(v: unknown): boolean {
  return v === null || (typeof v !== "object" && typeof v !== "function");
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function joinPath(base: string, key: string | number): string {
  if (typeof key === "number") return `${base}[${key}]`;
  const safe = /^[A-Za-z_$][\w$-]*$/.test(key) ? key : JSON.stringify(key);
  return base ? `${base}.${safe}` : safe;
}

/** Words and the spaces between them, so that joining the tokens gives the text back. */
export function tokenize(text: string): string[] {
  // A number keeps its separators (6,426 · 1.5 · 2026-10-21), so a moved counter reads as one edit.
  return text.match(/\s+|\d+(?:[.,:/-]\d+)*(?![\p{L}_])|[\p{L}\p{N}_]+|[^\s\p{L}\p{N}_]/gu) ?? [];
}

export function wordDiff(before: string, after: string): WordOp[] {
  const a = tokenize(before), b = tokenize(after);
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length, endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
  const midA = a.slice(start, endA), midB = b.slice(start, endB);
  const ops: WordOp[] = [];
  const push = (op: WordOp[0], text: string) => {
    if (!text) return;
    const last = ops[ops.length - 1];
    if (last && last[0] === op) last[1] += text;
    else ops.push([op, text]);
  };
  push("=", a.slice(0, start).join(""));
  if (midA.length * midB.length > LCS_LIMIT) {
    push("-", midA.join(""));
    push("+", midB.join(""));
  } else {
    // Longest common subsequence over the middle (after trimming the common start and end).
    const n = midA.length, m = midB.length;
    const table: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
      const row = table[i]!, next = table[i + 1]!;
      for (let j = m - 1; j >= 0; j--) {
        row[j] = midA[i] === midB[j] ? next[j + 1]! + 1 : Math.max(next[j]!, row[j + 1]!);
      }
    }
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (midA[i] === midB[j]) { push("=", midA[i]!); i++; j++; }
      else if (table[i + 1]![j]! >= table[i]![j + 1]!) { push("-", midA[i]!); i++; }
      else { push("+", midB[j]!); j++; }
    }
    while (i < n) push("-", midA[i++]!);
    while (j < m) push("+", midB[j++]!);
  }
  push("=", a.slice(endA).join(""));
  return coalesce(ops);
}

/** Text so short and plain that splitting two edits around it only makes them harder to read. */
const GLUE = /^[\s\p{P}\p{S}]{1,3}$/u;

/**
 * Join edits separated only by spaces or a stray punctuation mark into one removed and one added
 * phrase: "[-Force a new-]{+Delete all previous+} login" reads; "[-Force-]{+Delete+} [-a-]{+all+}"
 * does not. The glue appears on both sides, so the two sides still spell the old and new text.
 */
function coalesce(ops: WordOp[]): WordOp[] {
  const out: WordOp[] = [];
  let del = "", ins = "";
  const flush = () => {
    if (del) out.push(["-", del]);
    if (ins) out.push(["+", ins]);
    del = ""; ins = "";
  };
  for (let i = 0; i < ops.length; i++) {
    const [op, text] = ops[i]!;
    if (op === "-") del += text;
    else if (op === "+") ins += text;
    else if ((del || ins) && i + 1 < ops.length && GLUE.test(text)) { del += text; ins += text; }
    else { flush(); out.push(["=", text]); }
  }
  flush();
  return out;
}

function textNumbersOnly(ops: WordOp[]): boolean {
  const edits = ops.filter(op => op[0] !== "=").map(op => op[1]);
  return edits.length > 0 && edits.every(e => NUMERIC_TEXT.test(e));
}

function walk(path: string, before: unknown, after: unknown, out: FieldChange[]): void {
  if (out.length >= MAX_FIELDS_PER_TOOL || same(before, after)) return;
  if (isPlainObject(before) && isPlainObject(after)) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    for (const key of keys) {
      const p = joinPath(path, key);
      const hasB = Object.prototype.hasOwnProperty.call(before, key), hasA = Object.prototype.hasOwnProperty.call(after, key);
      if (hasB && hasA) walk(p, before[key], after[key], out);
      else if (hasB) out.push({ path: p, before: before[key], numbersOnly: false });
      else out.push({ path: p, after: after[key], numbersOnly: false });
      if (out.length >= MAX_FIELDS_PER_TOOL) return;
    }
    return;
  }
  if (Array.isArray(before) && Array.isArray(after) && !(before.every(isPrimitive) && after.every(isPrimitive))) {
    const n = Math.max(before.length, after.length);
    for (let i = 0; i < n; i++) {
      const p = joinPath(path, i);
      if (i >= before.length) out.push({ path: p, after: after[i], numbersOnly: false });
      else if (i >= after.length) out.push({ path: p, before: before[i], numbersOnly: false });
      else walk(p, before[i], after[i], out);
      if (out.length >= MAX_FIELDS_PER_TOOL) return;
    }
    return;
  }
  if (typeof before === "string" && typeof after === "string") {
    const words = wordDiff(before, after);
    out.push({ path, before, after, words, numbersOnly: textNumbersOnly(words) });
    return;
  }
  const numbersOnly = typeof before === "number" && typeof after === "number";
  out.push({ path, before, after, numbersOnly });
}

/** Field-level changes from `before` (approved) to `after` (served now), tools matched by name. */
export function diffToolDefinitions(before: readonly ToolDef[], after: readonly ToolDef[]): DefinitionDiff {
  const old = new Map(before.map(t => [t.name, t])), next = new Map(after.map(t => [t.name, t]));
  const names = [...new Set([...old.keys(), ...next.keys()])].sort();
  const changes: ToolChange[] = [];
  for (const name of names) {
    const b = old.get(name), a = next.get(name);
    if (!b && a) changes.push({ tool: name, kind: "added", fields: [], definition: a, numbersOnly: false });
    else if (b && !a) changes.push({ tool: name, kind: "removed", fields: [], definition: b, numbersOnly: false });
    else if (b && a && !same(b, a)) {
      const fields: FieldChange[] = [];
      walk("", b, a, fields);
      changes.push({ tool: name, kind: "changed", fields, numbersOnly: fields.length > 0 && fields.every(f => f.numbersOnly) });
    }
  }
  return {
    changes,
    added: changes.filter(c => c.kind === "added").length,
    removed: changes.filter(c => c.kind === "removed").length,
    changed: changes.filter(c => c.kind === "changed").length,
    numbersOnly: changes.filter(c => c.numbersOnly).length,
  };
}

function show(value: unknown, max = 400): string {
  const text = JSON.stringify(value) ?? "undefined";
  return text.length > max ? `${text.slice(0, max)}… (${text.length} chars)` : text;
}

/** The diff as review lines: `[-removed-]` and `{+added+}` inside text, `before → after` for values. */
export function formatDefinitionDiff(diff: DefinitionDiff): string[] {
  if (diff.changes.length === 0) return ["Tool definitions: unchanged."];
  const lines = [`Tool definitions: ${diff.changed} changed, ${diff.added} added, ${diff.removed} removed` +
    (diff.numbersOnly ? ` (${diff.numbersOnly} changed only in numbers: still a change, a number can be a limit)` : "")];
  for (const c of diff.changes) {
    if (c.kind === "added") { lines.push(`+ ${c.tool}  (new tool)`, `    ${show(c.definition, 4000)}`); continue; }
    if (c.kind === "removed") { lines.push(`- ${c.tool}  (removed)`); continue; }
    lines.push(`~ ${c.tool}${c.numbersOnly ? "  (numbers only)" : ""}`);
    for (const f of c.fields) {
      const tag = f.numbersOnly && !c.numbersOnly ? "  (numbers only)" : "";
      if (f.words) {
        const rendered = f.words.map(([op, text]) => op === "=" ? text : op === "-" ? `[-${text}-]` : `{+${text}+}`).join("");
        lines.push(`    ${f.path}: ${rendered}${tag}`);
      } else if (!("before" in f)) lines.push(`    ${f.path}: added ${show(f.after)}`);
      else if (!("after" in f)) lines.push(`    ${f.path}: removed (was ${show(f.before)})`);
      else if (Array.isArray(f.before) && Array.isArray(f.after)) {
        // A list of plain values (required, enum, type): which entries came and went.
        const was = new Set(f.before.map(v => JSON.stringify(v))), now = new Set(f.after.map(v => JSON.stringify(v)));
        const plus = [...now].filter(v => !was.has(v)), minus = [...was].filter(v => !now.has(v));
        const parts = [plus.length ? `added ${plus.join(", ")}` : "", minus.length ? `removed ${minus.join(", ")}` : ""].filter(Boolean);
        lines.push(`    ${f.path}: ${parts.length ? parts.join("; ") : `reordered ${show(f.before)} → ${show(f.after)}`}`);
      } else lines.push(`    ${f.path}: ${show(f.before)} → ${show(f.after)}${tag}`);
    }
    if (c.fields.length >= MAX_FIELDS_PER_TOOL) lines.push(`    … more than ${MAX_FIELDS_PER_TOOL} changed values; see the full definitions below`);
  }
  return lines;
}
