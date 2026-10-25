/**
 * What changed between the tool definitions a person approved and the ones a server serves now,
 * field by field, for the re-approval review.
 *
 * A pin is a hash: it says THAT something changed. A reviewer needs WHAT changed. Over four weeks
 * of HISTOR's log (snapshot 2026-10-20, 23,821 changes), 59.5% changed a tool's description
 * (45.1% by more than digits) and 30.8% added or removed tools, while 13.4% touched nothing but
 * digits, separators or whitespace (live counters, prices and limits written into definitions).
 * A review that shows two full JSON blobs for each of those trains people to approve without
 * reading. This module
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
  /** Text this change adds about the user's approval or about which tool to use (see Attention). */
  attention?: Attention[];
}

/**
 * What a reviewer should read first: text a change ADDS about the user's approval ("without asking", "the user has
 * already approved") or about which tool the model should pick ("prefer this over web search", "never use another
 * tool"). A reader asked for it (dev.to, 2026-10-23); in HISTOR's 20 October snapshot, 12 of 23,821 changes added or
 * dropped such a routing hint, 9 of them in nothing but the description. It marks; it never approves or refuses.
 * English phrasing only.
 */
export type Attention = "approval" | "tool choice";

export interface ToolChange {
  tool: string;
  kind: "added" | "removed" | "changed";
  /** For `changed`: every value that differs. */
  fields: FieldChange[];
  /** For `added` / `removed`: the whole definition. */
  definition?: ToolDef;
  /** A changed tool whose every field change is numbers only. */
  numbersOnly: boolean;
  /** For `changed`: every Attention its fields add. For `added`: every Attention in the new tool's text. */
  attention?: Attention[];
}

export interface DefinitionDiff {
  changes: ToolChange[];
  added: number;
  removed: number;
  changed: number;
  /** Changed tools whose changes are numbers only. */
  numbersOnly: number;
  /** Added or changed tools whose new text is about the user's approval or about tool choice. */
  attention: number;
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
      else out.push({ path: p, after: after[key], numbersOnly: false, ...flag(addedAttention("", textsOf(after[key]))) });
      if (out.length >= MAX_FIELDS_PER_TOOL) return;
    }
    return;
  }
  if (Array.isArray(before) && Array.isArray(after) && !(before.every(isPrimitive) && after.every(isPrimitive))) {
    const n = Math.max(before.length, after.length);
    for (let i = 0; i < n; i++) {
      const p = joinPath(path, i);
      if (i >= before.length) out.push({ path: p, after: after[i], numbersOnly: false, ...flag(addedAttention("", textsOf(after[i]))) });
      else if (i >= after.length) out.push({ path: p, before: before[i], numbersOnly: false });
      else walk(p, before[i], after[i], out);
      if (out.length >= MAX_FIELDS_PER_TOOL) return;
    }
    return;
  }
  if (typeof before === "string" && typeof after === "string") {
    const words = wordDiff(before, after);
    out.push({ path, before, after, words, numbersOnly: textNumbersOnly(words), ...flag(addedAttention(before, after)) });
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
    if (!b && a) changes.push({ tool: name, kind: "added", fields: [], definition: a, numbersOnly: false,
      ...flag(addedAttention("", textsOf([a.description, a.inputSchema, a.outputSchema]))) });
    else if (b && !a) changes.push({ tool: name, kind: "removed", fields: [], definition: b, numbersOnly: false });
    else if (b && a && !same(b, a)) {
      const fields: FieldChange[] = [];
      walk("", b, a, fields);
      const attention = ATTENTION_ORDER.filter(k => fields.some(f => f.attention?.includes(k)));
      changes.push({ tool: name, kind: "changed", fields, numbersOnly: fields.length > 0 && fields.every(f => f.numbersOnly), ...flag(attention) });
    }
  }
  return {
    changes,
    added: changes.filter(c => c.kind === "added").length,
    removed: changes.filter(c => c.kind === "removed").length,
    changed: changes.filter(c => c.kind === "changed").length,
    numbersOnly: changes.filter(c => c.numbersOnly).length,
    attention: changes.filter(c => c.attention?.length).length,
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
  if (diff.attention) {
    const names = diff.changes.filter(c => c.attention?.length).map(c => `${c.tool} (${c.attention!.join(", ")})`);
    lines.push(`Read first: ${diff.attention} ${diff.attention === 1 ? "tool gains" : "tools gain"} text about the user's approval or about which tool to use: ${names.join("; ")}`);
  }
  for (const c of diff.changes) {
    if (c.kind === "added") { lines.push(`+ ${c.tool}  (new tool${attentionNote(c.attention)})`, `    ${show(c.definition, 4000)}`); continue; }
    if (c.kind === "removed") { lines.push(`- ${c.tool}  (removed)`); continue; }
    lines.push(`~ ${c.tool}${c.numbersOnly ? "  (numbers only)" : ""}`);
    for (const f of c.fields) {
      const tag = (f.numbersOnly && !c.numbersOnly ? "  (numbers only)" : "") + (f.attention?.length ? `  (adds text about ${f.attention.map(k => k === "approval" ? "the user's approval" : "tool choice").join(" and ")})` : "");
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

// ── What a reviewer should read first ─────────────────────────────────────

const ATTENTION_ORDER: readonly Attention[] = ["approval", "tool choice"];
const ATTENTION: ReadonlyArray<readonly [Attention, RegExp]> = [
  // Asking the model to act without the user, or telling it the user already agreed.
  ["approval", /\bwithout\s+(?:asking|confirm(?:ing|ation)|(?:the\s+)?user'?s?\s+(?:approval|consent|permission)|approval|permission|(?:telling|informing|notifying)\s+(?:the\s+)?user)\b/gi],
  ["approval", /\b(?:do\s+not|don'?t|never|no\s+need\s+to)\s+(?:ask|confirm\s+with|check\s+with|prompt)\s+(?:the\s+)?user(?:\s+(?:for\s+(?:confirmation|approval|permission|consent)|before|first|again)\b|\s*(?:[.;!,]|$))/gim],
  ["approval", /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert)\s+(?:the\s+)?user\b/gi],
  ["approval", /\b(?:skip|bypass|avoid|suppress|disable)\s+(?:the\s+|any\s+)?(?:user\s+)?(?:confirmation|approval|consent)(?:\s+(?:step|prompt|dialog))?\b/gi],
  ["approval", /\b(?:auto[-\s]?approved?|pre[-\s]?approved|already\s+(?:been\s+)?(?:approved|confirmed|authori[sz]ed))\b/gi],
  ["approval", /\b(?:the\s+)?user\s+(?:has\s+)?(?:already\s+)?(?:approved|consented|agreed\s+to|authori[sz]ed)\b/gi],
  // Steering the model towards this tool or away from others.
  ["tool choice", /\b(?:prefer|use|call|choose|pick|select)\s+(?:this|these)\s+(?:tool|tools|server|function|one)\b[^.\n]{0,60}?\b(?:over|instead|rather\s+than|first|before|always)\b/gi],
  ["tool choice", /\b(?:prefer(?:red)?|use|call)\b[^.\n]{0,40}?\b(?:over|instead\s+of|rather\s+than)\s+(?:the\s+|any\s+|your\s+|a\s+)?(?:web[\s_-]?search|search(?:ing)?|fetch(?:ing)?|brows(?:er|ing)|built[\s-]?in|other\s+(?:tools?|servers?|sources?)|another\s+(?:tool|server)|(?:your\s+)?(?:own\s+)?knowledge|training\s+data)\b/gi],
  ["tool choice", /\bprefer\s+(?:this|it)\s+over\b/gi],
  ["tool choice", /\b(?:always|only)\s+(?:use|call)\s+(?:this|the\s+[\w-]+)\s+(?:tool|server|function)\b/gi],
  ["tool choice", /\b(?:do\s+not|don'?t|never)\s+(?:use|call)\s+(?:any\s+)?(?:other|another|the\s+built[\s-]?in|web[\s_-]?search|fetch)\b/gi],
  ["tool choice", /\bbefore\s+(?:using|calling)\s+any\s+other\s+(?:tool|server)\b/gi],
];
const MAX_ATTENTION_TEXT = 200_000;

function phrases(text: string): Map<Attention, Set<string>> {
  const out = new Map<Attention, Set<string>>();
  const body = text.slice(0, MAX_ATTENTION_TEXT);
  for (const [kind, re] of ATTENTION) {
    for (const m of body.matchAll(re)) {
      const set = out.get(kind) ?? new Set<string>();
      set.add(m[0].toLowerCase().replace(/\s+/g, " ").trim());
      out.set(kind, set);
    }
  }
  return out;
}

/** The kinds of Attention whose phrasing appears in `after` and not in `before`. */
export function addedAttention(before: string, after: string): Attention[] {
  const was = phrases(before), now = phrases(after);
  return ATTENTION_ORDER.filter(kind => [...(now.get(kind) ?? [])].some(p => !was.get(kind)?.has(p)));
}

/** Every string inside a value (descriptions nested in a schema), bounded. */
function textsOf(value: unknown, out: string[] = [], depth = 0): string {
  if (out.length > 2_000 || depth > 20) return out.join("\n");
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) textsOf(v, out, depth + 1);
  else if (isPlainObject(value)) for (const v of Object.values(value)) textsOf(v, out, depth + 1);
  return out.join("\n");
}

function flag(attention: Attention[]): { attention?: Attention[] } {
  return attention.length ? { attention } : {};
}

function attentionNote(attention: Attention[] | undefined): string {
  return attention?.length ? `; text about ${attention.map(k => k === "approval" ? "the user's approval" : "tool choice").join(" and ")}` : "";
}

// ── Where a change came from: the launch command and the version ───────────

/** A registry package named by a launcher (`npx pkg`, `uvx pkg`), and whether the command names an exact version.
 *  Without one, resolution can change between starts while the command and server identity hash stay the same.
 *  A launch may reuse cached code; neither its requested version nor serverInfo verifies the installed artifact. */
export interface LaunchSpec {
  runner: string;
  ecosystem: "npm" | "pypi";
  package: string;
  /** The version or range in the command, if any (`1.4.2`, `latest`, `^1`, `>=2`). */
  requested?: string;
  pinned: boolean;
}

const VALUE_FLAGS = new Set(["--registry", "--cache", "--userconfig", "--prefix", "--python", "--with", "--with-requirements",
  "--index-url", "--extra-index-url", "--index", "--pip-args", "--suffix", "-w", "--workspace", "-c", "--call"]);
const SPEC_FLAGS = new Set(["-p", "--package", "--from", "--spec"]);
const EXACT_NPM = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const EXACT_PY = /^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*$/;

export function launchSpec(server: { command?: string; args?: readonly string[] }): LaunchSpec | undefined {
  const command = (server.command ?? "").split(/[\\/]/).pop()?.replace(/\.(?:cmd|exe)$/i, "") ?? "";
  const args = [...(server.args ?? [])];
  let runner: string; let ecosystem: LaunchSpec["ecosystem"];
  if (["npx", "bunx", "pnpx"].includes(command)) { runner = command; ecosystem = "npm"; }
  else if (command === "npm" && args[0] === "exec") { runner = "npm exec"; ecosystem = "npm"; args.shift(); }
  else if ((command === "pnpm" || command === "yarn") && args[0] === "dlx") { runner = `${command} dlx`; ecosystem = "npm"; args.shift(); }
  else if (command === "uvx") { runner = "uvx"; ecosystem = "pypi"; }
  else if (command === "uv" && args[0] === "tool" && args[1] === "run") { runner = "uv tool run"; ecosystem = "pypi"; args.splice(0, 2); }
  else if (command === "pipx" && args[0] === "run") { runner = "pipx run"; ecosystem = "pypi"; args.shift(); }
  else return undefined;
  let spec: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") { spec ??= args[i + 1]; break; }
    const [flagName, inline] = a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    if (SPEC_FLAGS.has(flagName) && !(ecosystem === "pypi" && flagName === "-p")) { spec = inline ?? args[++i]; continue; }
    if (VALUE_FLAGS.has(flagName) || (ecosystem === "pypi" && flagName === "-p")) { if (inline === undefined) i++; continue; }
    if (a.startsWith("-")) continue;
    spec ??= a;
    break;
  }
  if (!spec) return undefined;
  return ecosystem === "npm" ? npmSpec(runner, spec) : pySpec(runner, spec);
}

function npmSpec(runner: string, spec: string): LaunchSpec | undefined {
  // Paths, git and tarball URLs are not a registry name: what they run is a different question.
  if (/^(?:[.~/]|file:|git[+:]|github:|gitlab:|bitbucket:|https?:)/i.test(spec) || (spec.includes("/") && !spec.startsWith("@"))) return undefined;
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  const name = at > 0 ? spec.slice(0, at) : spec, requested = at > 0 ? spec.slice(at + 1) : undefined;
  if (!/^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(name)) return undefined;
  return { runner, ecosystem: "npm", package: name, ...(requested ? { requested } : {}), pinned: !!requested && EXACT_NPM.test(requested) };
}

function pySpec(runner: string, spec: string): LaunchSpec | undefined {
  const m = /^([A-Za-z0-9][\w.-]*)(\[[\w,.-]+\])?\s*(?:(==|===|@)\s*([^\s;,]+)|((?:~=|!=|>=|<=|>|<)\s*[^\s;]+))?$/.exec(spec);
  if (!m) return undefined;
  const requested = m[4] ?? m[5]?.replace(/\s+/g, "");
  return { runner, ecosystem: "pypi", package: m[1]! + (m[2] ?? ""), ...(requested ? { requested } : {}), pinned: !!m[4] && EXACT_PY.test(m[4]) };
}

/** A version string a server reports about itself, if it is short and plain; anything else is not shown. */
export function plainVersion(v: unknown): string | undefined {
  return typeof v === "string" && /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/.test(v) ? v : undefined;
}

/** Review lines on where a change came from: the version the server reported at approval and now, and whether
 *  the launch command pins one. The reported version is the server's own word; the launch command is not. */
export function formatOriginLines(launch: LaunchSpec | undefined, approved: string | undefined, current: string | undefined, toolsChanged: boolean): string[] {
  const lines: string[] = [];
  if (approved || current) {
    const both = approved && current;
    lines.push(`Version the server reports (initialize serverInfo; not a verified package version): ${both ? (approved === current ? `${current}, unchanged since the approval` : `${approved} at the approval, ${current} now`) : current ? `${current} now; none was stored with the approval` : `${approved} at the approval; none reported now`}`);
    if (both && approved === current && toolsChanged) lines.push(`The tool definitions changed while the reported version stayed ${current}.`);
  }
  if (launch) {
    const how = `${launch.runner} ${launch.package}${launch.requested ? (launch.ecosystem === "npm" ? "@" : launch.requested.match(/^[<>=!~]/) ? "" : "==") + launch.requested : ""}`;
    if (launch.pinned) lines.push(`Launch: ${how} (an exact requested version; installed artifact not verified).`);
    else {
      lines.push(`Launch: ${how} (no exact version: resolution may change between starts or reuse cached code; verify the resolved package version and package-manager lock before pinning; serverInfo.version does not identify the installed artifact).`);
    }
  }
  return lines;
}
