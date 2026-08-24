import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.js";
import { displaySafe } from "./sanitize.js";
import { silentLogger } from "./logger.js";
import type {
  RulesetRef,
  Severity,
  WardenFinding,
  WardenGate,
  WardenGateInput,
  WardenGateResult,
  WardenLogger,
} from "./types.js";

/**
 * Static tool-definition scanner.
 *
 * The MCP tool *description* and *input schema* are attacker-controlled text the
 * model reads as trusted instructions — this is the tool-poisoning / prompt-
 * injection surface. We scan that text (never the live tool output) for known
 * signatures before a single token of it reaches the model. Cheap, deterministic,
 * and runs first so later gates can reason about its findings.
 *
 * Rules are TIERED, and the tier is what decides blocking — not severity:
 *
 *   block  — no plausible benign reading in a tool definition. Blocks at the
 *            policy threshold like any other finding.
 *   advise — legitimately appears in honest tool definitions. Reported, never
 *            blocks, never reduces the score, at any `blockAtSeverity`.
 *
 * Ruleset v1 had one tier, so `api_key` in a schema carried the same weight as
 * "ignore all previous instructions". A GitHub-style server whose `create_issue`
 * takes an `api_key` and mentions a personal access token scored 0.40 and had the
 * tool blocked under the default policy — i.e. most real MCP servers were refused,
 * which is how a scanner gets switched off entirely.
 */

type Tier = "block" | "advise";

/**
 * Which part of a tool definition a rule is meaningful against.
 *
 * `name` is an IDENTIFIER, not prose, and that difference decides the table
 * below. A rule that keys on a noun - `api_key`, `private_key`, `.env` - matches
 * ordinary identifiers (`sign_with_private_key` is a plausible wallet tool), so
 * running it over names would refuse honest servers on their naming convention:
 * exactly the ruleset v1 mistake, one surface over. A rule that keys on a PHRASE
 * needs whitespace and cannot match `snake_case` at all, and the two hidden-payload
 * rules are about characters that are never legitimate in a name.
 *
 * Names were scanned by nothing at all until ruleset v3, which meant zero-width
 * characters and a base64 blob could sit in the one field that reaches the model
 * first and WARDEN reported nothing.
 */
type Surface = "name" | "description" | "inputSchema";

/** Prose surfaces: the default, and everything a noun-keyed rule may look at. */
const PROSE: Surface[] = ["description", "inputSchema"];

/** Prose plus the identifier - for phrase and hidden-payload rules. */
const ALL_SURFACES: Surface[] = ["name", "description", "inputSchema"];

interface SignaturePattern {
  re: RegExp;
  code: string;
  severity: Severity;
  tier: Tier;
  /** Where this rule is run. See {@link Surface}. */
  surfaces: Surface[];
  /** Replaces the generic "matches <code> signature" wording when present. */
  note?: string;
  /**
   * Guards in {@link GUARDS} that decide whether a match is really the thing
   * this rule looks for. Any guard returning a reason drops the finding. Part of
   * the published rule table, and therefore of the digest: two builds with
   * identical regexes but different guards are different rulesets, and a
   * recorded scan has to be able to tell them apart.
   */
  guards?: GuardName[];
}

/**
 * A guard inspects a match in context and returns a reason to DROP it, or null
 * to report it.
 *
 * Guards exist because a regex over a tool definition cannot tell an instruction
 * from a description of one. The field survey in docs/mcp-survey.md measured the
 * cost: of 50 servers this scanner blocked, 46 were blocked for saying the right
 * thing — "Never send a private key", "the private key never leaves your
 * machine", a security scanner listing the attacks it detects. A rule table with
 * no notion of polarity or of quotation selects for the honest server.
 */
type Guard = (m: RegExpExecArray, text: string, surface: Surface) => string | null;

type GuardName =
  | "polarity"
  | "mention"
  | "identifierFragment"
  | "detection"
  | "harvestTarget"
  | "uri"
  | "payload"
  | "blob"
  | "publicKeyPath"
  | "zeroWidth";

// Imperative instructions aimed at the model — the classic injection tells.
const INJECTION_PATTERNS: SignaturePattern[] = [
  { re: /\bignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|preceding)\b/i, code: "TOOL_DEF_INJECTION", severity: "critical", tier: "block", surfaces: ALL_SURFACES, guards: ["mention"] },
  { re: /\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|instructions?|rules?)\b/i, code: "TOOL_DEF_INJECTION", severity: "critical", tier: "block", surfaces: ALL_SURFACES, guards: ["mention"] },
  // Demoted in v4. The survey found four real uses and all four were the
  // OPPOSITE of concealment: "no refund is issued automatically … do not tell
  // the user a refund is coming". Conscientious authors use the phrase to stop
  // the model inventing reassurance. Blocking on it selected for exactly the
  // servers that were being careful. A blocking rule needs a concealment target
  // that refers to the tool's own action; the bare phrase does not carry one.
  { re: /\bdo\s+not\s+(?:tell|inform|mention|reveal\s+to|notify)\s+(?:the\s+)?user\b/i, code: "TOOL_DEF_INJECTION", severity: "medium", tier: "advise", surfaces: ALL_SURFACES, guards: ["mention"] },
  { re: /\bwithout\s+(?:telling|informing|asking)\s+(?:the\s+)?user\b/i, code: "TOOL_DEF_INJECTION", severity: "high", tier: "block", surfaces: ALL_SURFACES },
  { re: /<\s*\/?\s*(?:system|instructions?|important)\s*>/i, code: "TOOL_DEF_INJECTION", severity: "high", tier: "block", surfaces: ALL_SURFACES },
  // Demoted in v4. The comment here used to say this was "the blocking rule most
  // likely to need a policy override"; the survey settled it — 15 findings across
  // 6 servers, every one an LLM proxy, persona manager or agent-configuration
  // tool that declares a `system` parameter because setting a system prompt is
  // its entire job. The phrase is the domain's vocabulary, not the attack.
  { re: /\b(?:system\s+prompt|developer\s+(?:message|prompt))\b/i, code: "TOOL_DEF_INJECTION", severity: "low", tier: "advise", surfaces: ALL_SURFACES },
  // Ordinary English. Kept as a signal because it co-occurs with real poisoning,
  // demoted because on its own it is noise: "You must supply a subject."
  { re: /\byou\s+must\b/i, code: "TOOL_DEF_IMPERATIVE", severity: "low", tier: "advise", surfaces: ALL_SURFACES },
  { re: /\binstead\s+of\b/i, code: "TOOL_DEF_IMPERATIVE", severity: "info", tier: "advise", surfaces: ALL_SURFACES },
];

// Data-exfiltration phrasing.
const EXFIL_PATTERNS: SignaturePattern[] = [
  // Demoted in v4. An attacker does not name the attack; a defender names it in
  // every sentence. All three of the survey's hits were defensive tools — an MCP
  // endpoint scanner, an injection scanner, and a policy builder whose `enum` is
  // `["exfiltration", "recon_then_destroy", …]`. The anchored "send X to
  // <external destination>" rules below carry the blocking weight instead.
  { re: /\bexfiltrat\w*/i, code: "TOOL_DEF_EXFIL", severity: "medium", tier: "advise", surfaces: ALL_SURFACES, guards: ["mention"] },
  // Anchored on an EXTERNAL destination. Unanchored, this matched "Send the
  // message to the recipient" in any honest email or webhook tool.
  {
    re: /\b(?:send|post|forward|relay)\s+(?:it|them|this|the\s+\w+|all|results?|output|data|contents?)\s+to\s+(?:https?:\/\/|\b[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b)/i,
    code: "TOOL_DEF_EXFIL",
    severity: "high",
    tier: "block",
    surfaces: ALL_SURFACES,
  },
  { re: /\b(?:post|send|put)\s+to\s+https?:\/\//i, code: "TOOL_DEF_EXFIL", severity: "critical", tier: "block", surfaces: ALL_SURFACES },
  { re: /\bupload\b[\s\S]{0,40}\bto\s+(?:https?:\/\/|[\w.-]+\.[a-z]{2,})/i, code: "TOOL_DEF_EXFIL", severity: "high", tier: "block", surfaces: ALL_SURFACES },
];

// Secrets. Naming a credential PARAMETER is what normal tools do; demanding the
// material that is never a parameter is not.
//
// The discriminator is the VERB, not the noun. "Requires a personal access token
// with repo scope" describes an input. "read the user's api_key from the .env
// file" instructs the model to go and get one. Tiering on the noun alone is what
// blocked every real server, and dropping the noun rules entirely would have let
// a harvest instruction through whenever it omitted an injection phrase.
const SECRET_PATTERNS: SignaturePattern[] = [
  {
    // The gap may no longer cross a sentence or a JSON string boundary. It used
    // to be `[\s\S]{0,30}`, which matched "read an open or sealed run (pass
    // api_key" — a verb in prose reaching into the next field's parameter name.
    re: /\b(?:read|extract|retrieve|fetch|obtain|dump|reveal|collect|harvest|grab|copy|print)\s[^.;"\n]{0,30}?\b(?:api[_\s-]?key|access[_\s-]?token|bearer\s+token|credential|password|passwd|secret|\.env\b|environment\s+variable)/i,
    code: "TOOL_DEF_SECRET_HARVEST",
    severity: "critical",
    tier: "block",
    // Phrase-keyed: the verb must be followed by whitespace, so `read_api_key`
    // as an identifier cannot match while `read api_key` in a name can.
    surfaces: ALL_SURFACES,
    // "never store secrets", "never collect card data", "does not reveal or mint
    // a standalone agent credential" — three servers blocked for promising in
    // writing not to do this.
    guards: ["polarity", "harvestTarget"],
  },
  // Severity lowered from critical to high in v4: still over the default block
  // threshold, but no longer zeroing the gate score outright. One noun in a
  // schema template shared by 377 tools should not read as "this server is
  // maximally compromised" — and with the polarity guard, the template that
  // caused it ("do not … include private key material") no longer matches at all.
  { re: /\bprivate[_\s-]?key\b/i, code: "TOOL_DEF_SECRET_REQUEST", severity: "high", tier: "block", surfaces: PROSE, guards: ["polarity", "detection", "identifierFragment"] },
  { re: /\bseed[_\s-]?phrase\b|\bmnemonic\b/i, code: "TOOL_DEF_SECRET_REQUEST", severity: "high", tier: "block", surfaces: PROSE, guards: ["polarity", "mention", "detection", "identifierFragment"] },
  { re: /~\/\.ssh|\bid_rsa\b|\.ssh\/[\w.-]+/i, code: "TOOL_DEF_SECRET_REQUEST", severity: "high", tier: "block", surfaces: PROSE, guards: ["polarity", "publicKeyPath"] },
  // Advisory: these are ordinary parameter names and ordinary setup prose.
  { re: /\bapi[_\s-]?key\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "low", tier: "advise", surfaces: PROSE },
  { re: /\bcredentials?\b|\baccess[_\s-]?token\b|\bbearer\s+token\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "low", tier: "advise", surfaces: PROSE },
  { re: /\bsecret(?:s)?\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "low", tier: "advise", surfaces: PROSE },
  { re: /\bpassword\b|\bpasswd\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "medium", tier: "advise", surfaces: PROSE },
  { re: /(?:^|[^.\w])\.env\b|\benvironment\s+variables?\b/i, code: "TOOL_DEF_ENV_REFERENCE", severity: "medium", tier: "advise", surfaces: PROSE },
];

// Dangerous URL schemes embedded in text.
const URL_SCHEME_PATTERNS: SignaturePattern[] = [
  // A `data:` URI with no payload behind it is the format being documented —
  // `"example": "<url> OR data:image/png;base64,..."` on every image API.
  { re: /\bdata:[\w/+.-]+;base64,/i, code: "TOOL_DEF_DATA_URL", severity: "high", tier: "block", surfaces: ALL_SURFACES, guards: ["payload", "mention"] },
  // Case-SENSITIVE since v4. Under /i this matched the word "JavaScript"
  // followed by a colon, i.e. every language list ever written:
  // "TypeScript/JavaScript: *.spec/test.{ts,js}".
  { re: /\bjavascript:/, code: "TOOL_DEF_DATA_URL", severity: "high", tier: "block", surfaces: ALL_SURFACES, guards: ["uri", "mention"] },
];

// Hidden payloads. Part of the rule table (and therefore the digest) rather than
// special cases in the scan loop.
const PAYLOAD_PATTERNS: SignaturePattern[] = [
  {
    // Standard (RFC 4648 §4) AND URL-safe (§5) base64, padded or not — JWTs and
    // web payloads commonly omit padding.
    re: /[A-Za-z0-9+/_-]{120,}={0,2}/,
    code: "TOOL_DEF_BASE64_BLOB",
    severity: "high",
    tier: "block",
    surfaces: ALL_SURFACES,
    note: "contains a long base64-encoded blob — possible hidden payload",
    guards: ["blob"],
  },
  {
    // U+200B–200F, U+202A–202E, U+2060, U+FEFF. Built from a \u-escaped string so
    // the source stays reviewable (the characters are, by definition, invisible).
    re: new RegExp("[\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]"),
    code: "TOOL_DEF_HIDDEN_UNICODE",
    severity: "high",
    tier: "block",
    surfaces: ALL_SURFACES,
    note: "contains zero-width or bidi control characters hiding text from review",
    guards: ["zeroWidth"],
  },
];

/**
 * Words that flip the meaning of a credential noun near them.
 *
 * "Never send a private key" and "send a private key" differ by one of these and
 * nothing else, and a noun-keyed rule reads them identically. In the survey this
 * single distinction accounted for 390 of 492 blocking findings.
 */
const REFUSAL =
  /\b(?:never|not|no|non|without|nor|refus\w*|forbid\w*|prohibit\w*|exclud\w*|reject\w*|don'?t|doesn'?t|won'?t|cannot|can'?t|unnecessary|none)\b/i;

/**
 * How far a guard looks for context, and what stops it.
 *
 * Bounded because a refusal three sentences away is not about this noun, and
 * stopped at clause boundaries for the same reason. `","` is in the stop set
 * because on the schema surface the text is JSON: two adjacent field descriptions
 * are as unrelated as two sentences, and a 120-character window would otherwise
 * read one field's negation as covering the next field's noun.
 */
const CONTEXT_SPAN = 120;

/** Text either side of the match, cut at the nearest clause boundary. */
function clauseAround(text: string, start: number, end: number): { before: string; after: string } {
  let a = start;
  const floor = Math.max(0, start - CONTEXT_SPAN);
  while (a > floor && !isClauseStop(text, a - 1)) a--;
  let b = end;
  const ceil = Math.min(text.length, end + CONTEXT_SPAN);
  while (b < ceil && !isClauseStop(text, b)) b++;
  return { before: text.slice(a, start), after: text.slice(end, b) };
}

function isClauseStop(text: string, i: number): boolean {
  const c = text[i];
  if (c === "." || c === ";" || c === "!" || c === "?" || c === "\n") return true;
  // JSON field boundary: `","` between two schema descriptions.
  return c === '"' && text[i + 1] === "," ;
}

/** Is the match wrapped in quotes or backticks — i.e. cited rather than said? */
function isQuoted(text: string, start: number, end: number): boolean {
  for (const q of ["'", '"', "`"]) {
    const open = text.lastIndexOf(q, start - 1);
    if (open < 0) continue;
    const close = text.indexOf(q, end);
    if (close < 0) continue;
    // A citation is short. A whole paragraph between two apostrophes is not one.
    if (close - open <= 120 && !text.slice(open + 1, close).includes("\n")) return true;
  }
  return false;
}

/** Shannon entropy in bits per character. */
function entropy(sample: string): number {
  const counts = new Map<string, number>();
  for (const ch of sample) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const pr = n / sample.length;
    h -= pr * Math.log2(pr);
  }
  return h;
}

/**
 * Zero-width characters that are orthography, not concealment.
 *
 * U+200C ZERO WIDTH NON-JOINER is a REQUIRED letter-form control in Persian,
 * Arabic and several Indic scripts: `بخشنامه‌ها` is spelled with one. The survey
 * blocked an Iranian legal-calculation server five times for writing its own
 * language. U+200B, U+FEFF and the bidi overrides have no such role and stay
 * blocking.
 */
const SCRIPT_NEEDING_JOINER_CONTROL =
  /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\u0900-\u0DFF\uFB50-\uFDFF\uFE70-\uFEFE]/;

const GUARDS: Record<GuardName, Guard> = {
  /** A credential noun inside a refusal is a promise, not a request. */
  polarity(m, text) {
    // The cue can sit INSIDE the match when the rule spans a verb and a noun:
    // "read it, so never store secret" is one TOOL_DEF_SECRET_HARVEST match.
    if (REFUSAL.test(m[0])) return "refusal cue inside the match";
    const { before, after } = clauseAround(text, m.index, m.index + m[0].length);
    if (REFUSAL.test(before)) return "refusal cue before the match in the same clause";
    if (REFUSAL.test(after)) return "refusal cue after the match in the same clause";
    return null;
  },

  /**
   * A phrase in quotes, in backticks, or as a bare JSON enum value is a mention.
   *
   * Four of the survey's blocked servers were security tools listing the attacks
   * they detect — one of them in an `enum` of `["exfiltration", …]`.
   */
  mention(m, text, surface) {
    const start = m.index;
    const end = start + m[0].length;
    if (isQuoted(text, start, end)) return "match is quoted or in backticks — a citation, not an instruction";
    if (surface === "inputSchema" && text[start - 1] === '"' && text[end] === '"') {
      return "match is a complete JSON string token — an enum value or field name";
    }
    return null;
  },

  /**
   * `javascript:` as a URI, not as the name of a language.
   *
   * The rule is case-sensitive now, which alone removes "TypeScript/JavaScript:"
   * from every language list on earth. A scheme is also followed immediately by
   * its payload, so a space after the colon means a label.
   */
  uri(m, text) {
    const after = text.slice(m.index + m[0].length);
    // A scheme followed by punctuation is a list item or a label: "Filters out
    // javascript:, mailto:, data: schemes".
    if (after === "" || /^[\s"'`)\],;.]/.test(after)) return "no URI payload after the scheme — a label, not a link";
    return null;
  },

  /** A `data:` URI that carries no payload is documentation of the format. */
  payload(m, text) {
    const rest = text.slice(m.index + m[0].length);
    const body = /^[A-Za-z0-9+/=]*/.exec(rest)?.[0] ?? "";
    if (body.length < 32) return `only ${body.length} payload characters — a placeholder or an example`;
    return null;
  },

  /**
   * A long run of base64-alphabet characters that is structure, not a payload.
   *
   * `/` is in the base64 alphabet, so a deeply nested JSON Schema pointer —
   * `#/properties/flow/items/anyOf/2/properties/outcomes/items` — reads as a
   * blob. Real encoded data is near-uniform over the alphabet; identifiers and
   * paths are not, and they repeat words a reviewer can read.
   */
  blob(m) {
    const hit = m[0];
    if (/properties|items|definitions|anyOf|allOf|oneOf|\$defs/i.test(hit)) {
      return "match is a JSON Schema pointer, not an encoded payload";
    }
    const h = entropy(hit);
    if (h < BLOB_MIN_ENTROPY) return `entropy ${h.toFixed(2)} bits/char is below the ${BLOB_MIN_ENTROPY} floor — structure, not data`;
    return null;
  },

  zeroWidth(m, text) {
    const ch = m[0];
    if (ch !== "\u200C" && ch !== "\u200D") return null;
    const prev = text[m.index - 1] ?? "";
    const next = text[m.index + 1] ?? "";
    if (SCRIPT_NEEDING_JOINER_CONTROL.test(prev) || SCRIPT_NEEDING_JOINER_CONTROL.test(next)) {
      return "joiner control adjacent to a script that requires it — orthography, not concealment";
    }
    return null;
  },

  /**
   * A credential noun that is a FRAGMENT of a longer identifier is that
   * identifier's name.
   *
   * `bip39-mnemonic-checksum` sat in a comma-separated list of several hundred
   * calculator names and blocked a generic lookup gateway four times. A schema
   * field genuinely called `seed_phrase` still matches, because there the rule
   * consumes the whole token rather than part of it.
   */
  identifierFragment(m, text) {
    const start = m.index;
    const end = start + m[0].length;
    let a = start;
    while (a > 0 && /[\w.-]/.test(text[a - 1]!)) a--;
    let b = end;
    while (b < text.length && /[\w.-]/.test(text[b]!)) b++;
    const token = text.slice(a, b);
    if (token.length === m[0].length) return null;
    if (!/[-.]/.test(token)) return null;
    return `match is part of the longer identifier "${token.slice(0, 60)}"`;
  },

  /**
   * A secret named as the OBJECT OF DETECTION is not a secret being requested.
   *
   * The survey blocked a secret scanner on "Detect likely leaked API keys,
   * tokens, private-key headers, JWTs" and an injection scanner on its own
   * taxonomy. Naming what you look for is the defender's whole job.
   */
  detection(m, text) {
    const { before } = clauseAround(text, m.index, m.index + m[0].length);
    if (/\b(?:detect\w*|scan\w*|identif\w*|find\w*|report\w*|flag\w*|audit\w*|inspect\w*|check(?:s|ed|ing)?\s+for|look(?:s|ed|ing)?\s+for|leaked?)\b/i.test(before)) {
      return "secret named as the object of detection, not requested";
    }
    return null;
  },

  /**
   * A harvest instruction says WHOSE secret, or WHERE it lives.
   *
   * The rule's own comment always claimed this: "read the user's api_key from
   * the .env file". Without the constraint it also matched "Obtain a permanent
   * anonymous API key" and "obtain a visitor access token" — tools that ISSUE
   * you a credential, which is the opposite transaction.
   */
  harvestTarget(m) {
    const hit = m[0];
    if (/\b(?:the\s+user'?s?|user'?s|your|their|his|her|its|my|from|out\s+of|stored|saved|existing)\b/i.test(hit)) return null;
    if (/[~/\\]|\.env\b|environment/i.test(hit)) return null;
    return "no owner or location for the secret — reads as a credential being issued, not taken";
  },

  /** `.ssh/authorized_keys` and `id_ed25519.pub` are public by definition. */
  publicKeyPath(m, text) {
    // A RAW forward window, not a clause: the giveaway is the extension, and
    // `.pub` begins with the character clauseAround treats as a sentence end.
    const end = m.index + m[0].length;
    const hit = m[0] + text.slice(end, end + 48);
    if (/authorized_keys|known_hosts|\.pub\b/i.test(hit)) return "path names public key material";
    return null;
  },
};

/** Entropy floor for {@link GUARDS.payload}-style blob detection. */
const BLOB_MIN_ENTROPY = 4.2;

const RULES: SignaturePattern[] = [
  ...INJECTION_PATTERNS,
  ...EXFIL_PATTERNS,
  ...SECRET_PATTERNS,
  ...URL_SCHEME_PATTERNS,
  ...PAYLOAD_PATTERNS,
];

/**
 * Ruleset version. Bump on ANY change to the table above — a scan result is only
 * comparable to another scan made under the same version and digest.
 *
 * 1 — single tier; credential parameter names blocked real servers.
 * 2 — block/advise tiers; exfil "send … to" anchored on an external destination;
 *     TOOL_DEF_SECRET_HARVEST added so demoting the credential nouns does not
 *     open a hole; advisory findings no longer affect the score.
 * 3 — rules gained `surfaces`, and the tool NAME became a scanned surface. Until
 *     v3 the name was scanned by nothing, so zero-width characters, a base64 blob
 *     or an injection phrase in the one field that reaches the model first went
 *     entirely unreported. Noun-keyed rules stay off the name on purpose: they
 *     match ordinary identifiers, and refusing `sign_with_private_key` would be
 *     the v1 calibration error committed on a new surface.
 * 4 — calibrated against 1 108 live public MCP servers (docs/mcp-survey.md). v3
 *     blocked 50 of them and only 4 held up on review, so v4 adds context
 *     GUARDS — polarity, quotation, URI form, payload length, entropy, script
 *     adjacency — and demotes four blocking rules the survey showed were
 *     selecting for honest servers: the bare `exfiltrat*` noun, `system prompt`,
 *     `do not tell the user`, and (in severity only) the credential nouns. A
 *     rule's guards are part of this table and therefore of the digest.
 */
export const STATIC_SCAN_RULESET_VERSION = "4";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Penalty applied to the gate score per worst BLOCKING severity found. */
const SEVERITY_PENALTY: Record<Severity, number> = {
  info: 0,
  low: 0.1,
  medium: 0.3,
  high: 0.6,
  critical: 1,
};

export interface StaticScanRule {
  code: string;
  severity: Severity;
  tier: Tier;
  /** Which surfaces the rule is run against, so a re-run scans the same fields. */
  surfaces: Surface[];
  /** The regex source, so a third party can re-run the exact rule. */
  source: string;
  flags: string;
  /**
   * Which context guards this rule is subject to. Published because the regex
   * alone no longer describes the rule: the same pattern with and without
   * `polarity` reports different findings on the same text.
   */
  guards: string[];
}

export interface StaticScanRuleset extends RulesetRef {
  rules: StaticScanRule[];
}

/**
 * The rule table plus its digest, so a scan result stays checkable after the
 * rules change.
 *
 * Sorted, so the digest depends on the rules and not on the order they happen to
 * be declared in — and sorted by CODE-UNIT comparison, not `localeCompare`: the
 * digest is a cross-machine identifier, and a locale-dependent collation would
 * make the same rule table digest differently on a differently-configured host,
 * which is exactly the divergence the digest exists to detect. The preimage is
 * the RFC 8785 canonical form (see ./jcs.ts) so this file does not invent a
 * second serialization of its own.
 */
export function staticScanRuleset(): StaticScanRuleset {
  const rules: StaticScanRule[] = RULES.map((r) => ({
    code: r.code,
    severity: r.severity,
    tier: r.tier,
    surfaces: [...r.surfaces],
    source: r.re.source,
    flags: r.re.flags,
    guards: [...(r.guards ?? [])],
  })).sort((a, b) => cmp(a.code, b.code) || cmp(a.source, b.source) || cmp(a.flags, b.flags));

  const preimage = canonicalize({ version: STATIC_SCAN_RULESET_VERSION, rules });
  const digest = `sha256-${createHash("sha256").update(preimage, "utf8").digest("base64")}`;

  return { version: STATIC_SCAN_RULESET_VERSION, digest, rules };
}

/** Code-unit comparison. See staticScanRuleset for why not localeCompare. */
function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Just the identity of the rule table, for embedding in a verdict. */
export function staticScanRulesetRef(): RulesetRef {
  const { version, digest } = staticScanRuleset();
  return { version, digest };
}

export class StaticScanGate implements WardenGate {
  readonly name = "static-scan";

  private readonly log: WardenLogger;

  /**
   * @param log where dropped matches are reported. A guard silently discarding a
   *   finding is the one behaviour in this gate that cannot be seen in the
   *   verdict, so it is the one that most needs a debug line.
   */
  constructor(log: WardenLogger = silentLogger()) {
    this.log = log.child("static-scan");
  }

  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const findings: WardenFinding[] = [];

    for (const tool of input.tools) {
      const schemaText = safeStringifySchema(tool.inputSchema);
      // The name is an identifier, the description is prose, the schema text is
      // field names + descriptions + enums. All three reach the model; each rule
      // declares which of them it is meaningful against (see Surface).
      const haystacks: Array<{ text: string; surface: Surface; where: string }> = [
        { text: tool.name ?? "", surface: "name", where: "name" },
        { text: tool.description ?? "", surface: "description", where: "description" },
        { text: schemaText, surface: "inputSchema", where: "input schema" },
      ];
      // The name is quoted back in every message, so it is escaped once here
      // rather than at each call site. `finding.tool` keeps the raw name: it is
      // the key the host filters its tool list with.
      const shown = displaySafe(tool.name);

      for (const { text, surface, where } of haystacks) {
        for (const rule of RULES) {
          if (!rule.surfaces.includes(surface)) continue;
          const m = matchOf(rule.re, text);
          if (!m) continue;
          const dropped = rule.guards?.map((g) => GUARDS[g](m, text, surface)).find((r) => r !== null);
          if (dropped) {
            this.log.debug(
              `static-scan: dropped ${rule.code} on "${shown}" ${where} — ${dropped}`,
            );
            continue;
          }
          // The matched text goes into the message. Without it the reader gets
          // "matches TOOL_DEF_SECRET_HARVEST signature (\b(?:read|extract|…)" and
          // cannot tell which alternative fired, or on what — which is most of
          // the work of judging whether a finding is real.
          const span = displaySafe(m[0], SPAN_MAX);
          const finding: WardenFinding = {
            gate: this.name,
            severity: rule.severity,
            code: rule.code,
            message: rule.note
              ? `Tool "${shown}" ${where} ${rule.note} — at "${span}".`
              : `Tool "${shown}" ${where} matches ${rule.code} signature (${describe(rule.re)}) at "${span}".`,
            tool: tool.name,
          };
          if (rule.tier === "advise") finding.advisory = true;
          findings.push(finding);
        }
      }
    }

    return { findings, score: scoreFor(findings) };
  }
}

/**
 * 1 minus the penalty for the worst BLOCKING severity found; clamped to [0,1].
 *
 * Advisory findings are excluded on purpose. The composite is presented to users
 * as a safety score, and a credential parameter name is not a safety defect —
 * letting it drag the number down made a clean server look like a compromised one.
 */
function scoreFor(findings: WardenFinding[]): number {
  let worst: Severity = "info";
  for (const f of findings) {
    if (f.advisory) continue;
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  const score = 1 - SEVERITY_PENALTY[worst];
  return Math.max(0, Math.min(1, score));
}

/** Deterministic, total stringify of a JSON schema for scanning. */
function safeStringifySchema(schema: unknown): string {
  try {
    return JSON.stringify(schema) ?? "";
  } catch {
    return String(schema ?? "");
  }
}

/** Short human label for a signature regex, for the finding message. */
function describe(re: RegExp): string {
  return re.source.length > 48 ? `${re.source.slice(0, 45)}…` : re.source;
}

/** How much of the matched text a finding quotes back. */
const SPAN_MAX = 80;

/**
 * First match, with its position, without mutating the shared rule regex.
 *
 * The rules are module-level constants reused for every tool, so `lastIndex` must
 * never be left behind on them: a `g`-flagged rule would silently start scanning
 * the next tool from wherever the previous match ended. None of them carry `g`
 * today; this makes that a non-issue rather than an invariant to remember.
 */
function matchOf(re: RegExp, text: string): RegExpExecArray | null {
  return new RegExp(re.source, re.flags.replace(/[gy]/g, "")).exec(text);
}
