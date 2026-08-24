import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.js";
import type {
  RulesetRef,
  Severity,
  WardenFinding,
  WardenGate,
  WardenGateInput,
  WardenGateResult,
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

interface SignaturePattern {
  re: RegExp;
  code: string;
  severity: Severity;
  tier: Tier;
  /** Replaces the generic "matches <code> signature" wording when present. */
  note?: string;
}

// Imperative instructions aimed at the model — the classic injection tells.
const INJECTION_PATTERNS: SignaturePattern[] = [
  { re: /\bignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|preceding)\b/i, code: "TOOL_DEF_INJECTION", severity: "critical", tier: "block" },
  { re: /\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|instructions?|rules?)\b/i, code: "TOOL_DEF_INJECTION", severity: "critical", tier: "block" },
  { re: /\bdo\s+not\s+(?:tell|inform|mention|reveal\s+to|notify)\s+(?:the\s+)?user\b/i, code: "TOOL_DEF_INJECTION", severity: "critical", tier: "block" },
  { re: /\bwithout\s+(?:telling|informing|asking)\s+(?:the\s+)?user\b/i, code: "TOOL_DEF_INJECTION", severity: "high", tier: "block" },
  { re: /<\s*\/?\s*(?:system|instructions?|important)\s*>/i, code: "TOOL_DEF_INJECTION", severity: "high", tier: "block" },
  // A tool DEFINITION that talks about the model's own instructions is arguing
  // with the system prompt, not describing a capability. Honest servers describe
  // user-supplied prompts instead. This is the blocking rule most likely to need
  // a policy override — a prompt-management server may legitimately trip it.
  { re: /\b(?:system\s+prompt|developer\s+(?:message|prompt))\b/i, code: "TOOL_DEF_INJECTION", severity: "high", tier: "block" },
  // Ordinary English. Kept as a signal because it co-occurs with real poisoning,
  // demoted because on its own it is noise: "You must supply a subject."
  { re: /\byou\s+must\b/i, code: "TOOL_DEF_IMPERATIVE", severity: "low", tier: "advise" },
  { re: /\binstead\s+of\b/i, code: "TOOL_DEF_IMPERATIVE", severity: "info", tier: "advise" },
];

// Data-exfiltration phrasing.
const EXFIL_PATTERNS: SignaturePattern[] = [
  { re: /\bexfiltrat\w*/i, code: "TOOL_DEF_EXFIL", severity: "critical", tier: "block" },
  // Anchored on an EXTERNAL destination. Unanchored, this matched "Send the
  // message to the recipient" in any honest email or webhook tool.
  {
    re: /\b(?:send|post|forward|relay)\s+(?:it|them|this|the\s+\w+|all|results?|output|data|contents?)\s+to\s+(?:https?:\/\/|\b[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b)/i,
    code: "TOOL_DEF_EXFIL",
    severity: "high",
    tier: "block",
  },
  { re: /\b(?:post|send|put)\s+to\s+https?:\/\//i, code: "TOOL_DEF_EXFIL", severity: "critical", tier: "block" },
  { re: /\bupload\b[\s\S]{0,40}\bto\s+(?:https?:\/\/|[\w.-]+\.[a-z]{2,})/i, code: "TOOL_DEF_EXFIL", severity: "high", tier: "block" },
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
    re: /\b(?:read|extract|retrieve|fetch|obtain|dump|reveal|collect|harvest|grab|copy|print)\s[\s\S]{0,30}?\b(?:api[_\s-]?key|access[_\s-]?token|bearer\s+token|credential|password|passwd|secret|\.env\b|environment\s+variable)/i,
    code: "TOOL_DEF_SECRET_HARVEST",
    severity: "critical",
    tier: "block",
  },
  { re: /\bprivate[_\s-]?key\b/i, code: "TOOL_DEF_SECRET_REQUEST", severity: "critical", tier: "block" },
  { re: /\bseed[_\s-]?phrase\b|\bmnemonic\b/i, code: "TOOL_DEF_SECRET_REQUEST", severity: "critical", tier: "block" },
  { re: /~\/\.ssh|\bid_rsa\b|\.ssh\/[\w.-]+/i, code: "TOOL_DEF_SECRET_REQUEST", severity: "critical", tier: "block" },
  // Advisory: these are ordinary parameter names and ordinary setup prose.
  { re: /\bapi[_\s-]?key\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "low", tier: "advise" },
  { re: /\bcredentials?\b|\baccess[_\s-]?token\b|\bbearer\s+token\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "low", tier: "advise" },
  { re: /\bsecret(?:s)?\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "low", tier: "advise" },
  { re: /\bpassword\b|\bpasswd\b/i, code: "TOOL_DEF_CREDENTIAL_PARAM", severity: "medium", tier: "advise" },
  { re: /(?:^|[^.\w])\.env\b|\benvironment\s+variables?\b/i, code: "TOOL_DEF_ENV_REFERENCE", severity: "medium", tier: "advise" },
];

// Dangerous URL schemes embedded in text.
const URL_SCHEME_PATTERNS: SignaturePattern[] = [
  { re: /\bdata:[\w/+.-]+;base64,/i, code: "TOOL_DEF_DATA_URL", severity: "high", tier: "block" },
  { re: /\bjavascript:/i, code: "TOOL_DEF_DATA_URL", severity: "high", tier: "block" },
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
    note: "contains a long base64-encoded blob — possible hidden payload",
  },
  {
    // U+200B–200F, U+202A–202E, U+2060, U+FEFF. Built from a \u-escaped string so
    // the source stays reviewable (the characters are, by definition, invisible).
    re: new RegExp("[\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]"),
    code: "TOOL_DEF_HIDDEN_UNICODE",
    severity: "high",
    tier: "block",
    note: "contains zero-width or bidi control characters hiding text from review",
  },
];

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
 */
export const STATIC_SCAN_RULESET_VERSION = "2";

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
  /** The regex source, so a third party can re-run the exact rule. */
  source: string;
  flags: string;
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
    source: r.re.source,
    flags: r.re.flags,
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

  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const findings: WardenFinding[] = [];

    for (const tool of input.tools) {
      const schemaText = safeStringifySchema(tool.inputSchema);
      // Description is prose; schema text is field names + descriptions + enums.
      const haystacks: Array<{ text: string; where: string }> = [
        { text: tool.description ?? "", where: "description" },
        { text: schemaText, where: "input schema" },
      ];

      for (const { text, where } of haystacks) {
        for (const rule of RULES) {
          if (!rule.re.test(text)) continue;
          const finding: WardenFinding = {
            gate: this.name,
            severity: rule.severity,
            code: rule.code,
            message: rule.note
              ? `Tool "${tool.name}" ${where} ${rule.note}.`
              : `Tool "${tool.name}" ${where} matches ${rule.code} signature (${describe(rule.re)}).`,
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
