/**
 * MCP tool surface for the WARDEN stdio server.
 *
 * These definitions are scored by Glama TDQS. Each tool: a title longer than
 * the name, when-to-use / when-not naming a sibling, MCP annotations that match
 * behaviour, every input property described, and an output schema so the
 * description does not have to narrate the return shape.
 *
 * All six tools are local, deterministic, and perform no network I/O. The
 * stdio process uses the built-in threat-feed floor and an empty pin store —
 * it is a scanner, not a long-lived host.
 */

import {
  CanonicalizationError,
  EgressGuard,
  StaticScanGate,
  ThreatFeed,
  Warden,
  canonicalize,
  classifyTools,
  parseJsonStrict,
  staticScanRuleset,
} from "./index.js";
import type {
  McpServerRef,
  Severity,
  ToolDef,
  WardenFinding,
  WardenPolicy,
  WardenVerdict,
} from "./types.js";

export const MAX_TOOLS = 256;
export const MAX_STRING = 16_384;
export const MAX_PAYLOAD_CHARS = 256_000;

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export const DEFAULT_MCP_POLICY: WardenPolicy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: [],
  allowUnknownServers: true,
  pinToolDefs: true,
};

export interface McpToolDef {
  name: string;
  title: string;
  description: string;
  annotations: {
    title: string;
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
}

const TOOL_DEF_ITEM = {
  type: "object",
  additionalProperties: false,
  required: ["name", "description", "inputSchema"],
  properties: {
    name: {
      type: "string",
      minLength: 1,
      maxLength: 256,
      description:
        "Exact tool name as advertised by tools/list. Matched case-sensitively against findings.tool and against sensitive glob patterns.",
    },
    description: {
      type: "string",
      maxLength: MAX_STRING,
      description:
        "Advertised description string from tools/list. This is prompt text the model would see; WARDEN scans it. Pass the server's text unmodified — rewriting it hides the injection surface.",
    },
    inputSchema: {
      type: "object",
      description:
        "JSON Schema object from tools/list (type/properties/required/…). Pass through as-is. WARDEN stringifies it and scans field names, descriptions, and enums. Do not invent properties the server did not advertise.",
    },
  },
} as const;

const FINDING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["gate", "severity", "code", "message"],
  properties: {
    gate: { type: "string", description: "Gate that produced the finding: static-scan, threat-feed, origin, or pinning." },
    severity: { type: "string", enum: SEVERITIES, description: "Attention rank. Independent of whether the finding blocks." },
    code: { type: "string", description: "Stable machine code, e.g. TOOL_DEF_INJECTION or THREAT_TOOL_MATCH." },
    message: { type: "string", description: "Human-readable finding, including the matched span where a static-scan rule fired." },
    tool: { type: "string", description: "Tool name the finding refers to, when the defect is per-tool rather than server-wide." },
    advisory: {
      type: "boolean",
      description: "When true the finding is report-only: it never blocks and never costs a tool, at any blockAtSeverity.",
    },
  },
} as const;

const RULESET_REF_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["version", "digest"],
  properties: {
    version: { type: "string", description: "Monotonic static-scan ruleset version (currently \"4\")." },
    digest: {
      type: "string",
      description: "sha256-<base64> over the RFC 8785 canonical form of the published rule table. A recorded scan is not reproducible without this.",
    },
  },
} as const;

export const MCP_TOOLS: McpToolDef[] = [
  {
    name: "vet_mcp_server",
    title: "Vet an MCP server through the full WARDEN gate chain",
    description:
      "Run WARDEN's ordered gate chain (static-scan → threat-feed → origin → pinning) over a server identity plus its advertised tools/list payload and return a recordable verdict (allow/block, 0..1 product score, findings, allowedTools/blockedTools, ruleset digest).\n\n" +
      "When to use: you have a complete server record and want the same decision a host should make before any of those tool definitions reach the model. Prefer this over calling the four gates yourself.\n\n" +
      "When NOT to use: inspecting descriptions only (call static_scan_tools — no origin/pinning); splitting tools by operator glob (classify_sensitive_tools); checking one outbound URL (check_egress_url); producing RFC 8785 bytes (canonicalize_json).\n\n" +
      "Behaviour: local, deterministic, no network. This stdio process uses the built-in 11-record threat floor (it does not fetch a signed feed) and an empty in-memory pin store, so every server is first-contact: TOOL_DEF_UNPINNED is advisory and does not block. Origin defaults to allowUnknownServers=true so catalog-discovered servers are not fail-closed. Override policy when you need the host's real knobs. Does not connect to, start, or approve the target server.\n\n" +
      "Returns structured JSON matching outputSchema. Example: vet_mcp_server({ server: { id: \"demo@0\", name: \"demo\", transport: \"stdio\", command: \"npx\" }, tools: [{ name: \"add\", description: \"Add two integers.\", inputSchema: { type: \"object\" } }] }).",
    annotations: {
      title: "Vet an MCP server through the full WARDEN gate chain",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["server", "tools"],
      properties: {
        server: {
          type: "object",
          additionalProperties: false,
          required: ["id", "name", "transport"],
          description:
            "Identity of the MCP server being vetted — the host's McpServerRef, not a live connection. WARDEN never launches this command or fetches this URL.",
          properties: {
            id: {
              type: "string",
              minLength: 1,
              maxLength: 256,
              description: "Stable server id the host uses for pins and logs (e.g. \"github@1\"). Findings quote this id.",
            },
            name: {
              type: "string",
              minLength: 1,
              maxLength: 256,
              description: "Human-facing server name. Threat-feed server-scope patterns match this field.",
            },
            transport: {
              type: "string",
              enum: ["stdio", "sse", "http"],
              description: "How the host would launch the server. stdio uses command/args; sse/http use url. WARDEN does not open the transport.",
            },
            command: {
              type: "string",
              maxLength: 1024,
              description: "stdio executable (e.g. \"npx\"). Required for a realistic stdio identity hash; omit for url transports.",
            },
            args: {
              type: "array",
              items: { type: "string", maxLength: 1024 },
              maxItems: 32,
              description: "stdio argv. Included in the launch-identity hash used by pinning. Omit when unused.",
            },
            url: {
              type: "string",
              maxLength: 2048,
              description: "sse/http endpoint. Threat-feed and identity hashing see this string; this tool does not request it.",
            },
            catalog: {
              type: "string",
              maxLength: 256,
              description:
                "Remote catalog this server was discovered from. When set and policy.allowUnknownServers is false, the origin gate fail-closes. Omit for operator-declared servers.",
            },
          },
        },
        tools: {
          type: "array",
          minItems: 1,
          maxItems: MAX_TOOLS,
          description:
            "Exact tools/list payload (1..256 tools). Each item is name + description + inputSchema from the server. Do not filter before vetting — blockedTools is the partition.",
          items: TOOL_DEF_ITEM,
        },
        policy: {
          type: "object",
          additionalProperties: false,
          description:
            "Optional WardenPolicy overlay. Omitted keys keep the stdio defaults: blockAtSeverity=high, empty sensitiveToolPatterns, allowUnknownServers=true, pinToolDefs=true. Use classify_sensitive_tools when you only want the glob split.",
          properties: {
            blockAtSeverity: {
              type: "string",
              enum: SEVERITIES,
              description:
                "Block the whole connection when any non-advisory finding reaches this severity. Default high. advisory findings never block, even at info.",
            },
            sensitiveToolPatterns: {
              type: "array",
              items: { type: "string", maxLength: 128 },
              maxItems: 64,
              description:
                "Case-insensitive * globs matched against tool names. Hits are still advertised; they go to blockedTools only when a finding also trips. For a glob-only split, call classify_sensitive_tools.",
            },
            allowUnknownServers: {
              type: "boolean",
              description:
                "When false, servers that carry server.catalog are refused by the origin gate. Default true on this stdio scanner so you can inspect catalog entries without declaring them.",
            },
            pinToolDefs: {
              type: "boolean",
              description:
                "When true, tool-def drift after a stored pin is fatal. This process has an empty pin store, so first contact stays UNPINNED/advisory. Default true.",
            },
          },
        },
      },
    },
    outputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["allow", "score", "findings", "allowedTools", "blockedTools", "rulesets"],
      properties: {
        allow: { type: "boolean", description: "false when a gate was fatal or a non-advisory finding reached blockAtSeverity." },
        score: {
          type: "number",
          minimum: 0,
          maximum: 1,
          description: "Product of per-gate scores in [0, 1]. One bad gate drags the whole server down; it is not an average.",
        },
        decidedBy: { type: "string", description: "Gate that produced the blocking decision, present only when allow is false." },
        findings: { type: "array", items: FINDING_SCHEMA, description: "Accumulated findings across all gates, including advisory." },
        allowedTools: { type: "array", items: { type: "string" }, description: "Tool names the host may expose to the model." },
        blockedTools: { type: "array", items: { type: "string" }, description: "Tool names quarantined; the rest of the server may still be usable." },
        rulesets: {
          type: "object",
          additionalProperties: false,
          required: ["staticScan"],
          properties: { staticScan: RULESET_REF_SCHEMA },
          description: "Rule-table identity in force for this verdict. Store this with the scan.",
        },
      },
    },
  },
  {
    name: "static_scan_tools",
    title: "Static-scan MCP tool definitions for injection and exfil",
    description:
      "Run only the static-scan gate (ruleset v4, 25 signatures with context guards) over advertised tool names, descriptions, and input schemas. Returns findings, a 0..1 gate score, and the published ruleset digest.\n\n" +
      "When to use: you have a tools/list dump and want injection / credential / hidden-Unicode hits without origin, pinning, or the threat feed. Cheaper and narrower than vet_mcp_server.\n\n" +
      "When NOT to use: you need the full host decision (vet_mcp_server); you want operator glob classification (classify_sensitive_tools); you want the published rule table itself (list_scan_rules).\n\n" +
      "Behaviour: local regex+guard evaluation, no network, no mutation. Advisory-tier hits are reported with advisory=true and do not reduce the score. Does not launch servers or send tool output to a model.\n\n" +
      "Returns structured JSON matching outputSchema. Example: static_scan_tools({ tools: [{ name: \"add\", description: \"Add two integers.\", inputSchema: { type: \"object\" } }] }).",
    annotations: {
      title: "Static-scan MCP tool definitions for injection and exfil",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["tools"],
      properties: {
        tools: {
          type: "array",
          minItems: 1,
          maxItems: MAX_TOOLS,
          description: "tools/list items to scan (1..256). Same shape as vet_mcp_server.tools.",
          items: TOOL_DEF_ITEM,
        },
      },
    },
    outputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["score", "findings", "ruleset"],
      properties: {
        score: {
          type: "number",
          minimum: 0,
          maximum: 1,
          description: "static-scan gate contribution: 1 minus the penalty for the worst non-advisory severity. Advisory hits do not change this number.",
        },
        findings: { type: "array", items: FINDING_SCHEMA, description: "Hits from the 25-rule table, including advisory-only codes." },
        ruleset: RULESET_REF_SCHEMA,
      },
    },
  },
  {
    name: "classify_sensitive_tools",
    title: "Classify MCP tools as sensitive vs safe by glob policy",
    description:
      "Split advertised tool names into sensitive vs safe using the operator's case-insensitive * globs (the same policy.sensitiveToolPatterns a host would use). Sensitive tools stay advertised; they require per-call approval — this tool does not run them.\n\n" +
      "When to use: show the user which names will need confirmation before they approve a server, or to preview a glob set. This is policy over identifiers, not an injection scan.\n\n" +
      "When NOT to use: scanning descriptions for poisoning (static_scan_tools or vet_mcp_server); checking whether a URL is allowed out (check_egress_url).\n\n" +
      "Behaviour: local glob match, no network. An empty patterns array marks every tool safe. Patterns match the whole name; \"*delete*\" hits create_delete_repo. Does not call Warden.vet and does not persist anything.\n\n" +
      "Returns { sensitive, safe }. Example: classify_sensitive_tools({ tools: [{ name: \"delete_repo\", description: \"Delete a repository.\", inputSchema: { type: \"object\" } }], patterns: [\"*delete*\"] }).",
    annotations: {
      title: "Classify MCP tools as sensitive vs safe by glob policy",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["tools", "patterns"],
      properties: {
        tools: {
          type: "array",
          minItems: 1,
          maxItems: MAX_TOOLS,
          description: "tools/list items whose names will be classified. Descriptions and schemas are ignored; only name is matched.",
          items: TOOL_DEF_ITEM,
        },
        patterns: {
          type: "array",
          items: { type: "string", minLength: 1, maxLength: 128 },
          maxItems: 64,
          description:
            "Operator globs, case-insensitive, matched against the whole tool name. \"*\" is the only wildcard. Empty array → every tool is safe. Same semantics as WardenPolicy.sensitiveToolPatterns, not threat-feed matching.",
        },
      },
    },
    outputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["sensitive", "safe"],
      properties: {
        sensitive: { type: "array", items: { type: "string" }, description: "Names matching at least one pattern. Still advertised; require per-call approval." },
        safe: { type: "array", items: { type: "string" }, description: "Names matching no pattern." },
      },
    },
  },
  {
    name: "check_egress_url",
    title: "Check a URL against a WARDEN egress allowlist",
    description:
      "Ask EgressGuard whether a URL's hostname is on an operator allowlist. A tool reaching a host you never listed is the classic phone-home tell. Empty allowlist blocks everything (fail-closed), not everything-allowed.\n\n" +
      "When to use: a tool is about to fetch/post and you want the same check a host should wrap around that request. Hostnames match case-insensitively; \"*.example.com\" matches subdomains, not the apex.\n\n" +
      "When NOT to use: vetting tool definitions (vet_mcp_server / static_scan_tools); canonicalizing JSON (canonicalize_json). This does not fetch the URL and does not inspect tool text.\n\n" +
      "Behaviour: local URL parse + hostname match. Unparseable URLs are refused. No DNS, no HTTP. Idempotent.\n\n" +
      "Returns { allowed, host?, reason? }. Example: check_egress_url({ url: \"https://api.github.com/repos\", allowlist: [\"api.github.com\", \"*.internal.example.com\"] }).",
    annotations: {
      title: "Check a URL against a WARDEN egress allowlist",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url", "allowlist"],
      properties: {
        url: {
          type: "string",
          minLength: 1,
          maxLength: 2048,
          description:
            "Absolute URL the tool wants to open (https://host/path). Only the hostname is compared; path, query, and credentials are not allowlisted separately. Must be parseable by the WHATWG URL parser.",
        },
        allowlist: {
          type: "array",
          items: { type: "string", maxLength: 253 },
          maxItems: 256,
          description:
            "Permitted hostnames. Exact match, or leading \"*.\" for subdomains (\"*.example.com\" matches api.example.com, not example.com). Empty array blocks every host. Entries are trimmed and compared case-insensitively.",
        },
      },
    },
    outputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["allowed"],
      properties: {
        allowed: { type: "boolean", description: "true only when the hostname matches an allowlist entry." },
        host: { type: "string", description: "Parsed hostname when the URL was valid." },
        reason: { type: "string", description: "Why the request is blocked; omitted when allowed is true." },
      },
    },
  },
  {
    name: "canonicalize_json",
    title: "Canonicalize JSON with RFC 8785 (JCS) bytes",
    description:
      "Return the RFC 8785 JSON Canonicalization Scheme serialization WARDEN uses for threat-feed signatures and tool-def pins, so another implementation can byte-check against it. Integers only inside ±(2^53−1); lone surrogates and non-integers are refused with a reason code, not escaped.\n\n" +
      "When to use: you are publishing or verifying a signed threat feed, hashing tool defs, or comparing two JSON documents that must agree regardless of key order. Subpath @aimarket/warden/jcs is the same function.\n\n" +
      "When NOT to use: scanning tool defs (static_scan_tools); pretty-printing for humans (this output is for bytes, not display).\n\n" +
      "Behaviour: local, no network. Pass either a parsed JSON value or a JSON string (string is parsed with parseJsonStrict first). Failure returns isError with CanonicalizationCode — it does not emit partial bytes.\n\n" +
      "Returns { canonical } or an error. Example: canonicalize_json({ value: { b: 1, a: 2 } }) → {\"a\":2,\"b\":1}.",
    annotations: {
      title: "Canonicalize JSON with RFC 8785 (JCS) bytes",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["value"],
      properties: {
        value: {
          description:
            "JSON value to canonicalize, or a JSON string to parse first. Objects have keys sorted by UTF-16 code units. Numbers must be integers in ±(2^53−1). Do not pass undefined, functions, or cyclic structures.",
        },
      },
    },
    outputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["canonical"],
      properties: {
        canonical: {
          type: "string",
          description: "RFC 8785 canonical JSON text (UTF-8-ready string). Hash or sign these bytes, not JSON.stringify output.",
        },
      },
    },
  },
  {
    name: "list_scan_rules",
    title: "List the published WARDEN static-scan rule table",
    description:
      "Return the in-force static-scan ruleset: version, digest, and every rule's code, severity, tier (block vs advise), surfaces (name / description / inputSchema), optional regex source, and named guards. A recorded verdict is only reproducible together with this identity.\n\n" +
      "When to use: explain a finding code, confirm you are on ruleset v4, or re-run a scan with the same table. include_source=true adds the regex source and flags for an independent re-implementation.\n\n" +
      "When NOT to use: evaluating a live tools/list (static_scan_tools or vet_mcp_server — those apply the table). This tool does not scan anything.\n\n" +
      "Behaviour: local snapshot of the compiled rule table, no network, no mutation. Digest is sha256 over the RFC 8785 form of {version, rules}.\n\n" +
      "Returns the ruleset object. Example: list_scan_rules({ include_source: false }).",
    annotations: {
      title: "List the published WARDEN static-scan rule table",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        include_source: {
          type: "boolean",
          default: false,
          description:
            "When true, each rule includes source (regex body) and flags so a third party can re-run the exact pattern. Default false — identity, tier, surfaces, and guards only, smaller payload.",
        },
      },
    },
    outputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["version", "digest", "rules"],
      properties: {
        version: { type: "string", description: "Monotonic ruleset version." },
        digest: { type: "string", description: "sha256-<base64> of the canonical rule table." },
        rules: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["code", "severity", "tier", "surfaces", "guards"],
            properties: {
              code: { type: "string", description: "Finding code this rule emits." },
              severity: { type: "string", enum: SEVERITIES, description: "Attention rank when the rule fires." },
              tier: { type: "string", enum: ["block", "advise"], description: "block can refuse a connection; advise is report-only." },
              surfaces: {
                type: "array",
                items: { type: "string", enum: ["name", "description", "inputSchema"] },
                description: "Which tool-def fields the rule is run against.",
              },
              guards: { type: "array", items: { type: "string" }, description: "Named context guards that can drop a regex match (polarity, mention, …)." },
              source: { type: "string", description: "Regex source; only when include_source is true." },
              flags: { type: "string", description: "Regex flags; only when include_source is true." },
            },
          },
        },
      },
    },
  },
];

export const MCP_INSTRUCTIONS =
  "WARDEN — MCP security firewall over stdio. Library first; these tools expose the same gates a host would call before any third-party tools/list reaches the model.\n\n" +
  "Tools:\n" +
  "• vet_mcp_server — full chain (static-scan → threat-feed → origin → pinning)\n" +
  "• static_scan_tools — injection/exfil scan only\n" +
  "• classify_sensitive_tools — operator glob split (not an injection scan)\n" +
  "• check_egress_url — hostname allowlist, fail-closed on empty list\n" +
  "• canonicalize_json — RFC 8785 bytes for feeds and pins\n" +
  "• list_scan_rules — published rule table + digest\n\n" +
  "No network, no secrets required. Do not pass live credentials inside tool descriptions you are scanning — they will be echoed in findings. This process does not start other MCP servers.";

let feedReady: Promise<ThreatFeed> | undefined;

async function builtinFeed(): Promise<ThreatFeed> {
  if (!feedReady) {
    feedReady = (async () => {
      const feed = new ThreatFeed();
      await feed.load();
      return feed;
    })();
  }
  return feedReady;
}

function asTools(raw: unknown): ToolDef[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new McpToolError("tools must be a non-empty array");
  }
  if (raw.length > MAX_TOOLS) {
    throw new McpToolError(`at most ${MAX_TOOLS} tools per call`);
  }
  return raw.map((item, i) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new McpToolError(`tools[${i}] must be an object`);
    }
    const rec = item as Record<string, unknown>;
    const name = rec.name;
    const description = rec.description;
    if (typeof name !== "string" || !name) throw new McpToolError(`tools[${i}].name is required`);
    if (typeof description !== "string") throw new McpToolError(`tools[${i}].description is required`);
    if (description.length > MAX_STRING) throw new McpToolError(`tools[${i}].description exceeds ${MAX_STRING} chars`);
    if (!rec.inputSchema || typeof rec.inputSchema !== "object" || Array.isArray(rec.inputSchema)) {
      throw new McpToolError(`tools[${i}].inputSchema must be a JSON object`);
    }
    return {
      name,
      description,
      inputSchema: rec.inputSchema as ToolDef["inputSchema"],
    };
  });
}

function asServer(raw: unknown): McpServerRef {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new McpToolError("server must be an object");
  }
  const rec = raw as Record<string, unknown>;
  const transport = rec.transport;
  if (transport !== "stdio" && transport !== "sse" && transport !== "http") {
    throw new McpToolError("server.transport must be stdio, sse, or http");
  }
  if (typeof rec.id !== "string" || !rec.id) throw new McpToolError("server.id is required");
  if (typeof rec.name !== "string" || !rec.name) throw new McpToolError("server.name is required");
  const ref: McpServerRef = { id: rec.id, name: rec.name, transport };
  if (typeof rec.command === "string") ref.command = rec.command;
  if (Array.isArray(rec.args)) ref.args = rec.args.map(String);
  if (typeof rec.url === "string") ref.url = rec.url;
  if (typeof rec.catalog === "string") ref.catalog = rec.catalog;
  return ref;
}

function asPolicy(raw: unknown): WardenPolicy {
  const policy: WardenPolicy = { ...DEFAULT_MCP_POLICY };
  if (raw == null) return policy;
  if (typeof raw !== "object" || Array.isArray(raw)) throw new McpToolError("policy must be an object");
  const rec = raw as Record<string, unknown>;
  if (rec.blockAtSeverity != null) {
    if (!SEVERITIES.includes(rec.blockAtSeverity as Severity)) {
      throw new McpToolError(`policy.blockAtSeverity must be one of ${SEVERITIES.join(", ")}`);
    }
    policy.blockAtSeverity = rec.blockAtSeverity as Severity;
  }
  if (rec.sensitiveToolPatterns != null) {
    if (!Array.isArray(rec.sensitiveToolPatterns)) throw new McpToolError("policy.sensitiveToolPatterns must be an array");
    policy.sensitiveToolPatterns = rec.sensitiveToolPatterns.map(String);
  }
  if (typeof rec.allowUnknownServers === "boolean") policy.allowUnknownServers = rec.allowUnknownServers;
  if (typeof rec.pinToolDefs === "boolean") policy.pinToolDefs = rec.pinToolDefs;
  return policy;
}

export class McpToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "McpToolError";
  }
}

export interface ToolCallResult {
  structured: object;
}

export async function callMcpTool(name: string, args: Record<string, unknown>): Promise<ToolCallResult> {
  switch (name) {
    case "vet_mcp_server":
      return { structured: { ...(await vetMcpServer(args)) } };
    case "static_scan_tools":
      return { structured: await staticScan(args) };
    case "classify_sensitive_tools":
      return { structured: classify(args) };
    case "check_egress_url":
      return { structured: checkEgress(args) };
    case "canonicalize_json":
      return { structured: canon(args) };
    case "list_scan_rules":
      return { structured: listRules(args) };
    default:
      throw new McpToolError(`unknown tool "${name}"`);
  }
}

async function vetMcpServer(args: Record<string, unknown>): Promise<WardenVerdict> {
  const tools = asTools(args.tools);
  const server = asServer(args.server);
  const policy = asPolicy(args.policy);
  const threatFeed = await builtinFeed();
  const pins = new Map();
  const warden = Warden.create({
    policy,
    threatFeed,
    store: {
      getPin: async (id) => pins.get(id),
      putPin: async (p) => void pins.set(p.serverId, p),
    },
  });
  return warden.vet(server, tools);
}

async function staticScan(args: Record<string, unknown>): Promise<{
  score: number;
  findings: WardenFinding[];
  ruleset: { version: string; digest: string };
}> {
  const tools = asTools(args.tools);
  const gate = new StaticScanGate();
  const result = await gate.evaluate({
    server: { id: "scan@0", name: "scan", transport: "stdio" },
    tools,
    prior: [],
    policy: DEFAULT_MCP_POLICY,
  });
  const ruleset = staticScanRuleset();
  return { score: result.score, findings: result.findings, ruleset: { version: ruleset.version, digest: ruleset.digest } };
}

function classify(args: Record<string, unknown>): { sensitive: string[]; safe: string[] } {
  const tools = asTools(args.tools);
  if (!Array.isArray(args.patterns)) throw new McpToolError("patterns must be an array");
  const patterns = args.patterns.map(String);
  return classifyTools(tools, { ...DEFAULT_MCP_POLICY, sensitiveToolPatterns: patterns });
}

function checkEgress(args: Record<string, unknown>): { allowed: boolean; host?: string; reason?: string } {
  if (typeof args.url !== "string" || !args.url) throw new McpToolError("url is required");
  if (!Array.isArray(args.allowlist)) throw new McpToolError("allowlist must be an array");
  const guard = new EgressGuard(args.allowlist.map(String));
  const result = guard.check(args.url);
  let host: string | undefined;
  try {
    host = new URL(args.url).hostname;
  } catch {
    host = undefined;
  }
  return result.allowed ? { allowed: true, host } : { allowed: false, host, reason: result.reason };
}

function canon(args: Record<string, unknown>): { canonical: string } {
  let value: unknown = args.value;
  if (typeof value === "string") {
    try {
      value = parseJsonStrict(value);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new McpToolError(`value string is not strict JSON (${detail})`);
    }
  }
  try {
    return { canonical: canonicalize(value) };
  } catch (err) {
    if (err instanceof CanonicalizationError) throw new McpToolError(`${err.code}: ${err.message}`);
    throw err;
  }
}

function listRules(args: Record<string, unknown>): Record<string, unknown> {
  const includeSource = args.include_source === true;
  const ruleset = staticScanRuleset();
  const rules = ruleset.rules.map((r) => {
    const row: Record<string, unknown> = {
      code: r.code,
      severity: r.severity,
      tier: r.tier,
      surfaces: r.surfaces,
      guards: r.guards,
    };
    if (includeSource) {
      row.source = r.source;
      row.flags = r.flags;
    }
    return row;
  });
  return { version: ruleset.version, digest: ruleset.digest, rules };
}

export function payloadTooLarge(args: unknown): boolean {
  try {
    return JSON.stringify(args ?? {}).length > MAX_PAYLOAD_CHARS;
  } catch {
    return true;
  }
}
