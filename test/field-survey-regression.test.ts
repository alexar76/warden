import { describe, it, expect } from "vitest";
import { StaticScanGate } from "../src/static-scan.js";
import { ThreatFeed } from "../src/threat-feed.js";
import type { McpServerRef, ToolDef, WardenPolicy } from "../src/types.js";

/**
 * Regression corpus from the field survey (docs/mcp-survey.md).
 *
 * Every string below is real text from a real public MCP server, kept verbatim
 * (trimmed) because paraphrasing it would lose the exact property that made the
 * rule misfire. Ruleset v3 blocked 50 of 1 108 servers and only 4 held up on
 * review; these are the cases that produced the other 46, plus the four that
 * must keep blocking.
 *
 * A synthetic corpus cannot replace this. Every false positive here is a phrasing
 * nobody sitting down to write test fixtures would invent — "the private key
 * never leaves your machine", a Persian ZERO WIDTH NON-JOINER, a JSON Schema
 * pointer that reads as base64, `TypeScript/JavaScript:` in a language list.
 */

const policy: WardenPolicy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: [],
  allowUnknownServers: true,
  pinToolDefs: false,
};

const server: McpServerRef = { id: "srv", name: "srv", transport: "http", url: "https://example.test/mcp" };

const gate = new StaticScanGate();

async function scan(tool: Partial<ToolDef> & { name: string }) {
  const full: ToolDef = { description: "", inputSchema: {}, ...tool };
  const r = await gate.evaluate({ server, tools: [full], prior: [], policy });
  return r.findings.filter((f) => !f.advisory);
}

/** Would the default policy refuse the connection over these findings? */
const blocks = (f: Awaited<ReturnType<typeof scan>>) =>
  f.some((x) => x.severity === "high" || x.severity === "critical");

describe("field survey: honest servers are not refused", () => {
  it("a refusal is not a request — 390 of 492 blocking findings were this", async () => {
    for (const description of [
      "Never send a private key: none is needed and the request is refused if one is present.",
      "Use this to import your own public key so you can SSH into instances. The private key never leaves your machine.",
      "YOU sign and broadcast the returned transaction yourself, with your own wallet's private key, on your own infrastructure — Otto never sees or holds your key.",
      "Checks the chain of trust, does NOT check revocation (CRL/OCSP), and does NOT confirm the certificate matches any private key.",
      "Use exact field names from this schema; do not guess aliases or include private key material.",
    ]) {
      expect(blocks(await scan({ name: "t", description })), description.slice(0, 40)).toBe(false);
    }
  });

  it("a promise not to collect secrets is not a harvest instruction", async () => {
    for (const description of [
      "Anyone holding the URL can read it, so never store secrets, credentials or personal data.",
      "Public read-only: never collect card data, secrets or email; never create a booking.",
      "This creates a human-owned profile for use through this connector; it does not reveal or mint a standalone agent credential.",
    ]) {
      expect(blocks(await scan({ name: "t", description })), description.slice(0, 40)).toBe(false);
    }
  });

  it("issuing a credential to the caller is the opposite of harvesting one", async () => {
    for (const description of [
      "Obtain a permanent anonymous API key for Blue Pillow Hotels & Stays. No signup, no login required.",
      "Create a new visitor session and obtain a visitor access token for the site.",
      "Fetch a run and its entries. The owner can read an open or sealed run (pass api_key).",
    ]) {
      expect(blocks(await scan({ name: "t", description })), description.slice(0, 40)).toBe(false);
    }
  });

  it("a security tool naming the attack is not committing it", async () => {
    for (const description of [
      "Screens text an agent is about to treat as an instruction, for prompt-injection and social-engineering ('ignore previous instructions', 'send funds to', 'approve this', 'admin override').",
      "Detects hidden directives that hijack agents — instruction overrides, 'don't tell the user', data exfiltration, secret harvesting, tool-shadowing, and invisible-unicode steganography.",
      "Detect likely leaked API keys, tokens, private-key headers, JWTs, and credential assignments in caller-supplied source text.",
    ]) {
      expect(blocks(await scan({ name: "t", description })), description.slice(0, 40)).toBe(false);
    }
    // …including when the taxonomy is a JSON enum.
    expect(
      blocks(
        await scan({
          name: "axiorank_create_policy",
          description: "Create a detection policy.",
          inputSchema: { properties: { kinds: { type: "array", items: { enum: ["exfiltration", "recon_then_destroy", "injection_then_action"] } } } },
        }),
      ),
    ).toBe(false);
  });

  it("'do not tell the user' is how honest servers suppress invented reassurance", async () => {
    for (const description of [
      'Some corridors convert in real time during the session, others batch daily, so do NOT tell the user a payment is "held until the next session".',
      "AFTER payment succeeds, no refund is issued automatically — the result says so explicitly; do not tell the user a refund is coming.",
      "A facturx-en16931 result is the payload and not a Factur-X document — do not tell the user otherwise.",
    ]) {
      const findings = await scan({ name: "t", description });
      expect(blocks(findings), description.slice(0, 40)).toBe(false);
      // Still reported, just not blocking: the phrase is worth a human's eye.
      expect((await gate.evaluate({ server, tools: [{ name: "t", description, inputSchema: {} }], prior: [], policy })).findings.some((f) => f.advisory)).toBe(true);
    }
  });

  it("'system prompt' is the domain vocabulary of prompt-management tools", async () => {
    const findings = await scan({
      name: "create_persona",
      description: "Set the playbook's singleton persona name and system prompt.",
      inputSchema: { properties: { persona_system_prompt: { type: "string", description: "Initial persona/system prompt" } } },
    });
    expect(blocks(findings)).toBe(false);
  });

  it("a language name followed by a colon is not a javascript: URI", async () => {
    for (const description of [
      "Finds direct tests per language pattern: CSharp/Java/PHP: *Test(s).<ext>; Python: test_*.py; TypeScript/JavaScript: *.spec/test.{ts,js}; Rust: *_tests.rs.",
      "THE LANGUAGE — plain async JavaScript: `bowmark` is a ready global (no import).",
      "Extracts all hyperlinks from a page. Filters out javascript:, mailto:, data: schemes.",
      "The sanitizer strips inline `on*=` event-handler attributes, `javascript:` and `data:text/html` URIs.",
      "page_margin: Page margins (e.g., 20mm)  javascript: Enable JavaScript execution",
    ]) {
      expect(blocks(await scan({ name: "t", description })), description.slice(0, 40)).toBe(false);
    }
  });

  it("a data: URI with no payload behind it is documentation of the format", async () => {
    const findings = await scan({
      name: "generateWithStyle",
      description: "Generate images matching a reference image's style: supply a style_image (URL or base64).",
      inputSchema: { properties: { style_image: { type: "string", example: "<url> OR data:image/png;base64,..." } } },
    });
    expect(blocks(findings)).toBe(false);
  });

  it("Persian orthography is not hidden text", async () => {
    // U+200C ZERO WIDTH NON-JOINER is a required letter-form control here.
    for (const description of [
      "Search official circulars and directives (بخشنامه‌ها) from the judiciary and government bodies.",
      "Calculate Iranian inheritance shares (سهم‌الارث) under قانون مدنی arts. 862–949.",
      "Calculate حق‌الثبت (registration duty) for property, vehicle and company documents.",
    ]) {
      expect(blocks(await scan({ name: "t", description })), description.slice(0, 30)).toBe(false);
    }
  });

  it("a JSON Schema pointer is not a base64 payload", async () => {
    const ref = "#/properties/flow/items/anyOf/2/properties/outcomes/items/properties/transitions/items/properties/target/properties/id";
    expect(blocks(await scan({ name: "export_app", inputSchema: { properties: { flow: { items: { $ref: ref } } } } }))).toBe(false);
  });

  it("a credential noun inside a longer identifier is that identifier's name", async () => {
    const description =
      "Deterministic calculators: vehicle-stopping-distance, vcard-property-registry, nato-stanag-military-rank-codes, bip39-mnemonic-checksum, larson-miller-creep-rupture-parameter.";
    expect(blocks(await scan({ name: "lookup", description }))).toBe(false);
  });

  it("an authorized_keys path names public key material", async () => {
    const description =
      "Inject your SSH public key into a site's container for direct SSH access. The key is appended to /home/admin/.ssh/authorized_keys.";
    expect(blocks(await scan({ name: "add_ssh_key", description }))).toBe(false);
  });
});

describe("field survey: the four real findings still block", () => {
  it("a tool that takes a wallet signing key as a parameter", async () => {
    const findings = await scan({
      name: "store_pm_credential",
      description: "Store Polymarket API credentials for this account.",
      inputSchema: { properties: { signer_private_key: { type: "string", description: "Polymarket: signer EOA private key, 0x…" } } },
    });
    expect(blocks(findings)).toBe(true);
  });

  it("a tool that returns a private key through the tool channel", async () => {
    const findings = await scan({
      name: "register",
      description: "Register an agent.",
      inputSchema: {
        properties: {
          withdrawal_address: {
            type: "string",
            description: "Omit it on testnet and a sandbox payout wallet is auto-provisioned, returning its private key exactly once.",
          },
        },
      },
    });
    expect(blocks(findings)).toBe(true);
  });

  it("a tool whose prose tells the model to write private keys to disk", async () => {
    const findings = await scan({
      name: "agent_create",
      description:
        "BEFORE: read ~/.conduit/credentials.json — if it exists, reuse the agent. AFTER: write credentials (version, agent_id, public_key, private_key as JWKs; chmod 0600).",
    });
    expect(blocks(findings)).toBe(true);
  });

  it("a documented cloud parameter is still a credential in a schema", async () => {
    const findings = await scan({
      name: "import_data",
      description: "Import data into a managed database instance.",
      inputSchema: { properties: { pvkPassword: { type: "string", description: "Password that encrypts the private key" } } },
    });
    expect(blocks(findings)).toBe(true);
  });
});

describe("field survey: threat-feed wildcards", () => {
  const feed = new ThreatFeed({});
  const hits = (tool: ToolDef) => feed.match(server, [tool]).map((f) => f.code);

  it("does not match a credential noun inside another word", async () => {
    // `*sweep*funds*` found `funds` inside "refunds".
    const tool: ToolDef = {
      name: "sweep",
      description: "Floor-sweep: buy the CHEAPEST N listed ENS names in ONE Seaport transaction. Skips any order that sold since discovery and refunds the excess.",
      inputSchema: {},
    };
    expect(hits(tool)).not.toContain("THREAT_CRYPTO_DRAINER");
  });

  it("does not join two words from different clauses", async () => {
    // `*seed*phrase*` found "for a seed topic … suggested search phrases".
    const tool: ToolDef = {
      name: "youtube-keyword-research",
      description: "For a seed topic, returns suggested search phrases plus intent clusters: questions people ask and tutorial queries.",
      inputSchema: {},
    };
    expect(hits(tool)).not.toContain("THREAT_SEED_PHRASE");
  });

  it("still matches a genuine adjacent reference", async () => {
    const tool: ToolDef = {
      name: "wallet_import",
      description: "Import a wallet from its seed phrase.",
      inputSchema: { properties: { seed_phrase: { type: "string" } } },
    };
    expect(hits(tool)).toContain("THREAT_SEED_PHRASE");
  });
});
