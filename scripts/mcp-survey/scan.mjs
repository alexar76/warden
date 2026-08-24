// Runs @aimarket/warden 0.3.0 (installed from the npm registry, not the monorepo)
// over tool definitions harvested live from public MCP servers.
import { readFileSync, writeFileSync } from "node:fs";
import { StaticScanGate, ThreatGate, ThreatFeed, staticScanRulesetRef, STATIC_SCAN_RULESET_VERSION } from "@aimarket/warden";

const IN = process.argv[2] ?? "../tools_raw.jsonl";
const OUT = process.argv[3] ?? "../scan_results.json";

const policy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: ["*delete*", "*transfer*", "*key*", "*secret*"],
  allowUnknownServers: true,   // survey: origin gate is host state, not a property of the server
  pinToolDefs: false,          // survey: no prior approval exists to drift from
};

const staticScan = new StaticScanGate();
const threatFeed = new ThreatFeed({});          // never load()ed -> built-in deny-list floor only
const threat = new ThreatGate(threatFeed);

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const blocks = (f) => !f.advisory && RANK[f.severity] >= RANK[policy.blockAtSeverity];

const rows = [];
for (const line of readFileSync(IN, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const rec = JSON.parse(line);
  if (rec.status !== "ok" || !Array.isArray(rec.tools) || rec.tools.length === 0) continue;
  const tools = rec.tools.map((t) => ({
    name: String(t.name ?? ""),
    description: String(t.description ?? ""),
    inputSchema: (t.inputSchema && typeof t.inputSchema === "object") ? t.inputSchema : {},
  }));
  const server = {
    id: rec.name, name: rec.server_info?.name ?? rec.name,
    transport: "http", url: rec.url, catalog: "registry.modelcontextprotocol.io",
  };
  const input = { server, tools, prior: [], policy };
  let ss, th;
  try { ss = await staticScan.evaluate(input); }
  catch (e) { rows.push({ server: rec.name, url: rec.url, error: `static-scan:${e.message}` }); continue; }
  try { th = await threat.evaluate({ ...input, prior: ss.findings }); }
  catch (e) { th = { findings: [], score: 1, error: e.message }; }
  const findings = [...ss.findings, ...th.findings];
  rows.push({
    server: rec.name,
    display: rec.server_info?.name ?? rec.title ?? rec.name,
    url: rec.url,
    toolCount: tools.length,
    staticScore: ss.score,
    threatScore: th.score,
    score: ss.score * th.score,
    fatal: Boolean(ss.fatal || th.fatal),
    wouldBlock: findings.some(blocks) || Boolean(ss.fatal || th.fatal),
    findings: findings.map((f) => ({ gate: f.gate, code: f.code, severity: f.severity, tool: f.tool, advisory: Boolean(f.advisory), message: f.message })),
  });
}
const out = {
  wardenVersion: JSON.parse(readFileSync("node_modules/@aimarket/warden/package.json", "utf8")).version,
  source: "registry.modelcontextprotocol.io (live tools/list over streamable-http)",
  ruleset: { version: STATIC_SCAN_RULESET_VERSION, ref: staticScanRulesetRef() },
  policy, scanned: rows.length, rows,
};
writeFileSync(OUT, JSON.stringify(out, null, 2));
console.log(`warden ${out.wardenVersion} ruleset v${out.ruleset.version} ${JSON.stringify(out.ruleset.ref)}`);
console.log(`scanned=${rows.length} withFindings=${rows.filter(r=>r.findings?.length).length} wouldBlock=${rows.filter(r=>r.wouldBlock).length}`);
