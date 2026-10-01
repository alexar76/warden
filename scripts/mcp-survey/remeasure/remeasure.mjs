// Re-scans a frozen survey corpus with every published @aimarket/warden release pinned in
// package.json (installed from the npm registry, not the monorepo), so the table in
// docs/mcp-survey.md can be recomputed by anyone from files in this repository.
//
//   npm ci
//   node remeasure.mjs <corpus.jsonl[.gz]> <out.json>      # write results
//   node remeasure.mjs <corpus.jsonl[.gz]> <out.json> --check   # recompute, exit 1 on any difference
//   node remeasure.mjs <corpus.jsonl[.gz]> --list 0.7.0      # print the servers one release blocks
//   node remeasure.mjs <corpus.jsonl[.gz]> --local ../../../dist   # same scan with an unpublished build
//
// `--local` is for a source tree that is not on npm yet (run `npm run build` in warden/ first). Its
// result is printed, never written: the committed result files pin published releases only.
//
// The scan is the one scan.mjs ran in the 2026-08-24 survey: same policy, StaticScanGate plus a
// ThreatGate over the built-in deny-list (the feed is never load()ed, so nothing is fetched).
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i < 0 ? undefined : args.splice(i, 2)[1] ?? ""; };
const listVersion = flag("--list");
const localDist = flag("--local");
const check = args.includes("--check") ? (args.splice(args.indexOf("--check"), 1), true) : false;
const [corpusPath, outPath] = args;
if (!corpusPath || (!outPath && listVersion === undefined && localDist === undefined)) {
  console.error("usage: node remeasure.mjs <corpus.jsonl[.gz]> <out.json> [--check] | <corpus> --list <version> | <corpus> --local <dist-dir>");
  process.exit(2);
}

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const lock = JSON.parse(readFileSync(new URL("./package-lock.json", import.meta.url), "utf8"));
const releases = Object.keys(pkg.dependencies).map((alias) => ({
  alias,
  version: alias.replace(/^warden-/, ""),
  integrity: lock.packages?.[`node_modules/${alias}`]?.integrity ?? null,
}));

const policy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: ["*delete*", "*transfer*", "*key*", "*secret*"],
  allowUnknownServers: true,   // survey: origin gate is host state, not a property of the server
  pinToolDefs: false,          // survey: no prior approval exists to drift from
};
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const blocks = (f) => !f.advisory && RANK[f.severity] >= RANK[policy.blockAtSeverity];

const raw = readFileSync(corpusPath);
const text = (corpusPath.endsWith(".gz") ? gunzipSync(raw) : raw).toString("utf8");
const records = text.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const servers = records
  .filter((r) => r.status === "ok" && Array.isArray(r.tools) && r.tools.length > 0)
  .map((r) => ({
    name: r.name,
    input: {
      server: { id: r.name, name: r.server_info?.name ?? r.name, transport: "http", url: r.url,
                catalog: "registry.modelcontextprotocol.io" },
      tools: r.tools.map((t) => ({
        name: String(t.name ?? ""),
        description: String(t.description ?? ""),
        inputSchema: (t.inputSchema && typeof t.inputSchema === "object") ? t.inputSchema : {},
      })),
      prior: [],
      policy,
    },
  }));

async function scanWith(release) {
  const w = await import(release.alias);
  const staticScan = new w.StaticScanGate();
  const threat = new w.ThreatGate(new w.ThreatFeed({}));
  const blocked = [];
  const byCode = {};
  let withFindings = 0, findingsTotal = 0, blockingFindings = 0, errors = 0;
  for (const s of servers) {
    const input = structuredClone(s.input);   // no release sees another's leftovers
    let ss, th;
    try { ss = await staticScan.evaluate(input); } catch { errors++; continue; }
    try { th = await threat.evaluate({ ...input, prior: ss.findings }); } catch { th = { findings: [] }; }
    const findings = [...ss.findings, ...th.findings];
    if (findings.length) withFindings++;
    findingsTotal += findings.length;
    for (const f of findings.filter(blocks)) { blockingFindings++; byCode[f.code] = (byCode[f.code] ?? 0) + 1; }
    if (findings.some(blocks) || ss.fatal || th.fatal) blocked.push(s.name);
  }
  blocked.sort();
  return {
    package: `@aimarket/warden@${release.version}`,
    integrity: release.integrity,
    ruleset: { version: w.STATIC_SCAN_RULESET_VERSION, ref: w.staticScanRulesetRef() },
    scanned: servers.length - errors,
    scan_errors: errors,
    clean: servers.length - errors - withFindings,
    with_findings: withFindings,
    blocked: blocked.length,
    findings_total: findingsTotal,
    blocking_findings: blockingFindings,
    advisory_findings: findingsTotal - blockingFindings,
    blocking_by_code: Object.fromEntries(Object.entries(byCode).sort(([a], [b]) => a.localeCompare(b))),
    // Names are left out on purpose, as in the survey report; the set is pinned by its hash and
    // `--list <version>` prints it from the committed corpus.
    blocked_set_sha256: createHash("sha256").update(blocked.join("\n")).digest("hex"),
    _blockedNames: blocked,
  };
}

if (listVersion !== undefined) {
  const release = releases.find((r) => r.version === listVersion);
  if (!release) { console.error(`no pinned release ${listVersion}`); process.exit(2); }
  for (const name of (await scanWith(release))._blockedNames) console.log(name);
  process.exit(0);
}

if (localDist !== undefined) {
  const r = await scanWith({ alias: pathToFileURL(resolve(localDist, "index.js")).href, version: "local", integrity: null });
  console.log(`local build ${localDist}  ruleset v${r.ruleset.version} ${r.ruleset.ref.digest}  blocked=${r.blocked}  blocking_findings=${r.blocking_findings}  with_findings=${r.with_findings}`);
  for (const name of r._blockedNames) console.log(name);
  process.exit(0);
}

const results = [];
for (const release of releases) results.push(await scanWith(release));

// The 50 servers the 2026-08-24 run blocked, as named in its committed dataset: how many are
// still in this corpus, and how many of those each release blocks today. Their definitions may
// have changed since August, so this is a cross-check, not a re-run of August.
const august = JSON.parse(readFileSync(new URL("../../../docs/data/mcp-survey-2026-08-24.json", import.meta.url), "utf8"));
const augustBlocked = new Set(august.blocked_servers.map((b) => b.server));
const present = new Set(servers.map((s) => s.name).filter((n) => augustBlocked.has(n)));

const out = {
  corpus: {
    file: corpusPath.split("/").pop(),
    sha256: createHash("sha256").update(text).digest("hex"),
    records: records.length,
    servers_with_tools: servers.length,
    tool_definitions: servers.reduce((n, s) => n + s.input.tools.length, 0),
  },
  policy,
  releases: results.map(({ _blockedNames, ...r }) => r),
  august_blocked_cross_check: {
    august_blocked: augustBlocked.size,
    present_in_this_corpus: present.size,
    still_blocked_by: Object.fromEntries(results.map((r) => [r.package, r._blockedNames.filter((n) => present.has(n)).length])),
  },
};

const json = JSON.stringify(out, null, 2) + "\n";
if (check) {
  const committed = readFileSync(outPath, "utf8");
  if (committed !== json) {
    console.error(`MISMATCH: ${outPath} does not match a fresh scan of ${corpusPath}`);
    process.exit(1);
  }
  console.log(`OK: ${outPath} reproduces from ${corpusPath}`);
} else {
  writeFileSync(outPath, json);
}
for (const r of out.releases) {
  console.log(`${r.package.padEnd(24)} ruleset v${r.ruleset.version}  blocked=${r.blocked}  blocking_findings=${r.blocking_findings}  with_findings=${r.with_findings}`);
}
