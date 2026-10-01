import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { staticScanRuleset, STATIC_SCAN_RULESET_VERSION, ThreatFeed } from "../src/index.js";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const LANDING = join(root, "docs", "landing", "index.html");
const SURVEY = join(root, "docs", "mcp-survey.md");
const html = readFileSync(LANDING, "utf8");

const LANGS = ["en", "ru", "es", "fr", "zh"] as const;

/**
 * The landing quotes numbers, and a landing page is exactly where a stale number
 * survives longest: nothing imports it, no build step reads it, and the person who
 * changes the rule table is not the person looking at the marketing copy. Ruleset
 * v3 shipped as "v2" in a published package for the same reason.
 *
 * So every figure on the page is checked against the thing it describes.
 */
describe("landing page", () => {
  it("exists and is self-contained", () => {
    expect(existsSync(LANDING)).toBe(true);
    // A firewall's own page fetching a CDN font would be a poor advertisement.
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/<link[^>]+rel=["']stylesheet["']/i);
    expect(html).not.toMatch(/src=["']https?:/i);
    expect(html.trimEnd().endsWith("</html>")).toBe(true);
  });

  it("offers all five languages, and translates every string in each", () => {
    for (const lang of LANGS) {
      expect(html, `hreflang ${lang}`).toContain(`hreflang="${lang}"`);
      expect(html, `switcher ${lang}`).toContain(`data-lang="${lang}"`);
    }
    const keys = [...html.matchAll(/data-i18n="([^"]+)"/g)].map((m) => m[1]!);
    expect(keys.length).toBeGreaterThan(60);

    // The dictionaries are inlined as one JSON object literal after `const DICT = `.
    const start = html.indexOf("const DICT = ");
    expect(start).toBeGreaterThan(-1);
    const open = html.indexOf("{", start);
    let depth = 0;
    let end = open;
    for (let i = open; i < html.length; i++) {
      if (html[i] === "{") depth++;
      else if (html[i] === "}") {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    const dict = JSON.parse(html.slice(open, end + 1)) as Record<string, Record<string, string>>;
    // English is snapshotted from the markup on purpose, so it must NOT be here.
    expect(Object.keys(dict).sort()).toEqual(["es", "fr", "ru", "zh"]);
    for (const [lang, table] of Object.entries(dict)) {
      const missing = keys.filter((k) => typeof table[k] !== "string" || table[k]!.length === 0);
      expect(missing, `${lang} is missing: ${missing.join(", ")}`).toEqual([]);
      const extra = Object.keys(table).filter((k) => !keys.includes(k));
      expect(extra, `${lang} has keys the page does not use: ${extra.join(", ")}`).toEqual([]);
    }
  });

  it("quotes the ruleset that actually ships", () => {
    const rs = staticScanRuleset();
    const block = rs.rules.filter((r) => r.tier === "block").length;
    const advise = rs.rules.filter((r) => r.tier === "advise").length;
    const named = rs.rules.filter((r) => r.surfaces.includes("name")).length;

    expect(html).toContain(`ruleset v${STATIC_SCAN_RULESET_VERSION}`.replace("ruleset ", "")); // "v4" appears
    expect(html, "rule count").toContain(`${rs.rules.length} rules`);
    expect(html, "tier split").toContain(`${block} can block`);
    expect(html, "tier split").toContain(`${advise} are advisory-only`);
    expect(html, "name surface").toContain(`${named} also cover the name`);
    // The digest is quoted truncated in the verdict sample; the prefix must be real.
    const prefix = rs.digest.slice(0, "sha256-klRyTiD3".length);
    expect(html, `digest prefix ${prefix}`).toContain(prefix);
    expect(html, "built-in floor").toContain(`${new ThreatFeed().builtins.length} built-in`);
  });

  it("quotes the field survey as the survey reports it", () => {
    const survey = readFileSync(SURVEY, "utf8");
    for (const figure of ["1 108", "17 491", "2 787", "492"]) {
      expect(survey, `survey should mention ${figure}`).toContain(figure);
      expect(html, `landing should mention ${figure}`).toContain(figure);
    }
    // The before/after that the whole page leans on.
    expect(html).toContain("4 → 4");
  });

  it("quotes the re-measure that the committed corpus reproduces", () => {
    // The August dataset is the run as executed: @aimarket/warden@0.3.0, ruleset v2, plus a
    // ruleset_v2_vs_v3 block showing v3 changed nothing on that corpus. August's v4 re-run was
    // measured on a harvest that was never kept, so `50 → 6` may only appear as history. The
    // figures the page quotes come from the 2026-10-01 corpus, which IS committed: here the
    // page is checked against the result files and the result files against the corpus hash.
    // Recomputing the scans themselves needs the five published releases from npm, which is
    // `npm run check` in scripts/mcp-survey/remeasure rather than this offline suite.
    const data = JSON.parse(
      readFileSync(join(root, "docs", "data", "mcp-survey-2026-08-24.json"), "utf8"),
    ) as { survey: { ruleset: { version: string } }; ruleset_v2_vs_v3?: unknown };
    expect(data.survey.ruleset.version, "August dataset is still the pre-v4 run").toBe("2");
    expect(data.ruleset_v2_vs_v3, "v3-equivalence block is what licenses the v3 label").toBeTruthy();

    type Release = { package: string; blocked: number; blocking_findings: number; advisory_findings: number };
    type Result = { corpus: { file: string; sha256: string }; releases: Release[] };
    const load = (name: string): Result => {
      const r = JSON.parse(readFileSync(join(root, "docs", "data", name), "utf8")) as Result;
      const corpus = gunzipSync(readFileSync(join(root, "docs", "data", r.corpus.file))).toString("utf8");
      expect(createHash("sha256").update(corpus).digest("hex"), `${name} names its corpus`).toBe(r.corpus.sha256);
      return r;
    };
    const fmt = (n: number) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
    const fresh = load("mcp-remeasure-2026-10-01.json");
    const carry = load("mcp-remeasure-2026-10-01-august-carryover.json");
    const by = (r: Result, v: string) => r.releases.find((x) => x.package === `@aimarket/warden@${v}`)!;

    // Card and table: 0.3.0 against the newest pinned release, whatever it is now.
    const newest = fresh.releases[fresh.releases.length - 1]!.package.split("@").pop()!;
    expect(html, "carry-over card").toContain(`${by(carry, "0.3.0").blocked} → ${by(carry, newest).blocked}`);
    expect(html, "card names the newest release").toContain(`blocked by 0.3.0 → ${newest}`);
    expect(html, "table header names the newest release").toContain(`<th>${newest} · v`);

    const [a, b] = [by(fresh, "0.3.0"), by(fresh, newest)];
    for (const [label, x, y] of [
      ["servers blocked", a.blocked, b.blocked],
      ["blocking findings", a.blocking_findings, b.blocking_findings],
      ["advisory findings", a.advisory_findings, b.advisory_findings],
    ] as const) {
      expect(html, `table row ${label}`).toContain(
        `${label}</td><td class="mono">${fmt(x)}</td><td class="mono">${fmt(y)}</td>`,
      );
    }
    expect(html, "provenance note present").toContain('data-i18n="survey.prov"');
    expect(html, "the old figure is marked as not recomputable").toContain("cannot be recomputed");

    // The survey says the same, with the same numbers.
    const survey = readFileSync(SURVEY, "utf8");
    expect(survey, "August v4 column qualified").toContain("ruleset v4 (August re-run, corpus not kept)");
    expect(survey, "how to check").toContain("npm run check");
    expect(survey, "fresh corpus table").toContain(
      `| servers blocked | ${a.blocked} | ${fresh.releases.slice(1).map((r) => r.blocked).join(" | ")} |`,
    );
  });

  it("quotes the test count the runner reports", () => {
    // Same rule the READMEs follow: the badge is generated from a real run, so the
    // page may not invent a number of its own.
    const badge = readFileSync(join(root, "docs", "badges", "tests.svg"), "utf8");
    const n = /(\d+) passing/.exec(badge)?.[1];
    expect(n).toBeTruthy();
    expect(html, `landing should say ${n} tests`).toContain(`>${n}<`);
  });

  it("the 3D hero names the same four gates as the gate table, in order", () => {
    // The hero pins DOM labels onto the geometry so they translate, which also
    // means they can drift away from the chain the rest of the page teaches. They
    // are the API's own identifiers, so they are not translated — but they must
    // still be the same four names in the same order as the diagram below.
    const stage = html.slice(html.indexOf('id="stage"'), html.indexOf('id="stage"') + 2400);
    const labels = [...stage.matchAll(/data-anchor="(\d)"[^>]*>(.*?)<\/div>/g)]
      .map((m) => [m[1], m[2].replace(/<[^>]+>/g, "").trim()]);
    expect(labels.map((l) => l[0])).toEqual(["0", "1", "2", "3"]);
    expect(labels.map((l) => l[1])).toEqual([
      "G1 static-scan", "G2 threat-feed", "G3 origin", "G4 pinning",
    ]);
    // The flat SVG diagram that used to repeat these names is gone; the gate
    // table is now the only other place the page states them, so it is what the
    // hero has to agree with.
    const table = html.slice(html.indexOf("gates.t.gate"));
    for (const gate of ["static-scan", "threat-feed", "origin", "pinning"]) {
      expect(table, `the gate table should also name ${gate}`).toContain(`>${gate}<`);
    }
  });

  it("keeps the hero draggable, and keeps the block when there is no WebGL", () => {
    // Two decisions that a later edit could quietly undo. The scene is worth
    // nothing if it cannot be turned, and an earlier version deleted the whole
    // stage on a missing context — which deleted the legend with it.
    expect(html, "drag").toContain("pointerdown");
    expect(html, "touch drag must not eat vertical scroll").toContain("touch-action:pan-y");
    expect(html, "a lost context must not leave a black hero").toContain("webglcontextlost");
    expect(html).not.toMatch(/\.stage\.fallback\{display:none\}/);
    expect(html, "no-WebGL note").toContain('data-i18n="stage.nowebgl"');
  });
});
