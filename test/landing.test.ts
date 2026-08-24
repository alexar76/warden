import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
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
    expect(html).toContain("50 → 6");
    expect(html).toContain("4 → 4");
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
