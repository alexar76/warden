import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const LANGS = ["", "-ru", "-es", "-fr", "-zh"];      // README suffixes
const DOC_LANGS = ["", ".ru", ".es", ".fr", ".zh"];  // docs/<name><lang>.md
const DOCS = ["gates", "threat-feed", "integration", "mcp-survey"];

const readmes = LANGS.map((l) => `README${l}.md`);
const docs = DOCS.flatMap((d) => DOC_LANGS.map((l) => join("docs", `${d}${l}.md`)));
const all = [...readmes, ...docs];

/**
 * A five-language doc set is exactly where a broken relative link survives: the
 * one language the author reads is fine, and nobody clicks through the other
 * four. These are the checks a reviewer cannot do by eye.
 */
describe("documentation set", () => {
  it("ships every page in all five languages", () => {
    for (const f of all) expect(existsSync(join(root, f)), `missing ${f}`).toBe(true);
  });

  it("resolves every relative link", () => {
    const broken: string[] = [];
    for (const f of all) {
      const text = readFileSync(join(root, f), "utf8");
      for (const m of text.matchAll(/\]\(([^)#\s]+)(?:#[^)\s]*)?\)/g)) {
        const target = m[1]!;
        if (/^(https?:|mailto:)/.test(target)) continue;
        if (!existsSync(resolve(join(root, dirname(f)), target))) broken.push(`${f} → ${target}`);
      }
    }
    expect(broken).toEqual([]);
  });

  it("marks the current language as bold and links the other four", () => {
    const wrong: string[] = [];
    for (const f of all) {
      const line = readFileSync(join(root, f), "utf8")
        .split("\n")
        .find((l) => l.startsWith("> 🌐"));
      if (!line) {
        wrong.push(`${f}: no language switcher`);
        continue;
      }
      // exactly one bold entry — the page you are on — and four links out
      const bold = (line.match(/\*\*/g) ?? []).length / 2;
      const links = (line.match(/\]\(/g) ?? []).length;
      if (bold !== 1) wrong.push(`${f}: ${bold} bold entries in the switcher`);
      if (links < 4) wrong.push(`${f}: only ${links} sibling links`);
    }
    expect(wrong).toEqual([]);
  });

  it("references badges that exist", () => {
    const badges = new Set(readdirSync(join(root, "docs", "badges")));
    const missing: string[] = [];
    for (const f of readmes) {
      const text = readFileSync(join(root, f), "utf8");
      for (const m of text.matchAll(/docs\/badges\/([\w.-]+\.svg)/g)) {
        if (!badges.has(m[1]!)) missing.push(`${f} → ${m[1]}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("ships a conceptual hero (no UI screenshots — library has none)", () => {
    expect(existsSync(join(root, "docs", "assets", "hero.svg"))).toBe(true);
    for (const f of readmes) {
      const text = readFileSync(join(root, f), "utf8");
      expect(text, `${f} missing hero`).toContain("docs/assets/hero.svg");
    }
  });

  it("quotes the same test count in every README as the badge does", () => {
    const badge = readFileSync(join(root, "docs", "badges", "tests.svg"), "utf8");
    const n = /(\d+) passing/.exec(badge)?.[1];
    expect(n).toBeTruthy();
    for (const f of readmes) {
      const text = readFileSync(join(root, f), "utf8");
      expect(text, `${f} does not mention the ${n}-test suite`).toContain(n!);
    }
  });
});
