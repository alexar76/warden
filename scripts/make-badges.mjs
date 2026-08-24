// Regenerate docs/badges/*.svg. Shields-style, generated locally so the README
// renders the same on GitHub, in an offline clone, and inside a Docker build.
//
//   node scripts/make-badges.mjs
//
// Counts come from the repo itself, never from a hand-typed number: a badge
// claiming 90 tests after someone deleted twenty is worse than no badge.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "docs", "badges");
mkdirSync(out, { recursive: true });

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const depCount = Object.keys(pkg.dependencies ?? {}).length;

// Ask the runner, don't grep for `it(`: several suites generate cases in a loop,
// and a static count silently under-reports them.
const report = JSON.parse(
  execFileSync("npx", ["vitest", "run", "--reporter=json"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  }),
);
const tests = report.numTotalTests;
if (!Number.isInteger(tests) || tests < 1) throw new Error("could not read a test count from vitest");
if (report.numFailedTests > 0) throw new Error(`${report.numFailedTests} tests are failing — fix them before badging`);

const CHAR = 6.5;
const width = (s) => Math.round(10 + CHAR * s.length);

function badge(label, value, color) {
  const lw = width(label);
  const vw = width(value);
  const w = lw + vw;
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(label)}: ${esc(value)}">
  <title>${esc(label)}: ${esc(value)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="20" fill="#555"/>
    <rect x="${lw}" width="${vw}" height="20" fill="${color}"/>
    <rect width="${w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="${(lw / 2).toFixed(1)}" y="14" fill="#010101" fill-opacity=".3">${esc(label)}</text>
    <text x="${(lw / 2).toFixed(1)}" y="13">${esc(label)}</text>
    <text x="${(lw + vw / 2).toFixed(1)}" y="14" fill="#010101" fill-opacity=".3">${esc(value)}</text>
    <text x="${(lw + vw / 2).toFixed(1)}" y="13">${esc(value)}</text>
  </g>
</svg>
`;
}

const badges = {
  "ci.svg": ["CI", "passing", "#4c1"],
  "tests.svg": ["tests", `${tests} passing`, "#4c1"],
  "deps.svg": ["dependencies", depCount === 0 ? "0" : String(depCount), depCount === 0 ? "#4c1" : "#dfb317"],
  "node.svg": ["node", pkg.engines.node, "#4c1"],
  "license.svg": ["license", "MIT", "#007ec6"],
  "warden.svg": ["WARDEN", "MCP firewall", "#4c1"],
};

for (const [file, [label, value, color]] of Object.entries(badges)) {
  writeFileSync(join(out, file), badge(label, value, color));
  console.log(`${file.padEnd(14)} ${label}: ${value}`);
}
