#!/usr/bin/env node
/**
 * A published version may not silently mean two different rule tables.
 *
 * The incident this exists for: 0.3.0 went to npm at 08:34 UTC carrying ruleset
 * v2, ruleset v3 landed in the source 52 minutes later, and nothing republished.
 * For weeks afterwards `npm install @aimarket/warden@0.3.0` would have handed a
 * stranger a scanner with no rules at all on the tool-NAME surface, while the
 * README inside that same tarball documented v3 and printed a v3 digest. A
 * recorded verdict cites `rulesets.staticScan`, so two rule tables behind one
 * version number is not a packaging nit — it makes every stored scan ambiguous.
 *
 * The check: if this package's version is ALREADY on the registry, its ruleset
 * ref must equal the local one. Changing the rules therefore requires changing
 * the version, which is the invariant we actually want.
 *
 * Exits 0 when the version is unpublished (the normal pre-release state), when
 * the refs agree, or when the registry is unreachable — a network failure must
 * not be reported as a ruleset mismatch. Exits 1 only on a real disagreement.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("..", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const { name, version } = pkg;

const local = (await import(pathToFileURL(join(root, "dist", "index.js")).href)).staticScanRulesetRef();
console.log(`local  ${name}@${version} ruleset v${local.version} ${local.digest}`);

let published;
try {
  published = JSON.parse(execFileSync("npm", ["view", `${name}@${version}`, "version", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }));
} catch {
  console.log(`${name}@${version} is not on the registry yet — nothing to compare, this is the pre-release state`);
  process.exit(0);
}
if (!published) {
  console.log(`${name}@${version} is not on the registry yet — nothing to compare`);
  process.exit(0);
}

const work = mkdtempSync(join(tmpdir(), "warden-ruleset-"));
try {
  const tarball = execFileSync("npm", ["pack", `${name}@${version}`, "--silent", "--pack-destination", work], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim().split("\n").pop();
  execFileSync("tar", ["-xzf", join(work, tarball), "-C", work]);
  const remote = (await import(pathToFileURL(join(work, "package", "dist", "index.js")).href)).staticScanRulesetRef();
  console.log(`npm    ${name}@${version} ruleset v${remote.version} ${remote.digest}`);

  if (remote.version !== local.version || remote.digest !== local.digest) {
    console.error(
      `\nMISMATCH: ${name}@${version} is published with ruleset v${remote.version} (${remote.digest})\n` +
        `but this source builds ruleset v${local.version} (${local.digest}).\n\n` +
        `Bump the package version. A published version must mean exactly one rule table —\n` +
        `verdicts cite the ruleset ref, and two tables behind one version make every\n` +
        `recorded scan ambiguous. See docs/mcp-survey.md for what this cost us once.`,
    );
    process.exit(1);
  }
  console.log("OK — published ruleset matches this source");
} catch (err) {
  if (err?.status === 1 && err?.message?.includes("MISMATCH")) throw err;
  console.log(`could not fetch the published tarball (${err?.message ?? err}) — not treating a network failure as a mismatch`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
