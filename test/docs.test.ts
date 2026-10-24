import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { loadPolicy, publicRequestDigest } from "../src/flow-guard.js";
import { parseTaskManifest } from '../src/task-adapter.js';
import { createHash } from 'node:crypto';
import { AtomicScreenServer, ATOMIC_SCREEN_PROTOCOL } from '../src/atomic-screen.js';
import { parseWrapArgs } from '../src/wrap-cli.js';
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const LANGS = ["", "-ru", "-es", "-fr", "-zh"];      // README suffixes
const DOC_LANGS = ["", ".ru", ".es", ".fr", ".zh"];  // docs/<name><lang>.md
const DOCS = ["gates", "threat-feed", "integration", "mcp-survey", "security-hardening", "scan", "scanner-comparison", "flow-guard"];

const readmes = LANGS.map((l) => `README${l}.md`);
const docs = DOCS.flatMap((d) => DOC_LANGS.map((l) => join("docs", `${d}${l}.md`)));
const all = [...readmes, ...docs];

/**
 * A five-language doc set is exactly where a broken relative link survives: the
 * one language the author reads is fine, and nobody clicks through the other
 * four. These are the checks a reviewer cannot do by eye.
 */
describe("documentation set", () => {
  it('ships the native macOS embedding contract and executable commands in all five languages', async () => {
    for (const suffix of DOC_LANGS) {
      const page = readFileSync(join(root, `docs/flow-guard${suffix}.md`), 'utf8');
      for (const evidence of ['WardenDesktopSurface', 'WardenDesktopStandardIO', 'MainActor', 'invalidate()', 'NSApp.sendAction', 'method_getImplementation', 'NativeAction', 'sheetParent', 'WindowServer', 'npm run build:macos', 'npm run test:macos', 'TCC', 'void action(id sender)', '@?', 'hitTest', '../native/macos/Package.swift']) expect(page).toContain(evidence);
      const command = page.split('\n').find(line => line.includes('-- native/macos/.build/warden-desktop --demo'))!;
      const options = await parseWrapArgs(command.replace('node dist/mcp-server.js ', '').split(' '));
      expect(options).toMatchObject({ id: 'macos-owned-app', flow: 'native', screenRead: 'screenshot', screenAtomic: true, command: 'native/macos/.build/warden-desktop', args: ['--demo'] });
      const example = [...page.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map(m => JSON.parse(m[1]!)).find(v => v.name === 'click');
      expect(example).toEqual({ name: 'click', arguments: { index: '3' } });
    }
    for (const suffix of LANGS) expect(readFileSync(join(root, `README${suffix}.md`), 'utf8')).toContain('npm run test:macos');
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    for (const file of ['native/macos/Package.swift', 'native/macos/Sources', 'scripts/build-macos.mjs']) expect(pkg.files).toContain(file);
    expect(pkg.scripts['test:macos']).toContain('vitest.macos.config.ts');
    expect(readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8')).toContain('npm run test:macos');
    const workspaceWorkflow = join(root, '../.github/workflows/ci.yml');
    if (existsSync(workspaceWorkflow)) expect(readFileSync(workspaceWorkflow, 'utf8')).toContain('npm run test:macos');
  });
  it('validates the atomic protocol and runnable command in all five languages', async () => {
    const expected = { protocol: ATOMIC_SCREEN_PROTOCOL, observation: { name: 'screenshot', arguments: {} }, action: { name: 'click', arguments: { index: 3 } } };
    for (const suffix of DOC_LANGS) {
      const page = readFileSync(join(root, `docs/flow-guard${suffix}.md`), 'utf8');
      const example = [...page.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map(m => JSON.parse(m[1]!)).find(v => v.protocol === ATOMIC_SCREEN_PROTOCOL);
      expect(example).toEqual(expected);
      const server = new AtomicScreenServer({ observation: expected.observation, actions: ['click'], snapshot: { structuredContent: { applicationId: 'local.example', elements: [
        { index: 3, role: 'button', bounds: { x: 10, y: 10, width: 40, height: 20 } },
      ] } }, apply: () => { throw new Error('Documentation check must never execute an effect'); } });
      expect(server.prepare(example).protocol).toBe(ATOMIC_SCREEN_PROTOCOL);
      for (const evidence of ['--screen-atomic', 'AtomicScreenServer', 'warden/screen/prepare', 'warden/screen/commit', 'warden/screen/cancel', 'atomic_committed', 'atomic_refused', 'execution_uncertain', 'A → B → A', '256', '1500', '../examples/atomic-screen-server.mjs']) expect(page).toContain(evidence);
      const command = page.split('\n').find(line => line.includes('--screen-atomic -- node examples/atomic-screen-server.mjs'))!;
      const options = await parseWrapArgs(command.replace('node dist/mcp-server.js ', '').split(' '));
      expect(options).toMatchObject({ screenAtomic: true, screenRead: 'screenshot', flow: 'screen', command: 'node', args: ['examples/atomic-screen-server.mjs'] });
    }
    for (const suffix of LANGS) expect(readFileSync(join(root, `README${suffix}.md`), 'utf8')).toContain('--screen-atomic');
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    expect(pkg.exports['./atomic-screen'].import).toBe('./dist/atomic-screen.js');
    expect(pkg.files).toContain('examples/atomic-screen-server.mjs');
  });
  it("ships the same pinned task manifest, policy and replay limits in all five languages", () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-doc-policy-'));
    try {
      let first: unknown;
      for (const suffix of DOC_LANGS) {
        const page = readFileSync(join(root, `docs/flow-guard${suffix}.md`), 'utf8');
        const blocks = [...page.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map(m => ({ text: m[1]!, value: JSON.parse(m[1]!) }));
        const manifest = blocks.find(b => b.value.taskId)!;
        expect(parseTaskManifest(manifest.text)).toMatchObject({ version: 1, taskId: 'public-report', operations: [{ id: 'send_report', maxUses: 1 }] });
        const example = blocks.find(b => b.value.taskAdapter)!.value;
        expect(example.taskAdapter.manifestSha256).toBe(createHash('sha256').update(manifest.text + '\n').digest('hex'));
        if (!first) first = [manifest.value, example]; else expect([manifest.value, example]).toEqual(first);
        const path = join(dir, 'policy.json'); writeFileSync(path, JSON.stringify(example));
        const policy = loadPolicy({ WARDEN_FLOW_POLICY: path, WARDEN_STATE_DIR: dir, WARDEN_FLOW_MODE: '' });
        expect(policy.taskAdapter).toMatchObject({ mode: 'capabilities', server: 'warden_task' });
        expect(policy.taskAdapter?.invalid).toBeUndefined();
        for (const evidence of ['task_adapter_delegated', 'idempotency-key', '0/579', '608/949', '613/949', 'summary-2026-10-23-local.json', '1–4']) expect(page).toContain(evidence);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it("documents both secret-transfer regressions and their reproducible replay in all five languages", () => {
    for (const suffix of DOC_LANGS) {
      const page = readFileSync(join(root, `docs/flow-guard${suffix}.md`), 'utf8');
      for (const evidence of ['secret-chunks-6-filler', 'secret-spelled-out', 'secret_fragment', 'v2', 'ask', '0/23', 'scripts/redteam/flow-redteam.mjs', 'scripts/redteam/fragment-collisions.mjs']) expect(page).toContain(evidence);
    }
  });
  it('validates the same review-mode plan and complete outcome policy in all five languages', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-doc-run-'));
    try {
      let first: unknown;
      for (const suffix of DOC_LANGS) {
        const page = readFileSync(join(root, `docs/flow-guard${suffix}.md`), 'utf8');
        const blocks = [...page.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map(m => JSON.parse(m[1]!));
        const merged = { ...blocks.find(b => b.taskId), ...blocks.find(b => b.runs) };
        const example = blocks.find(b => b.taskAdapter?.mode === 'review');
        const text = JSON.stringify(merged, null, 2) + '\n';
        expect(parseTaskManifest(text).runs).toEqual([{ id: 'mail_to_bob', title: 'Send the reviewed public report to bob@corp.com in Mail', operations: ['send_report'] }]);
        expect(example.taskAdapter.manifestSha256).toBe(createHash('sha256').update(text).digest('hex'));
        if (!first) first = [merged, example]; else expect([merged, example]).toEqual(first);
        const path = join(dir, 'policy.json'); writeFileSync(path, JSON.stringify(example));
        expect(loadPolicy({ WARDEN_FLOW_POLICY: path, WARDEN_STATE_DIR: dir, WARDEN_FLOW_MODE: '' }).taskAdapter?.mode).toBe('review');
        for (const text of ['--screen-read', '--screen-read-input', 'task_run', 'screen_validation', 'execution_uncertain', 'summary-2026-10-23-auten-local.json']) expect(page).toContain(text);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it("validates the same exact public-request example in all five languages", () => {
    const args = { to: 'bob@corp.com', subject: 'status', body: 'The public release is ready.' };
    const expected = { tool: 'mcp__mail__send_email', requestSha256: publicRequestDigest('mcp__mail__send_email', args) };
    for (const suffix of DOC_LANGS) {
      const page = readFileSync(join(root, `docs/flow-guard${suffix}.md`), 'utf8');
      const rule = [...page.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map(m => JSON.parse(m[1]!)).find(v => v.credentialEgress)?.credentialEgress.allow;
      expect(rule).toEqual([expected]);
      for (const text of ['credential_egress', 'payload_incomplete', 'credential-egress.mjs', '0/16', '12/12']) expect(page).toContain(text);
    }
  });
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

  it("names itself an MCP server in the H1, like ARGUS / aimarket-mcp", () => {
    for (const f of readmes) {
      const title = readFileSync(join(root, f), "utf8").split("\n").find((line) => line.startsWith("# ")) ?? "";
      expect(title, `${f} H1 must say MCP`).toMatch(/MCP/i);
    }
  });

  it("ships the landing 3D hero in every README", () => {
    expect(existsSync(join(root, "docs", "screenshots", "readme", "hero-3d.png"))).toBe(true);
    for (const f of readmes) {
      const text = readFileSync(join(root, f), "utf8");
      expect(text, `${f} missing hero`).toContain("docs/screenshots/readme/hero-3d.png");
      expect(text, `${f} hero should link to the live landing`).toContain("https://warden.modelmarket.dev/");
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
