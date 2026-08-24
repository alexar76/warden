# Changelog

All notable changes to `@aimarket/warden`.

## 0.3.0 — 2026-08-24

First standalone release. The gates, the threat feed, the pinning store contract and the RFC 8785
canonicalizer were extracted from [ARGUS](https://github.com/alexar76/argus) 0.3.0, where they had
lived as `src/warden/`. The version number is deliberately continuous with the agent that shipped
them, not reset to 0.1.0: this is the same enforcement code, at the same ruleset version (`v2`,
digest `sha256-gWC14PR4kUylkJaAGMnIYYX6tPhZTJ60cSB61UZxuWc=`), with the same 85 behavioural tests
that guarded it there.

### Why it moved

A host that wants an MCP firewall had to install an agent — with an MCP SDK, a wallet library and a
post-quantum keystore in tow — to get one. This package has **zero runtime dependencies** and imports
nothing but `node:crypto`.

### Changed for standalone use

- **Host seams are narrowed and named.** Pinning needs `PinStore` (`getPin`/`putPin`) instead of
  ARGUS's full `MemoryStore`, and logging needs `WardenLogger` instead of ARGUS's `Logger`. Both are
  structural, so an existing host store/logger usually satisfies them unchanged.
- **`log` is now optional** on `WardenInit` and `WardenCreateDeps`, defaulting to the new
  `silentLogger()`. A host with no logger of its own still gets enforcement — verdicts are returned as
  data from `vet()`, never inferred from log output.
- **`threatFeed` stays required.** Constructing one silently would hide from the host that no external
  intel is in play.
- **Subpath export `@aimarket/warden/jcs`** so another implementation can be byte-checked against the
  canonicalizer without pulling in the gate chain.
- **Types are exported from the entry point** (`WardenPolicy`, `WardenVerdict`, `WardenFinding`,
  `ThreatRecord`, `ToolDef`, …). ARGUS now re-exports them from here rather than declaring its own
  copies, so a change on this side breaks its build instead of drifting silently.
- No behavioural change to any gate. The rule table, the severities, the tiers, the score arithmetic
  and every finding code are the ones ARGUS 0.3.0 shipped.

### Added

- `test/packaging.test.ts` — fails if a runtime dependency appears, if any source file imports outside
  the package, or if the entry point stops exporting the enforcement surface. The zero-dependency claim
  is the reason this package exists, so it is a test and not a sentence in a README.
- `test/docs.test.ts` — resolves every relative link across the five-language doc set and holds the
  quoted test count to what the runner actually reports.
- `test/no-phantom-gate.test.ts` — the gate-chain half of ARGUS's regression guard for a removed
  reputation gate: vetting opens no socket, and no gate may report a service as unreachable without
  having sent a request. (The oracle-side half stayed with the oracle client, in ARGUS.)
- Documentation in English, Russian, Spanish, French and Chinese: the gate chain, the signed threat-feed
  contract, and an integration guide.

### Upgrading from ARGUS internals

If you imported the gates through ARGUS's source tree, the mapping is mechanical:

| Before | After |
|---|---|
| `src/warden/index.js` | `@aimarket/warden` |
| `src/warden/sandbox.js` | `@aimarket/warden` (`EgressGuard`, `isSensitiveTool`, `classifyTools`) |
| `src/warden/pinning.js` | `@aimarket/warden` (`PinningGate`, `canonicalToolsHash`, …) |
| `src/warden/jcs.js` | `@aimarket/warden/jcs` or the root export |
| `MemoryStore` (for pins) | `PinStore` |
| `Logger` | `WardenLogger` |
