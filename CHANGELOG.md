# Changelog

All notable changes to `@aimarket/warden`.

## 0.3.0 — 2026-08-24

First standalone release. The gates, the threat feed, the pinning store contract and the RFC 8785
canonicalizer were extracted from [ARGUS](https://github.com/alexar76/argus) 0.3.0, where they had
lived as `src/warden/`. The version number is deliberately continuous with the agent that shipped
them, not reset to 0.1.0: this is the same enforcement code, with the same behavioural tests that
guarded it there. The extraction itself changed no rule — it moved ruleset `v2` byte for byte — and
the security review below, run before this package was ever published, is what took the rules to
`v3` and closed six holes in the machinery around them.

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

### Security review before first release

The extracted code was read end to end and the findings reproduced. Six were real; all six are fixed
here and each has a regression test in `test/hardening.test.ts` that fails on the code as extracted.

- **Denial of service through glob matching (critical).** Threat-feed patterns and
  `policy.sensitiveToolPatterns` compiled `*` into `.*` and ran a regex. A 32-character pattern
  against a 220-character haystack took **112 seconds**; the sensitive-tool path took **89 seconds**
  from a long tool name. A signed feed record could therefore hang every connection check, which is
  precisely what the feed's trust model says a publisher must not be able to do — "a compromised
  publisher can only add protection" is false if one record stops the firewall answering. Replaced
  with a linear two-pointer matcher (`src/glob.ts`): the same case now returns in about a
  millisecond. Feed records are additionally refused past `MAX_GLOB_WILDCARDS` (12), and a feed is
  refused past 2000 records.
- **Terminal injection through finding messages (high).** Tool names, server ids, catalog names and
  a feed's `reason` string were interpolated raw into `finding.message`, which hosts print to a TTY
  and store in receipts. A tool named `<ESC>[2K<ESC>[1A…` overwrote the BLOCK line WARDEN had just
  written. Control characters and invisible characters are now escaped visibly (`src/sanitize.ts`,
  exported as `displaySafe`) — escaped rather than stripped, because a name containing `U+202E`
  should look suspicious in the report, not clean. `finding.tool` deliberately keeps the raw name:
  it is the key a host filters its tool list with.
- **The tool NAME was scanned by nothing (high).** An injection phrase, a zero-width character or a
  base64 blob in the first field the model reads produced zero findings. Ruleset **v3** gives every
  rule a `surfaces` list and adds the name to 17 of the 25 — every phrase-keyed and hidden-payload
  rule. The three noun-keyed codes stay off the name on purpose (`sign_with_private_key` is a
  plausible tool, and refusing it would be the v1 calibration error on a new surface).
- **A gate that threw took the whole verdict with it (high).** `vet()` rejected, so the host got no
  verdict at all — not even the findings the earlier gates had already produced — and a
  full-disk pin store or a bug in a custom gate decided whether the connection was blocked. A throw
  is now a `GATE_ERROR` finding at `high` with a zero score: a gate that crashed cleared nothing.
- **A frozen policy crashed the constructor (medium).** The `blockAtSeverity` typo fallback assigned
  into the caller's own object, so `Object.freeze(policy)` — a reasonable thing for a host to do —
  raised a `TypeError` out of `new Warden()` under ESM strict mode. The policy is now normalized
  into a private copy and the caller's object is never touched.
- **Pinning covered the advertisement but not the program (medium).** Tool-def pinning caught a
  server that changed what it advertises, not one that kept the advertisement and changed the
  command behind it — which a remote **catalog** can do to an already-approved id. `PinnedServer`
  gained an optional `identityHash` (transport, command, args, url, name) and a
  `SERVER_IDENTITY_DRIFT` finding. `env` is excluded on purpose: it holds secrets, and the pin is
  written to disk. Pins from before the field exists stay silent — absent is "not recorded", never
  "changed".

Two smaller fixes came out of the same pass: a `feedPublicKey` that parses but is not an Ed25519 key
is now refused with a warning instead of failing inside `verify()` and being logged at `debug`
(indistinguishable from "the feed had nothing new"), and an oversized feed body is now streamed and
aborted at the cap instead of being buffered whole by `res.text()` — `content-length` is advisory,
so the old check was one missing header away from being no check at all.

Two things the review deliberately did **not** change: `EgressGuard` passed every case put to it
(userinfo tricks, `file:`/`data:` schemes, suffix confusion, case folding), and the scan's cost over
large tool definitions is linear (500 tools × 240 KB in 1.3 s), so no truncation was introduced for
a problem that does not exist.

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
