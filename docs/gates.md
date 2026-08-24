# The gate chain

> 🌐 **English** · [Русский](gates.ru.md) · [Español](gates.es.md) · [Français](gates.fr.md) · [中文](gates.zh.md)

`Warden.vet(server, tools)` runs an ordered chain and returns one verdict. This page is the whole
decision procedure: what each gate looks at, what it may block, and how the number at the end is
built.

```
static-scan  →  threat-feed  →  origin  →  pinning
 (free)         (free after     (free)      (free)
                 load)
```

The order is cheapest-and-most-local first. Nothing in the chain performs a network request — the
only fetch WARDEN ever makes is `ThreatFeed.load(url)`, which you call yourself, before vetting.

## How a verdict is assembled

Each gate returns `{ findings, score, fatal? }`. The chain:

1. runs every gate in order, accumulating findings (each gate sees `prior`);
2. multiplies the gate scores — the composite is a **product**, so one bad gate drags the server down
   instead of being averaged away by three good ones;
3. blocks if any gate returned `fatal`, or if any non-advisory finding reaches
   `policy.blockAtSeverity`;
4. short-circuits **only** on an explicit `fatal`. A blocking-but-not-fatal finding still lets the
   remaining gates report, so the record of *why* stays complete.

```ts
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
```

If `policy.blockAtSeverity` is not one of those five keys, the constructor logs a warning and falls
back to `"high"`. A typo there used to be the worst possible failure: `rank >= undefined` is `false`
for every comparison, so a misspelled threshold silently disabled blocking altogether.

### Two axes: severity and tier

Severity answers *how much attention does this deserve*. The **tier** answers *is this a defect at
all* — and it is data on the finding (`advisory: true`), not a consequence of severity.

An `advisory` finding is reported, never blocks, and never costs a tool, at **any**
`blockAtSeverity`. A tool whose schema takes an `api_key` is worth pointing at and is not a defect;
expressing that by lowering its severity would have made it blocking again for anyone who tightened
the threshold.

## static-scan

Local regex scan over each tool's `description` and its `inputSchema` — those two fields only. 25
rules in ruleset **v2**: 18 `block`, 7 `advise`.

Gate score is `1 − penalty(worst blocking severity)`; advisory hits never affect it.

| worst blocking severity | none | info | low | medium | high | critical |
|---|---|---|---|---|---|---|
| gate score | 1 | 1 | 0.9 | 0.7 | 0.4 | 0 |

| Code | Severity | Tier | What it catches |
|---|---|---|---|
| `TOOL_DEF_INJECTION` | critical / high | block | "ignore all previous instructions", "do not tell the user", `<system>` tags, references to the developer prompt |
| `TOOL_DEF_SECRET_REQUEST` | critical | block | `private_key`, `seed_phrase`/`mnemonic`, `~/.ssh` paths |
| `TOOL_DEF_SECRET_HARVEST` | critical | block | a tool whose stated job is to read/dump/reveal secrets |
| `TOOL_DEF_EXFIL` | critical / high | block | "post to https://…", "forward it to…", "exfiltrate", upload-to-host phrasing |
| `TOOL_DEF_HIDDEN_UNICODE` | high | block | zero-width and bidi control characters — text the reviewer cannot see |
| `TOOL_DEF_BASE64_BLOB` | high | block | a 120+ character base64 run inside a description |
| `TOOL_DEF_DATA_URL` | high | block | `data:…;base64,` and `javascript:` URLs |
| `TOOL_DEF_CREDENTIAL_PARAM` | medium / low | advise | schema or description asking for `api_key`, `password`, `secret`, bearer tokens |
| `TOOL_DEF_ENV_REFERENCE` | medium | advise | `.env`, "environment variables" |
| `TOOL_DEF_IMPERATIVE` | low / info | advise | "you must", "instead of" — prompt-shaped phrasing, not proof of anything |

`staticScanRuleset()` returns every rule with its **regex source and flags**, so a third party can
re-run the exact rule, plus `{ version, digest }` where the digest is sha256 over the RFC 8785
canonical form of the sorted rule list. Sorting is by code-unit comparison, never `localeCompare`: a
locale-dependent collation would make the same table digest differently on a differently-configured
host, which is exactly the divergence the digest exists to detect.

## threat-feed

Matches server identity and tool definitions against `ThreatRecord`s — 11 built-in plus whatever a
signed feed added (see [the feed contract](threat-feed.md)).

- Any match ⇒ gate score **0**.
- `fatal` **only** for a `critical` record matched against the *server*. A critical match on one
  *tool* is not fatal, so the rest of the chain still reports and the blame stays scoped to that tool
  — which is what lets a mostly-fine server keep working with one tool quarantined.
- `ThreatRecord.scope` selects the surface: `server` (id/name/url/command/args), `tool`
  (name/description/inputSchema), or `any` — the default when a record omits it.

Built-in codes: `THREAT_TYPOSQUAT`, `THREAT_CRYPTO_DRAINER`, `THREAT_SEED_PHRASE`,
`THREAT_SSH_KEY_READ`, `THREAT_ENV_EXFIL`, `THREAT_DESTRUCTIVE_CMD`, `THREAT_FORK_BOMB`.

## origin

Did the operator declare this server, or did it arrive from a remote catalog (`McpServerRef.catalog`
is set)?

| `allowUnknownServers` | finding | score | fatal |
|---|---|---|---|
| `false` (fail-closed) | `SERVER_UNDECLARED`, high | 0 | yes |
| `true` | `SERVER_UNDECLARED`, info | 1 | no |

This knob used to mean "has no reputation score yet", which no deployment could satisfy — nothing
ever supplied trust edges to the oracle, so every server came back unvouched and `false` blocked all
of them. Catalog provenance is a fact the host already holds locally, needs no network, and cannot
deadlock.

## pinning

Compares the current tool defs against the snapshot the user approved. The hash is sha256 over the
RFC 8785 canonical form of the tool-def set — the same canonicalization the feed signature uses, not
a second serialization.

| Situation | Code | Severity | Score | Fatal |
|---|---|---|---|---|
| No pin yet (first contact) | `TOOL_DEF_UNPINNED` | info | 0.9 | no |
| Hash differs from the pin | `TOOL_DEF_DRIFT` | high | 0 | under `pinToolDefs` |
| Tool defs have no canonical form (unpinned) | `TOOL_DEF_UNCANONICAL` | medium | 0.5 | no |
| Tool defs have no canonical form (pinned) | `TOOL_DEF_UNCANONICAL` | high | 0 | under `pinToolDefs` |

First contact costs 0.1, not a block: a clean, declared, unpinned server scores exactly **0.9**, and
`TOOL_DEF_UNPINNED` is `info` on purpose — at `blockAtSeverity: "info"` a blocking first sight would
make every server unusable forever, since nothing can be pinned before it is approved once.

`warden.approve(server, tools)` writes the pin through your `PinStore`. It is idempotent.

## Per-tool partition

`allowedTools` / `blockedTools` split the advertised tools:

- a tool is **blocked** if a non-advisory finding names it (`finding.tool`) and reaches the threshold;
- every other tool is allowed;
- sensitive tools (`policy.sensitiveToolPatterns`) stay *allowed* — they are flagged so your agent
  loop can demand per-call approval at run time. See `classifyTools` / `isSensitiveTool`.

## Adding a gate

`WardenGate` is three lines of interface, and `new Warden({ gates, policy, log })` takes the chain
directly, so you can insert your own without forking:

```ts
import { Warden, StaticScanGate, ThreatGate, OriginGate, PinningGate } from "@aimarket/warden";
import type { WardenGate, WardenGateInput, WardenGateResult } from "@aimarket/warden";

class DenyByPublisher implements WardenGate {
  readonly name = "publisher-allowlist";
  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const ok = ALLOWED.has(input.server.name);
    return ok
      ? { findings: [], score: 1 }
      : { findings: [{ gate: this.name, severity: "high", code: "PUBLISHER_UNKNOWN",
                       message: `${input.server.name} is not an allowed publisher` }],
          score: 0, fatal: true };
  }
}

const warden = new Warden({
  gates: [new StaticScanGate(), new ThreatGate(feed), new DenyByPublisher(), new OriginGate(), new PinningGate(store)],
  policy,
});
```

Two rules for a gate you write: **never claim a remote service is unreachable unless you actually
sent a request** (`test/no-phantom-gate.test.ts` enforces this over the shipped gates), and return a
score you can defend — a gate that measured nothing must return `1`, not a "neutral" 0.6, or it taxes
every server for a measurement it never took.
