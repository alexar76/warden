# Integration guide

> 🌐 **English** · [Русский](integration.ru.md) · [Español](integration.es.md) · [Français](integration.fr.md) · [中文](integration.zh.md)

WARDEN is a library, not a proxy. You call it at one point in your MCP host's lifecycle — after the
server tells you what it can do, before the model is told.

```
connect ──► listTools ──► warden.vet() ──► expose allowedTools to the model
                              │                    │
                              │                    └─► per call: isSensitiveTool → ask the user
                              └─► blocked: disconnect, and record the verdict
                                           approved once: warden.approve() pins the defs
```

## Where the seam is

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Warden, ThreatFeed, isSensitiveTool, EgressGuard } from "@aimarket/warden";

const feed = new ThreatFeed({ feedPublicKey: process.env.FEED_PUBKEY, log });
await feed.load(process.env.FEED_URL);

const warden = Warden.create({ policy, threatFeed: feed, store, log });

async function connect(ref) {
  const client = new Client({ name: "my-host", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: ref.command, args: ref.args }));

  const { tools } = await client.listTools();
  const verdict = await warden.vet(ref, tools);

  if (!verdict.allow) {
    await client.close();                       // nothing was ever exposed to the model
    await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
    throw new Error(`${ref.id} blocked by ${verdict.decidedBy}`);
  }

  const usable = tools.filter((t) => verdict.allowedTools.includes(t.name));
  await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
  return { client, tools: usable, verdict };
}
```

Three things this ordering buys you, all of which are easy to lose by moving one line:

1. **`vet()` before the model sees anything.** A blocked tool definition is prompt text that never
   entered the context. Vetting after you have already passed tools to the model is theatre.
2. **`blockedTools` is not the same as blocking.** A server with one poisoned tool and nine good ones
   stays usable; drop only what the verdict named.
3. **Record the verdict, including `verdict.rulesets`.** Without the ruleset version and digest, a
   stored scan cannot be told apart from the server having changed later.

## Per-call approval

A verdict is a decision about *definitions*. Sensitive tools are about *calls*:

```ts
async function callTool(name, args) {
  if (isSensitiveTool(name, policy) && !(await confirmWithUser(name, args))) {
    throw new Error(`${name} requires approval`);
  }
  return client.callTool({ name, arguments: args });
}
```

Patterns are globs, matched case-insensitively against the whole tool name: `"*delete*"`,
`"*transfer*"`, `"*key*"`. `classifyTools(tools, policy)` gives you the split up front if you want to
show the user what will require confirmation before they approve the server.

If your tools make outbound requests, wrap them:

```ts
const egress = new EgressGuard(["api.github.com", "*.internal.example.com"]);
const { allowed, reason } = egress.check(url);
if (!allowed) throw new Error(reason);   // empty allowlist blocks everything, by design
```

## The two seams you must supply

**`PinStore`** — two methods. Anything works; the only requirement is that it survives a restart,
because pins are what make drift detectable at all:

```ts
// Development: in-memory. Every restart is "first contact" again.
const pins = new Map();
const store = {
  getPin: async (id) => pins.get(id),
  putPin: async (p) => void pins.set(p.serverId, p),
};

// Production: one JSON file is enough — a pin is 4 small fields.
import { readFile, writeFile } from "node:fs/promises";
const store = {
  async getPin(id) {
    const all = JSON.parse(await readFile(PATH, "utf8").catch(() => "{}"));
    return all[id];
  },
  async putPin(p) {
    const all = JSON.parse(await readFile(PATH, "utf8").catch(() => "{}"));
    all[p.serverId] = p;
    await writeFile(PATH, JSON.stringify(all, null, 2), { mode: 0o600 });
  },
};
```

**`WardenLogger`** — `debug/info/warn/error/child`. Most host loggers already satisfy it
structurally, so you can usually pass yours unchanged; `silentLogger()` is the documented default.
Pass a real one in production: every gate decision and every feed refusal is reported there, and a
silently-empty threat feed looks exactly like a working one without it.

In TypeScript you can make the contract explicit and let the compiler hold it:

```ts
import type { PinStore, WardenLogger } from "@aimarket/warden";
export interface MyStore extends PinStore { /* your own methods */ }
export interface MyLogger extends WardenLogger { /* … */ }
```

## Choosing a policy

```ts
const policy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: ["*delete*", "*transfer*", "*key*", "*password*"],
  allowUnknownServers: false,
  pinToolDefs: true,
};
```

| | `blockAtSeverity` | `allowUnknownServers` | `pinToolDefs` |
|---|---|---|---|
| Locked down | `medium` | `false` | `true` |
| Recommended default | `high` | `false` | `true` |
| Exploring a catalog | `high` | `true` | `true` |
| Report-only (audit a fleet) | `critical` | `true` | `false` |

Notes from running this in anger:

- `blockAtSeverity: "info"` is not "maximum security", it is a broken deployment — it blocks
  `TOOL_DEF_UNPINNED`, which every server carries on first contact, so nothing can ever be approved.
  The gates keep that finding advisory-free and `info` precisely so a tightened threshold degrades
  gracefully; do not go below `medium` without reading [the gate table](gates.md).
- Report-only is a real mode: keep the verdicts, block nothing, and see what your fleet would have
  refused before you turn it on.

## Do not run WARDEN over your own tools

WARDEN vets **third-party** MCP servers. Your own built-in tools are not an untrusted publisher, and
running them through the chain produces exactly the wrong result: your own tool called
`transfer_funds` with an honest description trips `TOOL_DEF_*` rules written to catch a stranger
advertising the same thing. Keep first-party tools on a separate, trusted path — this is a lesson from
ARGUS, where first-party ecosystem tools explicitly bypass the firewall.

## References

- [ARGUS](https://github.com/alexar76/argus) — the reference host. `src/mcp/host.ts` is this
  integration in production form: vet on connect, quarantine per tool, per-call approval, egress
  guard.
- [MOMUS](https://github.com/alexar76/momus) — the publisher side: a signed feed at
  `/warden/threat-feed` plus an unverified-suspicion intake.
- [The gate chain](gates.md) · [The signed threat feed](threat-feed.md)
