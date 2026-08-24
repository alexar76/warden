# The signed threat feed

> 🌐 **English** · [Русский](threat-feed.ru.md) · [Español](threat-feed.es.md) · [Français](threat-feed.fr.md) · [中文](threat-feed.zh.md)

WARDEN ships 11 built-in threat records. They are a floor, not a catalog — the point of the feed is
that someone who actually hunts hostile MCP servers can push what they find to every install, without
becoming able to *unblock* anything.

## The wire contract

```
GET https://your-host/threat-feed

{
  "records": [
    { "pattern": "*wallet-drainer*", "severity": "critical", "code": "THREAT_CRYPTO_DRAINER",
      "reason": "Crypto-drainer keyword in server identity", "source": "your-scanner",
      "scope": "server" }
  ],
  "timestamp": 1786205907380,
  "signature": "f588d5a4…9706"
}
```

| Field | Rule |
|---|---|
| `records` | array of `ThreatRecord`; entries that do not typecheck are dropped, not fatal |
| `timestamp` | epoch **milliseconds, integer**. Not optional — it is what makes replay detectable |
| `signature` | Ed25519, hex, over the RFC 8785 canonical form of `{records, timestamp}` — **not** over the raw body |

`ThreatRecord`:

| Field | Meaning |
|---|---|
| `pattern` | matched case-insensitively; `*` is a glob, a pattern without `*` is a plain substring test |
| `severity` | `info` … `critical`. A `critical` matched against the **server** is fatal for the connection |
| `code` | stable machine code, e.g. `THREAT_TYPOSQUAT` |
| `reason` | human sentence shown to the operator |
| `source` | who says so — carried through into the finding |
| `scope` | `server` \| `tool` \| `any` (default). Which surface the pattern is meaningful against |

Scope matters more than it looks. `*token*` is a reasonable *server*-identity pattern and a
catastrophic *tool* pattern — half the honest MCP servers in existence mention tokens in a schema.

## What WARDEN checks, and what it does on failure

The rule for every failure below is the same: **keep the built-in floor**. A feed that cannot be
verified is ignored; it never lowers the protection you already had, and it never blocks startup.

| Check | Failure mode it stops |
|---|---|
| `feedPublicKey` configured | An unsigned feed is refused outright — no key, no remote records, even if a URL is set |
| Ed25519 signature over canonical bytes | Whoever serves the URL cannot add or edit records |
| Freshness: signed `timestamp` within `maxAgeMs` (default 24 h, `DEFAULT_FEED_MAX_AGE_MS`) | A replayed months-old snapshot that silently erases every record added since. *A signature says who wrote a document, never when you were handed it* |
| Future skew: not dated more than `FEED_CLOCK_SKEW_MS` (5 min) ahead | A timestamp far in the future that would keep a stale document "fresh" forever |
| Canonical bytes (RFC 8785) | Publisher and verifier disagreeing because of JSON key order |
| Size: `content-length` and body ≤ 512 000 bytes | A feed URL used as a memory-exhaustion vector; the body is checked too, because content-length can be absent or lie |
| 10 s fetch timeout | A hanging feed blocking your startup |

Remote records are **appended to** the built-ins (`[...BUILTIN, ...remote]`). A feed cannot remove a
built-in record, and a compromised publisher therefore cannot switch protection off — only add to it.
That asymmetry is deliberate: the up-channel (anyone reporting a suspicion) and the down-channel (the
feed that can deny a server) must not be the same trust level.

## Publishing a feed WARDEN will accept

Generate a key once. WARDEN wants the public key as **hex-encoded SPKI DER** (88 hex chars for
Ed25519):

```js
import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const spkiHex = publicKey.export({ format: "der", type: "spki" }).toString("hex");
console.log(spkiHex); // → this is what your consumers pin as feedPublicKey
```

Sign the canonical form of `{records, timestamp}` — reuse WARDEN's own canonicalizer so there is one
implementation of the bytes, not two:

```js
import { sign } from "node:crypto";
import { canonicalize } from "@aimarket/warden/jcs";

function document(records, privateKey) {
  const timestamp = Date.now();                       // integer ms
  const payload = canonicalize({ records, timestamp }); // key order fixed by RFC 8785
  const signature = sign(null, Buffer.from(payload, "utf8"), privateKey).toString("hex");
  return { records, timestamp, signature };
}
```

Two things that bite publishers:

- **Do not cache the document.** `timestamp` is a freshness claim; a cached response eventually
  publishes a stale one and every consumer refuses it.
- **Sign the canonical form, not `JSON.stringify`.** They agree far more often than they differ,
  which is what makes the difference expensive to find later.

## Consuming it

```ts
const feed = new ThreatFeed({
  feedPublicKey: process.env.FEED_PUBKEY,   // pinned in advance, out of band
  maxAgeMs: 6 * 60 * 60 * 1000,             // optional; non-finite/≤0 falls back to 24 h
  log: myLogger,                            // optional, but this is where refusals are reported
});
await feed.load(process.env.FEED_URL);      // no URL → built-ins only, no network
```

`feed.builtins` returns the built-in floor if you want to show what is enforced with no feed at all.
Every refusal is a `log.warn` with the reason — a silently-empty feed and a rejected feed are
indistinguishable without it, so pass a logger in production.

## A reference publisher

[MOMUS](https://github.com/alexar76/momus) publishes this contract at `/warden/threat-feed`, with a
`/warden/threat-feed/summary` endpoint that exposes the SPKI hex key and record counts, and a
`/warden/report` intake for unverified field suspicions. Its verifier script
(`momus/scripts/verify_warden_channel.mjs`) checks a live deployment using **this package's** own
canonicalizer, which is the only way to prove both sides agree on the bytes.
