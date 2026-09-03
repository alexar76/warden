# Security Policy — WARDEN

## Reporting a vulnerability

**Do not open a public GitHub issue** for a firewall bypass, ruleset bypass, or signature-check failure.

Email **alexar76@rambler.ru**. We aim to acknowledge within 72 hours. Coordinated disclosure: up to 90 days to ship a fix before a public write-up. Credit on request.

## What this project is

`@aimarket/warden` is an in-process MCP security library (plus a stdio MCP scanner). It does **not** sandbox child processes, call an LLM, or hold operator secrets. A finding that WARDEN missed a paraphrase the regex table does not cover is expected (see README “What this is not”) — still report it if a **documented** blocking rule fails to fire, or if `vet()` performs network I/O you did not request via `ThreatFeed.load(url)`.

## Scope (high value)

- `vet()` / any gate returning allow when a non-advisory finding is at or above `blockAtSeverity`
- Threat-feed accepting an **unsigned** or replayed remote document
- RFC 8785 canonicalizer emitting bytes for input it should refuse (lone surrogates, non-integers)
- Pinning failing to detect a tool-def or launch-identity change when `pinToolDefs` is true
- The stdio MCP server connecting to, fetching, or executing the server under scan
- Secrets required at runtime for the published Docker/Glama image

## Out of scope

- OS-level confinement of MCP children (not shipped)
- False negatives on paraphrases no published rule covers
- Empty pin store on the stdio MCP scanner (documented: first-contact / UNPINNED advisory)
- npm supply-chain of **dev**Dependencies

## Threat feed keys

Do not open a PR that embeds a production Ed25519 **private** publishing key. `feedPublicKey` is the operator-pinned verify key.

MIT — see [`LICENSE`](LICENSE).
