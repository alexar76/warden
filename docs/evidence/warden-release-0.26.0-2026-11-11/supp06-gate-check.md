# SUPP-06 gate, checked from a packed archive

On 2026-11-11 a second pack of the same source was made in another session. That archive has SHA-256 `3f8fbe8e…1a1e`
and the same 404 files. It was installed into an empty folder.

The result applies to `aimarket-warden-0.26.0.tgz` in this folder:
- its `dist/` is byte-identical to this tarball's: `diff -r` of the two `dist/` trees shows no difference;
- both give the MOMUS build digest `976e0035799d23368a4c47d8c282e173537b2980d98f1dac44c523d962601b93`. That is
  `buildDigest` in `scripts/check-quality-gate.mjs`. The "dist digest" in `README.md` is a different hash.

`supp06-gate-drive.mjs` runs `warden-mcp wrap --id histor-e2e --histor-revision NAME --histor-revision-all -- uvx --from
aimarket-histor==0.7.0 aimarket-histor` against production HISTOR. It sends `initialize`, `tools/list`, then
`tools/call histor_server`.

| NAME | Result |
|---|---|
| `io.github.alexar76/histor` (the signed tip, Rekor 3803861704) | the call reached the server |
| `io.github.alexar76/warden` (another server's tip) | refused before the call: `WARDEN SUPP-06: digest_mismatch: served sha256:4789b5c9…c842 ≠ signed revision 1 sha256:5a773e88…1ad0; histor_server was not run` |

Run it with `node supp06-gate-drive.mjs <path to warden-mcp> <registry name> <state dir>`.

## Why the quality gate says "Quality service unavailable"

`check-quality-gate.mjs` fetches `https://histor.modelmarket.dev/security-quality/latest.json`. On 2026-11-11 that URL
answers 404:
- the public name now resolves to the front 82.47.146.138. It does not pass `/security-quality/*` on, while
  `/api/v1/*` works;
- on admin-vps the receipt exists: `/var/lib/momus-quality/public/latest.json`, written 2026-11-10 14:49Z. The local
  nginx there serves it with 200.

Until the front forwards that path, no WARDEN build passes `check:quality`, wherever it runs.
