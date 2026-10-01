# WARDEN 0.8.0 release validation

Status: implementation ready for review; **not released**. All npm config examples labelled
0.8.0 require publication first. Existing ARGUS version/lockfile remain unchanged.

## Scope and decisions

- The entire server is denied on a blocking verdict; no `--partial` flag.
- Default pinning blocks even clean definition changes. A clean `list_changed` is forwarded
  only for unchanged approved definitions, after human reapproval, or with explicit
  `pinToolDefs: false`. This resolves the conflicting acceptance statements in the brief.
- Re-list before every call remains enabled. No time-based bypass or cached approval window.
- TTY review prevents ordinary piped approval. It does **not** authenticate a human: a local
  agent with shell access can allocate a PTY or edit state. No claim of protection against
  such an agent is made.
- A notification during verification rejects dispatch. A notification during execution
  withholds the response, with a warning that execution may already have occurred. A stdio
  proxy cannot detect a silent change after the last list response or atomically bind a
  remote execution to a definition hash.
- Audit-only reports security findings without blocking or writing TOFU pins. Protocol,
  framing, timeout and resource errors remain errors.
- Revocation persists a denial until human approval instead of immediately re-entering TOFU.

## Automated acceptance

`npm test`: **240 passed**, 19 files on macOS arm64 / Node 22.22.1.
The 39 subprocess tests in `test/wrap.test.ts` exercise:

- clean tools, raw JSON result preservation and 5 MiB results under both client framings;
- poisoning, suppressed calls, stripped initialization instructions, sanitized stderr and
  version/digest-bearing verdict logs;
- persistent drift, real PTY approval, non-TTY refusal, candidate compare-and-swap,
  identity refusal before spawn, revoke and reapprove;
- poisoned notifications, clean notifications with pinning disabled, default clean drift,
  silent drift, notification races before dispatch and during execution;
- excessive tools/pages/bytes, repeated next-page tokens, duplicate names and invalid schemas;
- server-to-client roots/sampling, out-of-order IDs and transparent methods;
- propagated child exit codes and EOF escalation/reaping of a stubborn child;
- five proxies sharing a state directory; malformed flags and policy rejection;
- audit-only and refused unsigned feed configuration.

Existing tests cover the unchanged signed-feed verification/freshness/rollback implementation,
legacy no-argument MCP mode, gate behavior, documentation and zero runtime dependencies.
`test/publish-pr.test.ts` checks Gitea PR dry-run, all retained push gates, the AGit
review ref, body-file escaping and rejection of incomplete PR options without network access.

`npm run build` passed. `npm run check:ruleset` exited successfully; local ruleset:
`v6 sha256-dop0ekChIvyzXlNo2/ZdDckIRgBCZaw0ywvakh2VQsA=`.
A separate online npm query returned E404 for 0.8.0 on 2026-09-30: the release is unpublished.
No ruleset comparison against an already published 0.8.0 is therefore possible or required.

## Latency for the PR

Measured by `node scripts/benchmark-wrap.mjs` after building, on Apple M4 / macOS arm64 /
Node 22.22.1, 2026-09-30. 50 tools, 10 warmup iterations, 100 measured iterations per mode.
Each iteration makes one `tools/list` and one `tools/call`; the wrapped call includes its
mandatory re-list. Direct and wrapped runs are sequential. Units: milliseconds.

| Operation | Direct p50 | Direct p95 | Wrap p50 | Wrap p95 | Difference p50 | Difference p95 |
|---|---:|---:|---:|---:|---:|---:|
| tools/list, 50 tools | 0.257 | 0.760 | 16.669 | 23.330 | 16.412 | 22.570 |
| tools/call | 0.178 | 0.632 | 17.421 | 27.251 | 17.243 | 26.619 |

These are differences of distribution quantiles, not paired latency samples. They include
local IPC, scans and durable observation writes; exclude cold npx/network startup and actual
filesystem work. Raw measurement: [wrap-benchmark.json](wrap-benchmark.json). This is visible
local overhead; changing the revalidation policy requires an explicit design decision.

## Official filesystem server smoke

A separate local protocol smoke test ran the official npm
`@modelcontextprotocol/server-filesystem@2026.8.31` behind the built proxy, with access restricted
by its arguments to a new temporary directory containing only a test file. Initialization
succeeded, all **14 tools** were exposed, and `read_text_file` returned the exact expected
`WARDEN filesystem smoke\n` content. TOFU and the pre-call re-list both passed; the child
exited after stdin closed. This exercises a real MCP server, but does not replace the live
Claude Desktop / Cursor checks below.

## Live clients and release gates

- [ ] Claude Desktop on macOS: wrapped official filesystem server, visible tools, actual
  read, poisoned-description refusal and screenshot.
- [ ] Cursor: same check, screenshot and refusal-message usability.

Both applications are installed. The UI automation tool repeatedly reported pending
Accessibility and Screen Recording permissions even after the operator reported granting
them. No live-client success or screenshot is claimed; client configuration was not changed.
Logs: [Claude Desktop](https://py.sdk.modelcontextprotocol.io/get-started/real-host/),
[Cursor MCP Logs](https://prod.cursor.com/help/customization/mcp).

Release sequence:

1. Push the review branch only to Gitea using `scripts/push_gitea_monorepo.sh --branch <branch>`
   after its `--dry-run`; open PR with this latency table. Never push the monorepo to GitHub.
2. Complete review, live-client checks and merge.
3. Owner runs `npm login`, then `scripts/publish_warden.sh`; no tokens in chat, scripts or CI.
4. Publish the updated landing via `scripts/deploy_warden_landing.sh --remote USER@HOST`
   after selecting the deployment destination and updating release-candidate wording.
5. Only after WARDEN publication, optionally update ARGUS's exact pin and lockfile. For
   local integration use `scripts/link_warden_local.sh`.
