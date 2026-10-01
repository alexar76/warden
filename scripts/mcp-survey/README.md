# MCP survey harness

The scripts behind [`docs/mcp-survey.md`](../../docs/mcp-survey.md). They point WARDEN at public MCP
servers and record what it decides, with the exact text that triggered each rule.

**These scripts execute no third-party code.** Tool definitions are obtained by speaking MCP to a
server's own network endpoint (`initialize` + `tools/list`); nothing is installed, downloaded or run.
That constraint is why the corpus is remote servers rather than the stdio servers in the
awesome-lists — reaching those would mean running a stranger's code.

## Pipeline

```bash
python3 harvest_registry.py 80         # registry.modelcontextprotocol.io -> registry_remotes.json (80 pages; no arg = whole registry)
python3 harvest_tools.py               # live tools/list  -> tools_raw.jsonl   (14 threads, 2 per host, ~20 min)
npm install @aimarket/warden@0.3.0     # the artifact a stranger gets, not the working tree
node scan.mjs tools_raw.jsonl scan.json
python3 classify.py                    # exact matched span per blocking finding -> classified.json
```

| Script | Does |
|---|---|
| `mcpclient.py` | Minimal MCP client: `initialize`, `notifications/initialized`, `tools/list`, over streamable-http with SSE-or-JSON response parsing. Read-only; never calls a tool. |
| `harvest_registry.py` | Pages the official registry (optionally capped at N pages), keeps the latest record per server name, splits out those with a remote endpoint, writes `registry_meta.json`. |
| `harvest_tools.py` | One `tools/list` attempt per server, 20 s timeout, at most two connections per host, records the failure reason when there is one. Takes an optional input and output file. |
| `august_carryover.py` | Targets for re-asking, by recorded URL, the servers the 2026-08-24 run blocked. |
| `remeasure/remeasure.mjs` | Re-scans a frozen corpus with every published release pinned in `remeasure/package.json`; `--check` recomputes and fails on any difference. |
| `scan.mjs` | Runs `StaticScanGate` + `ThreatGate` (built-in deny-list, no remote feed) and writes per-server verdicts. |
| `classify.py` | Re-extracts the rule regexes from the installed `dist`, replays them against the harvested text, and reports the matched span with context — the difference between "flagged" and "flagged on *this*". |

## Reading the results

`scan.json` carries `wouldBlock` per server under the policy in the file header. `classified.json`
is the evidence: for every blocking finding, which surface matched, the matched substring, and 90
characters either side. Judging a finding without that context is how a false positive becomes a
statistic.

Two gates are deliberately absent. `origin` and `pinning` decide on host state — whether the
operator declared this server, whether its defs drifted since approval — so in a survey they return
the same answer for every server and measure nothing about the server.

Reachability numbers are not reproducible run to run: endpoints appear and disappear by the hour.

## Re-measuring a frozen corpus

A harvest is a property of its day; a scan of a harvest is not. So the corpus is committed and the
scan is recomputable. `docs/data/` holds the 2026-10-01 harvest of the first 80 registry pages and a
re-ask of the servers August blocked, each next to the results of scanning it with every published
release, installed from the registry by exact version and integrity hash:

```bash
cd remeasure
npm ci
npm run check        # recompute both result files from the committed corpora; exits 1 on any difference
node remeasure.mjs ../../../docs/data/mcp-corpus-2026-10-01.jsonl.gz --list 0.7.0   # what one release blocks
```

The result files carry counts and a hash of each release's blocked set, not server names — the same
rule as the report, which names false positives but not the servers whose findings held up. `--list`
prints the set from the corpus for anyone checking it.

The registry is paged in name order, so a page cap is an alphabetical slice and a different slice as
the registry grows: the 2026-08-24 run hit its 80-page cap at exactly 8 000 rows, and on 2026-10-01
the same 80 pages end at `co.p…`. That is why the servers August blocked are re-asked by URL instead
of hoping they fall inside the cap.
