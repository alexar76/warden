# MCP survey harness

The scripts behind [`docs/mcp-survey.md`](../../docs/mcp-survey.md). They point WARDEN at public MCP
servers and record what it decides, with the exact text that triggered each rule.

**These scripts execute no third-party code.** Tool definitions are obtained by speaking MCP to a
server's own network endpoint (`initialize` + `tools/list`); nothing is installed, downloaded or run.
That constraint is why the corpus is remote servers rather than the stdio servers in the
awesome-lists — reaching those would mean running a stranger's code.

## Pipeline

```bash
python3 harvest_registry.py            # registry.modelcontextprotocol.io -> registry_remotes.json
python3 harvest_tools.py               # live tools/list  -> tools_raw.jsonl   (14 threads, ~20 min)
npm install @aimarket/warden@0.3.0     # the artifact a stranger gets, not the working tree
node scan.mjs tools_raw.jsonl scan.json
python3 classify.py                    # exact matched span per blocking finding -> classified.json
```

| Script | Does |
|---|---|
| `mcpclient.py` | Minimal MCP client: `initialize`, `notifications/initialized`, `tools/list`, over streamable-http with SSE-or-JSON response parsing. Read-only; never calls a tool. |
| `harvest_registry.py` | Pages the whole official registry, keeps the latest record per server name, splits out those with a remote endpoint. |
| `harvest_tools.py` | One `tools/list` attempt per server, 20 s timeout, records the failure reason when there is one. |
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
