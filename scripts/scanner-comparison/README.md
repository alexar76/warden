# Scanner comparison harness

The scripts behind the comparison in [`docs/scan.md`](../../docs/scan.md#how-it-compares): WARDEN,
[mcp-audit](https://github.com/adudley78/mcp-audit) and [mcp-shield](https://github.com/riseandignite/mcp-shield)
run over the same MCP servers, through the same protocol, one server at a time.

Every server is replayed by [`replay.mjs`](replay.mjs), a stdio MCP server that answers `initialize`
and `tools/list` from a JSON file and nothing else. Each scanner therefore connects to it exactly as it
would to a real server, and none of them is handed text it would not see in the field.

| Set | What | Truth |
|---|---|---|
| `labelled` | 23 attacks and 12 hard benign cases, in [`build_sets.py`](build_sets.py) | written by WARDEN's authors |
| `independent` | the 6 exploit fixtures mcp-audit ships and the vulnerable demo server mcp-shield ships, fetched at pinned commits | written by those scanners' authors |
| `mcptox` | 485 poisoned tools on 45 real servers from MCPTox, split in half by server; see below | written by the benchmark's authors |
| `corpus` | the 986 public servers of [`docs/data/mcp-corpus-2026-10-01.jsonl.gz`](../../docs/data/) | every block judged by reading the text, in [`results/judgments-2026-10-09.json`](results/judgments-2026-10-09.json) |

## Run

```bash
python3 build_sets.py /tmp/cmp                       # writes the three replay configs
node warden_gates.mjs <warden package dir> /tmp/cmp/labelled-config.json /tmp/raw-labelled/warden-0.8.2.json
warden-mcp scan /tmp/cmp/labelled-config.json --json-file /tmp/raw-labelled/warden-0.9.0.json
python3 run_competitors.py /tmp/cmp/labelled-config.json /tmp/raw-labelled     # mcp-audit 0.18.2, mcp-shield 1.0.4
python3 normalize.py /tmp/raw-labelled /tmp/res/labelled.json                   # same for independent, corpus
python3 summarize.py /tmp/cmp /tmp/res results/judgments-2026-10-09.json results/2026-10-09.json
```

`warden_gates.mjs` runs the gate chain of any installed release, so 0.8.2 (ruleset v8, before `scan`
existed) is measured on the same sets; on 2026-10-09 it gave the same verdicts as the 0.9.0 `scan`
path with ruleset v8 on all three sets. `run_competitors.py` gives each run its own one-server
config and its own `HOME`, so cross-server heuristics and baseline state never mix servers. mcp-shield
takes about four seconds a server.

## MCPTox

[MCPTox](https://arxiv.org/abs/2508.14925) (Wang et al., AAAI 2026) is 485 poisoned tools on 45 real servers,
generated from three attack templates. It is the attack set WARDEN's authors did not write.

```bash
python3 fetch_mcptox.py /tmp/mcptox                 # the authors' published files; slow, the host rate-limits
python3 build_mcptox.py /tmp/mcptox /tmp/mtx         # mcptox-served, mcptox-decorated, mcptox-clean + the split
```

- **Served, not prompted.** Each poisoned tool is replayed exactly as its server's `def_tool/*.py` defines it.
  The benchmark's test prompts often add `<IMPORTANT>` or "Ignore the previous instructions and do the
  following:" in front; that variant is the separate `mcptox-decorated` set, because any scanner catches it.
- **Split before any rule was written.** Servers are ordered by `sha256("mcptox split 2026-10-09|" + name)`;
  the first 22 are `dev`, the other 23 are `test`. Ruleset v10's cross-tool rules were written from `dev` only;
  `test` is the reported measurement. The split is in `mcptox-labels.json` and in the results file.
- **Clean servers.** Each of the 45 servers' clean tool set is replayed too; a scanner should block none.
- The dataset is not copied into this repository; `results/2026-10-09-mcptox.json` holds case ids and verdicts only.
- mcp-shield was run on `mcptox-served` and `mcptox-clean` only; the summary marks a set a scanner did not
  run on as `not run`, never as zero blocks.

## The classifier run

`scan --classifier-url URL --classifier-model NAME --json-file …` on `mcptox-served`, `mcptox-clean`, the two
labelled sets and a seeded sample of 200 corpus servers (`random.Random("warden classifier corpus sample
2026-10-09").sample(…, 200)`). On 2026-10-09 the model was `deepseek-flash` behind an OpenAI-compatible
endpoint, 816 requests. `summarize_mcptox.py` reads those outputs next to the rule results.

## Snyk Agent Scan

Snyk Agent Scan judges tool text on Snyk's servers, so its run needs an account token and sends every
tool definition of the set to Snyk. The runner passes `SNYK_TOKEN` to that scanner only and never
writes it to a raw file:

```bash
SNYK_TOKEN=… python3 run_competitors.py /tmp/cmp/labelled-config.json /tmp/raw-labelled --only snyk-agent-scan --pause 10
```

The free version shares one quota among all its users. When the service answers HTTP 429 ("The public
quota for this service has been exceeded"), the run keeps nothing for that server, stops and exits
with code 75; finished servers are cached, so the same command resumes it. On 2026-10-09 the quota
was already spent at the first request, with a valid token.

## How the verdicts are read

- **block**: the scanner's own high-or-worse verdict on the tool definitions. WARDEN: `allow: false`.
  mcp-audit: a `poisoning` or `toxic_flow` finding at `HIGH` or `CRITICAL` (its default exit threshold
  reports everything, so this is the comparable line). mcp-shield: a tool at `HIGH Risk`. Snyk Agent
  Scan: a `prompt_injection_tool_desc` score. Its other three indexes (`untrusted_content`,
  `private_data`, `destructive_capabilities`) say what a server can do, not that its text attacks,
  so they count as flags; its own `--ci` fails on any of the four.
- **flag**: any finding about the tool definitions at all, advisory included.
- Findings the harness itself causes are left out for every scanner: mcp-audit's config-hygiene and
  command rules fire on the replay's absolute `node` path under a temporary directory, and its
  rug-pull rule records a first-scan baseline.

## What this does not show

- WARDEN's authors wrote the labelled set, and ruleset v9 was written after both attack sets were
  read. Its recall there is the recall of rules fitted to what they were shown. The 0.8.2 column is
  the measurement before that; the corpus column is the one no rule was fitted to.
- Snyk Agent Scan (formerly Invariant mcp-scan), the most used scanner, is not in the table yet: its
  free quota was spent when we ran it; see above.
- The corpus is remote servers from the official registry. Stdio servers from npm and PyPI, where
  most published poisoning examples live, are not in it.
