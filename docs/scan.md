# Scan the servers your MCP clients start

> 🌐 **English** · [Русский](scan.ru.md) · [Español](scan.es.md) · [Français](scan.fr.md) · [中文](scan.zh.md)

`warden-mcp scan` reads the MCP configuration you already have, connects to every server it starts, and vets the tool definitions before a model sees them. It is the same gate chain as [`wrap`](../README.md#protect-claude-desktop-or-cursor-with-one-wrapper) and the [library](integration.md), run once over your configs instead of in front of one server.

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 10 sha256-lJuKKKV5mtru… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes        claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes   claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(notes) TOOL_DEF_SECRET_REQUEST(notes)
  ! error   broken       claude-code    could not start: spawn /nonexistent/bin/server ENOENT

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
```

No account, no API key, no model. The only network traffic is to the servers in your config, and to the HISTOR log if you pass `--histor`.

## Where it looks

Without arguments, every file below that exists. Pass files to scan only those, `--project` for the project files in the working directory, or `--client NAME` for one client.

| Client | Project file | User file |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (user servers, and this project's) |
| Claude Desktop | — | `claude_desktop_config.json` in the app's config directory |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` (JSONC) | `mcp.json` in the user settings directory |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` |

A server the config starts through `warden-mcp wrap` is scanned as the server behind the wrapper, under the pin id `wrap` uses, so drift against the approved snapshot is reported. Entries that are disabled, need an `${input:…}` value the client prompts for, or have neither `command` nor `url` are listed as skipped, never dropped silently.

## Starting servers

To read a stdio server's tools, `scan` starts it with the command, arguments and environment from the config, exactly as your client would, and stops it after `tools/list`. It never calls a tool. That still runs the program. Where you do not want that, such as CI on a pull request, `--no-launch` vets the launch line only: the threat feed's command records, and the lock's launch identity.

Remote servers (`url`, streamable HTTP or the older HTTP+SSE) are asked over the network with the headers from the config. `--public-only` refuses any that resolve to loopback, private, link-local or cloud-metadata addresses, checked on the address actually dialled. Redirects are not followed.

## Output and exit codes

| Option | Writes |
|---|---|
| (default) | a table on stdout |
| `--json` | the JSON report on stdout |
| `--json-file FILE` | the JSON report to a file, alongside the table |
| `--sarif FILE` | SARIF 2.1.0 for GitHub code scanning; blocking findings only, located at the server's line in the config |
| `--markdown FILE` | a summary with collapsible details, for `$GITHUB_STEP_SUMMARY` or a PR comment |

Exit `0`: nothing blocked. `1`: a server was blocked, or with `--fail-on-error` could not be checked. `2`: a usage or config error. `--fail-on SEVERITY` moves the block threshold; `--policy FILE` takes the same strict policy file as `wrap`.

Credentials in launch lines and URLs are shown as `***`. Tool descriptions in the Markdown report are inside code blocks that the text cannot close.

## The lock file: review the definitions, not just the command

A config line says which program starts. It does not say what that program will tell your model. The lock records the latter, so that a pull request shows it.

```bash
warden-mcp scan --project --lock warden.lock.json --update-lock   # after reading what changed
git add .mcp.json warden.lock.json
```

`--update-lock` writes each server's launch identity and full tool definitions, and refuses to record a server WARDEN blocks. Re-running it on unchanged servers changes nothing in the file. With `--lock` alone:

- a server the lock does not know is blocked (`LOCK_MISSING`);
- a server started differently is blocked (`SERVER_IDENTITY_DRIFT`);
- a server that now advertises different tools is blocked (`TOOL_DEF_DRIFT`), and the Markdown report shows the change as a diff of names, descriptions and schemas.

Lock entries no config starts are listed, and pruned on the next update.

## GitHub Action

```yaml
name: MCP servers
on: [pull_request]
permissions:
  contents: read
  security-events: write   # only for upload-sarif
jobs:
  warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alexar76/warden@v0.9.0
        with:
          upload-sarif: 'true'
```

By default it reads the project files, does not start stdio servers (a pull request chooses that program), refuses non-public addresses, uses `warden.lock.json` when it exists, writes the job summary, and fails on a blocked server. Inputs: `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `classifier-url`, `classifier-model`, `classifier-blocks`, `sarif`, `upload-sarif`, `version`. Outputs: `blocked`, `servers`, `sarif`. Pin the action by commit SHA in production workflows.

## pre-commit

```yaml
repos:
  - repo: https://github.com/alexar76/warden
    rev: v0.9.0
    hooks:
      - id: warden-scan     # changed configs; does not start stdio servers
      - id: warden-lock     # the project matches warden.lock.json; starts stdio servers
```

Both run the published package through `npx`, so Node 20 or later must be on `PATH`.

## Claude Code plugin

```text
/plugin marketplace add alexar76/warden
/plugin install warden@warden
```

At session start it scans the servers Claude Code starts for the project, tells you which are blocked, and tells the model by name and finding code only. A blocked description never enters the model's context. Calls to tools of a blocked server, or to a blocked tool, are then denied by a `PreToolUse` hook that reads one small file and starts nothing. Details and limits: [claude-plugin/README.md](../claude-plugin/README.md).

## HISTOR: is this server serving you what it serves everyone?

[HISTOR](https://histor.modelmarket.dev) is a public log that records, every day, the tool definitions of every remote server in the official MCP registry. `--histor` asks it one question per remote server: is the tool set you were just served the one HISTOR observes?

What is sent: the endpoint with scheme, host and path only (no query, no user name or password), and the [MTL/1](https://github.com/alexar76/awr) digest of the tool set. No tool description, no header, no stdio server. Endpoints on private hosts or addresses, and paths that look like they carry a key, are not sent at all; the report says why.

| Answer | Meaning |
|---|---|
| `same` | You were served the set HISTOR currently observes |
| `different` | HISTOR has never seen this set: it changed after the last daily crawl, or the server serves you something it does not serve the public crawler. Reported as advisory `HISTOR_UNSEEN_TOOLSET` |
| `previously-observed` | A set HISTOR saw earlier, not the current one. Advisory `HISTOR_OLDER_TOOLSET` |
| `not-listed`, `not-observed` | HISTOR does not know this endpoint, or has not read it successfully |

HISTOR answers never block. An outage is reported and the scan continues.

## The optional classifier

WARDEN's rules are offline and deterministic, and they miss what no rule names: a paraphrase, an instruction in another language. `--classifier-url` and `--classifier-model` add a second opinion from a model you choose, through any OpenAI-compatible endpoint: a local Ollama, vLLM or LM Studio, or a hosted API.

```bash
warden-mcp scan --classifier-url http://localhost:11434/v1 --classifier-model qwen2.5:14b
WARDEN_CLASSIFIER_API_KEY=… warden-mcp scan --classifier-url https://api.deepseek.com --classifier-model deepseek-flash
```

- **It is off by default and sends tool text.** With both flags, every tool's name, description and schemas go to that endpoint. A local model keeps them on your machine. A key, if needed, comes only from `WARDEN_CLASSIFIER_API_KEY`, never from a flag.
- **Advisory unless `--classifier-blocks`.** Its verdicts are reported as `TOOL_DEF_CLASSIFIER`. With `--classifier-blocks` a verdict at or above the block threshold (`high` by default) blocks the tool like a rule. A classifier that does not answer is reported and never blocks.
- **Same question as HISTOR's.** The prompt, the four categories (`instruction_to_model`, `exfiltration`, `secret_request`, `concealment`) and the answer format are the HISTOR log's. The tool text sits between markers with a random suffix it cannot forge, and the model's answer is checked field by field. With `--histor`, the log's own stored verdict on the tool set you were served is shown too (`HISTOR_CLASSIFIER`, advisory).
- **It does not read annotations or extension fields.** The rules do.

Measured on 2026-10-09 with `deepseek-flash`, the model HISTOR uses, on MCPTox (the published benchmark described in the comparison below) and on our own sets:

| | Rules (v10) | Rules + classifier, blocking at `high` | Rules + any classifier flag (advisory) |
|---|---|---|---|
| MCPTox held-out half, 218 poisoned tools caught | 171 | 191 | 218 |
| 45 clean MCPTox servers, blocked or flagged | 0 | 0 | 4 flagged |
| 200 corpus servers drawn at random, blocked or flagged | 2 blocked | 2 blocked | 2 blocked, 12 more flagged |
| 23 attacks we wrote / 12 hard benign cases | 20 / 0 | 22 / 0 | 23 / 0 |

The two the rules block are the identity service and the deploy tool from the comparison below. The 13 servers the classifier flagged were flagged at `medium` or `low`, never `high`. Six of them are worth a human look: one tells the model to make an irreversible ENS name transfer "as the first and only action" without asking the user, another tells it not to disclose where its data comes from. The model also flags the official Fetch server, whose description tells the model it now has internet access and should not refuse. That is an instruction to the model, though not an attack. The model missed what the rules catch: an injection in annotations, a private key or seed phrase asked for as a parameter, and `rm -rf ~`.

## How it compares

On 2026-10-09 we ran WARDEN, mcp-audit 0.18.2 (`--connect`) and mcp-shield 1.0.4 over the same servers. Each server was replayed over stdio, so every scanner connected to it as it would in the field. The harness, the sets and every judgment are in [`scripts/scanner-comparison`](../scripts/scanner-comparison/). The full write-up, with the method and every caveat, is the [scanner comparison](scanner-comparison.md).

The last three rows come from MCPTox (Wang et al., AAAI 2026), a published benchmark of 485 poisoned tools written for 45 real MCP servers. We split its servers in two by a fixed hash. Ruleset v10 was written from 22 servers; the table reports the other 23, with 218 poisoned tools no rule was fitted to.

| Servers | WARDEN 0.8.2 (v8) | WARDEN 0.9.0 (v10) | mcp-audit 0.18.2 | mcp-shield 1.0.4 |
|---|---|---|---|---|
| 23 attacks we wrote, blocked | 14 | 20 | 10 | 6 |
| 10 attacks from mcp-audit's and mcp-shield's own fixtures, blocked | 7 | 10 | 10 | 8 |
| 12 hard benign cases, blocked | 0 | 0 | 1 | 1 |
| 986 public servers, blocked | 3 | 3 | 33 | 343 |
| …blocks that hold up when the text is read | 1, and 1 arguable | 1, and 1 arguable | 0 | 0 of 20 drawn at random |
| 218 poisoned MCPTox tools on the held-out servers, blocked | 26 | 171 | 25 | 41 |
| 225 MCPTox tools with an `<IMPORTANT>` or "Ignore the previous instructions" prefix, blocked | 225 | 225 | 222 | not run |
| 45 clean MCPTox servers, blocked | 0 | 0 | 2 | 3 |

- **Read the corpus row first.** No rule was fitted to it. mcp-audit's 33 blocks are 16 "homoglyphs" in text written wholly in its own script (Chinese punctuation, Greek symbols, Cyrillic), 12 honesty instructions such as "do not tell the user the check digits are wrong", 3 base64 utilities, an SSH public-key tool, and the deploy tool WARDEN also blocks by mistake. mcp-shield blocks 35% of real servers, almost all on a keyword: "API key", "token", `.env`, "..". An ellipsis ("Shopify...") counts as path traversal. It does block the identity service WARDEN blocks, on the word "credentials".
- **Know which numbers are fitted.** We wrote the first attack set. Ruleset v9 was written after we had read both attack sets, and v10 after the 22 MCPTox servers of the other half. So 20 and 10 are the recall of rules fitted to what they were shown. The held-out MCPTox row, the clean servers, the corpus and the whole 0.8.2 column are not fitted. On the corpus v10 blocks exactly what v8 blocked.
- **MCPTox tests a shape, not a keyword.** Almost every poisoned tool tells the model to call another tool first, or to change another tool's arguments. v10 names that shape (`TOOL_DEF_CROSS_TOOL`, see [the gate chain](gates.md)) and blocks 171 of 218 held-out tools, against 189 of 267 on the half it was written from. Add the benchmark's `<IMPORTANT>` or "Ignore the previous instructions" prefix and every scanner we ran catches it; we did not run mcp-shield on that set. On the clean servers mcp-audit blocks AmapMap and BaiduMap, and mcp-shield blocks FileSystem, AdFin and Commander on "sensitive file access".
- **What WARDEN still misses:** 47 of the 218 held-out MCPTox tools, an instruction in Chinese to read `.env`, a paraphrase with no keyword ("gather every credential file … keep this step to yourself") and "include the output of env". It reports 41 of those 47, and all three of ours, as advisory, not as blocks. They need a meaning-based check, not another rule: with the optional classifier above, 191 of the 218 are blocked at `high` and all 218 are flagged.
- **Not compared:** Snyk Agent Scan, formerly Invariant mcp-scan and the most used scanner. It judges descriptions on Snyk's servers and needs an account token. mcp-audit also ships a lock file, a PR diff mode and SARIF; WARDEN is not alone in that slot.

## What scan does not do

- It reads definitions once. A server that changes later is caught by the next scan, by the lock in CI, or at every call by `wrap`.
- It does not scan call arguments, results, prompts or resources, and it is not a sandbox: starting a stdio server runs it.
- Its verdicts are WARDEN's static rules and threat records. A paraphrase no rule covers passes; see [the gate chain](gates.md) and the [field survey](mcp-survey.md) for what the rules catch and how often they are wrong.
