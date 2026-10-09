# Scan the servers your MCP clients start

> 🌐 **English** · [Русский](scan.ru.md) · [Español](scan.es.md) · [Français](scan.fr.md) · [中文](scan.zh.md)

`warden-mcp scan` reads the MCP configuration you already have, connects to every server it starts, and vets the tool definitions before a model sees them. It is the same gate chain as [`wrap`](../README.md#protect-claude-desktop-or-cursor-with-one-wrapper) and the [library](integration.md), run once over your configs instead of in front of one server.

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 9 sha256-nC+ybcePE8AW… · block at high
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

By default it reads the project files, does not start stdio servers (a pull request chooses that program), refuses non-public addresses, uses `warden.lock.json` when it exists, writes the job summary, and fails on a blocked server. Inputs: `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `sarif`, `upload-sarif`, `version`. Outputs: `blocked`, `servers`, `sarif`. Pin the action by commit SHA in production workflows.

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

## What scan does not do

- It reads definitions once. A server that changes later is caught by the next scan, by the lock in CI, or at every call by `wrap`.
- It does not scan call arguments, results, prompts or resources, and it is not a sandbox: starting a stdio server runs it.
- Its verdicts are WARDEN's static rules and threat records. A paraphrase no rule covers passes; see [the gate chain](gates.md) and the [field survey](mcp-survey.md) for what the rules catch and how often they are wrong.
