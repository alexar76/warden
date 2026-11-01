# WARDEN for teams

One developer runs `npx -y @aimarket/warden scan` and sees what their MCP servers advertise.
A team needs the same check on every repository that configures an MCP client, with one
policy, a reviewed record of what was approved, and a signal when a server changes upstream.
All of that runs on what you already have: GitHub Actions, code scanning, and a lock file.

## 1. One policy for the organization

Put [`examples/github-org/.github/workflows/mcp-servers.yml`](../examples/github-org/.github/workflows/mcp-servers.yml)
in a shared repository (`<org>/.github` or `<org>/ci-policies`). It is a reusable workflow:
it checks out the calling repository, runs WARDEN over `.mcp.json`, `.cursor/mcp.json` and
`.vscode/mcp.json`, never starts a program a pull request chose (`launch-stdio: false`),
refuses remote servers that resolve to private addresses, fails at the organization's
severity floor, and uploads SARIF to code scanning.

## 2. One line per repository

[`examples/github-org/caller/mcp.yml`](../examples/github-org/caller/mcp.yml) calls it when a
client config or the lock changes, on pushes to `main`, and once a week. The weekly run is the
point: a remote server can change its tools without anyone touching your repository, and 45%
of remote servers in the official registry did within four weeks in October 2026.

## 3. Review changes where they happen

Each repository keeps `warden.lock.json`: the tool definitions someone reviewed. Create it once:

```bash
npx -y @aimarket/warden@0.22.2 scan --lock warden.lock.json --update-lock
git add warden.lock.json && git commit -m "Reviewed MCP tool definitions"
```

From then on a new server, or a server that advertises different tools, fails the check. The
pull request that updates the lock shows the field-by-field difference, so approving a change
is a code review, with the reviewer's name in the history.

## 4. Findings in one place

With `upload-sarif`, every block appears in the repository's **Security → Code scanning**
and in the organization's security overview, next to your other scanners: who configured
which server, what rule fired, since when.

## 5. Know when a server you approved changes

`histor: true` asks the public [HISTOR](https://histor.modelmarket.dev) log whether each remote
server serves your runner the tool set it serves everyone. Between CI runs, follow the same
servers with [HISTOR Watch](https://github.com/alexar76/histor/blob/main/docs/watch.md): a feed
of their changes, or a signed webhook into your team's Slack.

## Claude Code and editors

For the developer's own machine: the Claude Code plugin (`/plugin marketplace add alexar76/warden`)
runs the same rules before a tool call, and `warden-mcp wrap` puts WARDEN in front of a single
server for Claude Desktop or Cursor. See the [README](../README.md).

## What it does not do

WARDEN reads what servers advertise and how your clients start them. It does not prove what
a server does when a tool is called, and a lock records what was approved, not that it is
safe. [Scan guide](scan.md) · [scanner comparison](scanner-comparison.md).
