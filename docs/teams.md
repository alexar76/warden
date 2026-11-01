# WARDEN for teams

One developer runs `npx -y @aimarket/warden scan` and sees what their MCP servers advertise.
A team needs the same check on every repository that configures an MCP client, with one
policy, a reviewed record of what was approved, and a signal when a server changes upstream.
All of that runs on what you already have: GitHub Actions, code scanning, and a lock file.

## 1. One policy for the organization

Put [`examples/github-org/.github/workflows/mcp-servers.yml`](../examples/github-org/.github/workflows/mcp-servers.yml)
in a shared repository (`<org>/.github` or `<org>/ci-policies`). It is a reusable workflow:
it checks out the calling repository, runs WARDEN over `.mcp.json`, `.cursor/mcp.json` and
`.vscode/mcp.json`, and:

- never starts a program a pull request chose (`launch-stdio: false`);
- refuses remote servers that resolve to private addresses (`public-only`);
- blocks at the organization's floor (`FLOOR: high`). A repository may pass a stricter
  `fail-on` (`medium`), and the workflow fails if it passes a laxer one (`critical`);
- fails a repository that has MCP configs but no reviewed lock. The action alone skips the
  lock check when the file is missing, so without this step a repository could opt out of
  review by never committing one;
- uploads SARIF to code scanning.

## 2. One call per repository

[`examples/github-org/caller/mcp.yml`](../examples/github-org/caller/mcp.yml) calls it when a
client config or the lock changes, on pushes to `main`, and once a week. The weekly run is the
point: a remote server can change its tools without anyone touching your repository, and 45%
of remote servers in the official registry did within four weeks in October 2026. GitHub
pauses scheduled workflows in a public repository after 60 days without activity; re-enable
the workflow if that happens.

## 3. Review changes where they happen

Each repository keeps `warden.lock.json`: the tool definitions someone reviewed. Create it once,
from the repository's own configs only:

```bash
npx -y @aimarket/warden@0.22.3 scan --project --lock warden.lock.json --update-lock
git add warden.lock.json && git commit -m "Reviewed MCP tool definitions"
```

Keep `--project`. Without it the scan also reads your personal configs (`~/.claude.json`,
Claude Desktop, Cursor, Windsurf) and writes your own servers into the repository's lock.
This run starts the local (stdio) servers on your machine to read their tools. CI never starts
them.

From then on the check fails when:

| What changed | What CI compares | Result |
|---|---|---|
| A server not in the lock appears in a config | the server name | `LOCK_MISSING` |
| A remote server advertises different tools | the tool definitions it serves the runner | `TOOL_DEF_DRIFT`, with a field-by-field diff in the job summary |
| A local server's command, arguments or package changes | the launch line | `SERVER_IDENTITY_DRIFT` |

A local server's tool text is compared when a developer re-runs the command above; CI checks
how it is started. The pull request that updates the lock shows the difference, so approving
a change is a code review, with the reviewer's name in the history.

## 4. Or one allowlist for the organization

When the same few servers are used everywhere, keep one list instead of a lock per
repository. Create a repository (e.g. `<org>/mcp-allowlist`) with `mcp-allowlist.lock.json`,
made with the command above from a config that lists every approved server, and pass
`allowlist-repository: <org>/mcp-allowlist` in the caller (commented out in
[`caller/mcp.yml`](../examples/github-org/caller/mcp.yml)). Then:

- a repository may use any subset. Approved servers it does not use are listed as
  "in the lock but not in any config" and do not fail the check;
- a server not on the list fails in every repository until it is added. Adding one is a pull
  request to the allowlist repository, which makes that repository's history the
  organization's record of approvals;
- server names must match the list (`deepwiki` in the list, `deepwiki` in `.mcp.json`).

If the allowlist repository is private, the caller's `GITHUB_TOKEN` cannot read it: pass a
token with `contents: read` on it as the `allowlist-token` secret.

## 5. Findings in one place

With `upload-sarif`, every block appears in the repository's **Security → Code scanning**
and in the organization's security overview, next to your other scanners: who configured
which server, what rule fired, since when. Code scanning on private repositories needs GitHub
Advanced Security. Without it, set `upload-sarif: 'false'`; the job summary still lists every
finding.

## 6. Know when a server you approved changes

`histor: true` asks the public [HISTOR](https://histor.modelmarket.dev) log whether each remote
server serves your runner the tool set it serves everyone. For that it sends HISTOR the
server's endpoint and a digest, never tool text; set `histor: false` to keep it off. Between CI
runs, follow the same servers with
[HISTOR Watch](https://github.com/alexar76/histor/blob/main/docs/watch.md): a free feed of
their changes, or, as a paid plan, a signed webhook into your team's Slack or ticket system.

## What it costs

WARDEN, the action and these workflows are free and open source (MIT). Everything above runs
in your own CI: there is no account, and nothing about your organization is kept on our side.
The only paid part is HISTOR Watch's push delivery.

Not offered: a hosted dashboard, a hosted threat feed, or approvals stored on our side. The
equivalents are the ones above: the shared workflow as the policy, the lock or the allowlist
repository as the approval history, code scanning as the one place for findings.

## Claude Code and editors

For the developer's own machine: the Claude Code plugin (`/plugin marketplace add alexar76/warden`)
runs the same rules before a tool call, and `warden-mcp wrap` puts WARDEN in front of a single
server for Claude Desktop or Cursor. See the [README](../README.md).

## What it does not do

WARDEN reads what servers advertise and how your clients start them. It does not prove what
a server does when a tool is called, and a lock records what was approved, not that it is
safe. [Scan guide](scan.md) · [scanner comparison](scanner-comparison.md).

## Checked

On 2026-11-01, with npm `@aimarket/warden@0.22.2` and the action's `run.sh` given the inputs
this workflow passes, on a repository with one local server and one public remote server
(`mcp.deepwiki.com`): the lock run above wrote both; the CI run passed (remote: `histor: same`);
a new server failed with `LOCK_MISSING`, also at `fail-on: critical`; a remote tool that
differed from the lock failed with `TOOL_DEF_DRIFT` and one SARIF result; a changed launch line
failed with `SERVER_IDENTITY_DRIFT`; a repository using one server of a two-server allowlist
passed; without a lock the action passed a new server, which the policy step now fails. The
policy step ran against each case (missing lock or allowlist, laxer and stricter `fail-on`,
no MCP config). The workflows themselves were not run on GitHub.
