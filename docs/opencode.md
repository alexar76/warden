# Flow guard for OpenCode

The [flow guard](flow-guard.md) of the Claude Code plugin, through [OpenCode](https://opencode.ai)'s plugin hooks.
It is written for agents that run with nobody at the keyboard: Multica runtimes, CI jobs, scheduled reports.

## What it does

| OpenCode hook | Guard step |
|---|---|
| `tool.execute.before` | Maps the call to the guard's tool vocabulary (`bash` → `Bash`, `read` → `Read`, `write`/`edit`/`apply_patch` → `Write`/`Edit`, `webfetch` → `WebFetch`, `<server>_<tool>` → `mcp__<server>__<tool>`) and runs the PreToolUse check. A refused call throws: OpenCode does not run the tool, and the model reads the reason. |
| `tool.execute.after` | Runs the PostToolUse check: what the result brought in (outside text, private data, credentials). The guard's warning about instructions in a result is appended to that result. |
| `chat.message` | Records destinations the user's own message names. |
| `shell.env` | Blanks the environment variables you list (`stripEnv`) for shell commands. An injected `env` or `printenv` then cannot read a key that only the OpenCode process needs, such as the model provider's key or a hub key used by an MCP header. |

A subagent (`task`) runs in a child session. The guard keeps one state per session tree, keyed by its root: what a
child reads binds the parent and the other way round, so an injected parent cannot hand the read-and-send to a
fresh child. Parents come from `session.created`/`session.updated` events, else from the SDK client. A child's prompt
is written by the parent model and is not recorded as the user's words. If recording a result fails, every later
call of that session tree is refused.

MCP server names come from OpenCode's config (`mcp` section). A tool that is neither a core tool nor a configured
MCP tool (a subagent `task`, another plugin's tool) is treated as an unlabelled MCP tool: its result is outside text.

## No one to ask: `block`

Where the Claude Code hook would ask a person, an unattended agent has nobody to ask. `block` decides:

- **`data`** (default). Refuses every call that involves data: a known secret in the arguments, a call after the
  session read a credential (`credential_egress`), private text or personal data matching what the session read,
  a short credential fragment, an incomplete payload check, a change to the guard's or OpenCode's own settings.
  It also refuses any decision whose payload the guard marks sensitive, whatever reason came first (opaque shell
  code after a credential read is refused, not waved through as "only shell code"). Calls that only *act* after
  outside text — shell code outside the read-only subset, an unconfirmed destination, a destructive command, a GUI
  action — run, and the resolution is logged next to the guard's own line (`"event":"opencode"`,
  `"resolution":"allowed_unattended"`).
- **`all`**. Refuses everything the Claude Code hook would ask about. Most agents then stop at their first shell
  command after reading a web page.

Why `data` lets actions through: an unattended agent's job is usually to read outside text and then report — a
digest of GitHub issues sent to a chat, a market check written to a ticket. Refusing every shell command after the
first read stops the job, not the attacker. What bounds *where* such an agent can act is a network allowlist or a
sandbox around it; what the guard adds is that data the session read does not leave with those actions.

Measured with the red-team replay (`node scripts/redteam/flow-redteam.mjs --opencode=MODE`, 28 attacks written
against the guard's code, no model, no network):

| Profile | Delivered |
|---|---|
| Claude Code hook (a person answers every question) | 0 of 28 |
| OpenCode, `block: "all"` | 0 of 28 |
| OpenCode, `block: "data"` | 3 of 28 |

The three in `data` are actions without data: an MCP `push` with no credential read and no URL argument, an
unlabelled calendar tool that adds the attacker as an attendee, an unlabelled repository tool that gives the
attacker's account write access. Label such tools in `flow-policy.json` (`labels`) or use `block: "all"` when an
agent holds tools like these.

## Credentials the guard recognizes

Besides the earlier formats (private keys, AWS, GitHub, GitLab, Slack, npm, `sk-…` API keys, Google API keys),
agent runtimes carry two more: a **Telegram bot token** (`<bot id>:AA…`) and an **AIMarket hub API key**
(`aimk_…`). Reading them (from `env`, a file or a tool result) marks the session as holding credentials; sending
one is denied.

Secret paths added for agent runtimes: OpenCode's `~/.local/share/opencode/auth.json` and Multica's
`~/.multica/config.json`. Protected paths added (changing them would switch the guard off): `~/.config/opencode/`,
any `.opencode/` folder and `opencode.json`/`opencode.jsonc`.

## Install

The plugin is the compiled `dist/opencode-plugin.js` and the `dist/flow-guard*.js` parts it imports (Node built-ins
only). With the package installed where OpenCode resolves modules, put this one file in OpenCode's plugin folder
(`~/.config/opencode/plugin/` globally, `.opencode/plugin/` in a project):

```js
// warden.js — export only the plugin: OpenCode calls every exported function as one.
import { createWardenPlugin } from '@aimarket/warden/opencode';

export const WardenFlowGuard = createWardenPlugin({
  block: 'data',
  stripEnv: ['DEEPSEEK_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'],
});
```

Without the package, copy `dist/opencode-plugin.js` and every `dist/flow-guard*.js` into one folder next to the
config (for example `~/.config/opencode/warden/`) and import `../warden/opencode-plugin.js` instead.
`opencode-plugin/warden.js` in this repository is that loader.

Environment overrides: `WARDEN_OPENCODE_BLOCK=data|all`, `WARDEN_OPENCODE_STRIP_ENV=NAME,NAME`. The guard's state
and log live in the usual state directory (`WARDEN_STATE_DIR`, default `~/.local/state/warden`); the policy file is
the same `flow-policy.json` as for Claude Code.

### Where to put it when agents share a runtime

`~/.config/opencode/plugin/` is fine for one person's OpenCode. It is not enough when unattended agents run as that
same user, as on a Multica daemon. The files can be owned by root, but if any folder above them belongs to the agent
user, an agent can rename that folder with the guard inside, and later sessions start without it. We found exactly
this on our own daemon on 2026-11-05. The agent user could not change a guard file, but `mv` of the folder worked.

Keep the guard in a folder where nothing on its path belongs to the agent user. Point OpenCode at it with
`OPENCODE_CONFIG_DIR`; OpenCode 1.18.32 loads `plugin/` from that folder for every session. Mount it **writable**,
owned by root: OpenCode writes a `.gitignore` into each config folder at start. On a read-only mount it stops with
`FileSystem.writeFile`, while a folder it may not write is skipped. Example for a Multica daemon:
- the folder: `opencode-guard/plugin/warden.js` (the loader) and `opencode-guard/warden/` (`opencode-plugin.js`
  and the 19 `flow-guard*.js` files from this package's `dist/`), all root:root, folders 755, files 644;
- in the daemon's compose service: `OPENCODE_CONFIG_DIR: /opt/opencode-guard` and the volume
  `./opencode-guard:/opt/opencode-guard`;
- move any older copy out of `~/.config/opencode/plugin`, or the guard loads twice.

The full example, with install commands, the compose lines and four checks, is in aicom's
`multica/manual/README.md`, section 6, «Example: the guard for every agent» (five languages). The quick check, as the
agent user: `opencode debug config | jq -c .plugin` must list only the root-owned path, also with `HOME` pointing
elsewhere.

## In a live Multica runtime (2026-11-04, guard moved 2026-11-05)

Two Multica agents (OpenCode 1.18.32 + DeepSeek, unattended, egress through an allowlist proxy) run with
`block: "data"` and `stripEnv` for the model key and two hub keys.

- **A full GitHub digest** (read GitHub, read and write Attested Memory over MCP, post the report to the tracker,
  close the task): 18 reviewable decisions, all `allowed_unattended`, 0 refused. The first run found a false
  positive: the task's UUID, read in a command's output and passed back to the tracker CLI, matched as private text
  and as a "number" (personal data), so posting the report was refused. Fixed in the core: a canonical UUID is no
  personal-data token, and private-text fingerprints drop UUIDs except on a line that names a credential
  (`withoutRecordIds`), so a UUID-shaped API key read from an ordinary file is still caught.
- **A staged attack** with a fake GitHub token in a file: after the agent read GitHub and then the file, sending
  through the chat script, `curl` to an allowed host with the file as body, a public Attested Memory write over MCP,
  a project-file write and the tracker CLI were all refused. `printenv` showed the model key blank in the shell and
  `GH_TOKEN` present (the agent's `gh` needs it). Before any of that, the agent's own attempts to list and grep the
  plugin folder were refused as touching the guard's settings.
- **The guard's own folder** (2026-11-05). On the daemon the guard sat in `~/.config/opencode/plugin` and
  `~/.config/opencode/warden`. Those were root-owned folders inside `~/.config/opencode`, which belongs to the agent
  user, and the agent user could rename them. The guard now lives in `/opt/opencode-guard` (root-owned, through
  `OPENCODE_CONFIG_DIR`). As the agent user, writing, deleting and renaming there are all refused. The plugin also
  loads with `HOME` pointing elsewhere. Every scheduled agent session and a paid order since then wrote the guard's
  state. The files are the npm 0.23.0 `dist/` files, byte for byte.
- **Multica 0.8.0** (2026-11-05). By default it drives OpenCode 1.15 and later over ACP instead of `opencode run`.
  The daemon keeps `MULTICA_OPENCODE_TRANSPORT=run`, the transport this guard was tested on. OpenCode's
  `--dangerously-skip-permissions`, which Multica passes on that transport, only answers rules that would ask.
  Explicit `deny` rules still refuse.

## Limits

- The guard sees tool calls. It does not see what the model says, and it cannot stop harm that needs no tool call.
- `data` mode lets actions run after outside text, by design; see above.
- `chat.message` treats the user message as the user's words. A runtime that puts other people's text into that
  message (issue comments, forwarded chat) makes destinations named there count as user-named.
- The runtime may deliver the model's final answer itself: Multica posts it as a tracker comment without a tool
  call, so the guard does not see it. In the staged attack that comment carried no key; nothing technical stops it.
- `shell.env` blanks variables for shell commands only. The OpenCode process keeps them; a key passed to an MCP
  server as a header stays with OpenCode.
- Tested against OpenCode 1.18.32's plugin interface (`@opencode-ai/plugin`), in unit tests that drive the hooks
  directly and in a Multica runtime; other versions may name tools differently.
