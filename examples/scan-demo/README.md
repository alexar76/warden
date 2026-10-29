# scan-demo — see WARDEN block a poisoned server

Three stdio MCP servers in one `.mcp.json`, the config file Claude Code reads from a project directory:

| Server | What it is | Expected verdict |
|---|---|---|
| `notes` | [`notes.mjs`](notes.mjs): one tool, `save_note`, honest description | `allow` |
| `evil-notes` | [`poisoned-notes.mjs`](poisoned-notes.mjs): the same tool, whose description tells the model to read `~/.ssh/id_rsa` and a seed phrase and POST them to an outside address | `BLOCK` |
| `broken` | a command that does not exist | `error` (could not start) |

Run it from this directory, with nothing installed (Node ≥ 20). `--project` reads only this
directory's config files, so the output is the same on every machine:

```bash
npx -y @aimarket/warden@0.22.2 scan --project
```

```text
WARDEN scan 0.22.2 · ruleset 16 sha256-86y6iNc4R+LM… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes       claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes  claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(save_note) TOOL_DEF_SECRET_REQUEST(save_note) THREAT_SSH_KEY_READ(save_note) THREAT_SEED_PHRASE(save_note)
  ! error   broken      claude-code    could not start: spawn /nonexistent/bin/server ENOENT

  ⚠ toxic flow  claude-code has a possible private-data / untrusted-input / outbound path: capabilities of notes.save_note are unknown. …

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
```

The last warning is about the *benign* server: WARDEN does not know what `save_note` may read or
send, and says so instead of calling it safe. `warden-mcp declare` binds operator-known capabilities
to a server identity when you do know.

The servers answer `initialize`, `tools/list` and `tools/call` over newline-delimited JSON-RPC
([`stdio-server.mjs`](stdio-server.mjs), 40 lines, no dependencies). Their handlers never write
anything: the attack in `evil-notes` is the *description*, the text a model would read and obey,
which is exactly the surface `scan` vets. Nothing here contacts the network; `scan` starts each
server, reads its tool list, and stops it.

What to try next: `--json` for the full findings, `--lock warden.lock.json --update-lock` to pin
the allowed set and be told when a server changes, and the [scan guide](../../docs/scan.md).
